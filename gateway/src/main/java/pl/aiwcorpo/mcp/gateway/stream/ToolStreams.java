package pl.aiwcorpo.mcp.gateway.stream;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.LongSupplier;
import java.util.function.Predicate;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextClosedEvent;

import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.manifest.EndpointFilter;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * The open SSE streams of this instance (CC-192, CC-207): the {@code GET} of a legacy session and the {@code POST subscriptions/listen}
 * of the stateless protocol. Each stream is served by the thread of its own request (a virtual one), which is the only writer of its
 * response: it waits for a change, a heartbeat or the end of the token, so a slow client holds nobody else. A change (the registry, an
 * emergency switch, the policies, the definitions a server presents) wakes every stream; each computes the list of its user again and
 * tells its client when it differs from the one before. No stream counts for the limit of requests in flight; the number of open ones
 * is a metric. A stream ends when its token expires, when its session is deleted, when its user is purged and when the process stops;
 * nothing is replayed (Last-Event-ID is ignored), because a client lists the tools again after it reconnects and every call is checked anyway.
 */
public final class ToolStreams implements ApplicationListener<ContextClosedEvent> {

    private static final Logger log = LoggerFactory.getLogger(ToolStreams.class);
    private static final String META_SUBSCRIPTION = "io.modelcontextprotocol/subscriptionId";
    private static final byte[] KEEPALIVE = ": keepalive\n\n".getBytes(StandardCharsets.UTF_8);
    private static final byte[] OPEN = ": open\n\n".getBytes(StandardCharsets.UTF_8);

    public enum Kind { SESSION, LISTEN }

    private final UserToolLists lists;
    private final Duration heartbeat;
    private final long windowMillis;
    private final LongSupplier millis;
    private final MeterRegistry meters;
    private final Predicate<String> sessionExists;
    private final JsonMapper json;
    private final Set<Stream> open = ConcurrentHashMap.newKeySet();
    private final AtomicInteger openCount = new AtomicInteger();

    /**
     * @param sessionExists whether a legacy session is still there; a stream of a session that was deleted ends. It may throw when the
     *                      store does not answer, which ends the stream too (fail-closed)
     */
    public ToolStreams(UserToolLists lists, Duration heartbeat, Duration window, LongSupplier millis, MeterRegistry meters,
                       Predicate<String> sessionExists, JsonMapper json) {
        this.lists = lists;
        this.heartbeat = heartbeat;
        this.windowMillis = window.toMillis();
        this.millis = millis;
        this.meters = meters;
        this.sessionExists = sessionExists;
        this.json = json;
        Gauge.builder("mcp_gateway_open_streams", openCount, AtomicInteger::get)
                .description("SSE streams open on this instance: the GET of sessions and subscriptions/listen together").register(meters);
    }

    /**
     * Opens a stream for a user. The list of the user at this moment is the reference of the first comparison (CC-207); {@code subscriptionId}
     * is the id of the {@code subscriptions/listen} request, null for the stream of a session.
     */
    public Stream open(Kind kind, GatewayUser user, String sessionId, EndpointFilter filter, java.time.Instant tokenExpiresAt,
                       JsonNode subscriptionId, boolean toolsListChanged) {
        ListChangeTracker tracker = new ListChangeTracker(filter, lists.of(user), windowMillis);
        Stream stream = new Stream(kind, user, sessionId, tracker, tokenExpiresAt == null ? Long.MAX_VALUE
                : millis.getAsLong() + Math.max(0, Duration.between(java.time.Instant.now(), tokenExpiresAt).toMillis()), subscriptionId,
                toolsListChanged);
        open.add(stream);
        openCount.incrementAndGet();
        meters.counter("mcp_gateway_streams_opened_total", "kind", kind.name().toLowerCase()).increment();
        return stream;
    }

    /** Something that may change a list happened: every stream computes its list again. */
    public void changed() {
        open.forEach(Stream::wake);
    }

    /** The user of a session presented a token with other groups than the stream holds: the stream goes on with them (CC-176). */
    public void refreshUser(String sessionId, GatewayUser user) {
        for (Stream stream : open) {
            if (sessionId.equals(stream.sessionId) && !stream.user.groups().equals(user.groups())) {
                stream.user = user;
                stream.wake();
            }
        }
    }

    public void closeSession(String sessionId) {
        open.forEach(stream -> {
            if (sessionId.equals(stream.sessionId)) {
                stream.close("session_deleted");
            }
        });
    }

    public void closeUser(String sub) {
        open.forEach(stream -> {
            if (sub.equals(stream.user.sub())) {
                stream.close("user_purged");
            }
        });
    }

    public int openCount() {
        return openCount.get();
    }

    @Override
    public void onApplicationEvent(ContextClosedEvent event) {
        open.forEach(stream -> stream.close("shutdown"));
    }

    /** One open stream. */
    public final class Stream {
        private final Kind kind;
        private volatile GatewayUser user;
        private final String sessionId;
        private final ListChangeTracker tracker;
        private final long expiresAtMillis;
        private final JsonNode subscriptionId;
        private final boolean toolsListChanged;
        private final Semaphore wake = new Semaphore(0);
        private volatile boolean check;
        private volatile String closeReason;

        private Stream(Kind kind, GatewayUser user, String sessionId, ListChangeTracker tracker, long expiresAtMillis, JsonNode subscriptionId,
                       boolean toolsListChanged) {
            this.kind = kind;
            this.user = user;
            this.sessionId = sessionId;
            this.tracker = tracker;
            this.expiresAtMillis = expiresAtMillis;
            this.subscriptionId = subscriptionId;
            this.toolsListChanged = toolsListChanged;
        }

        void wake() {
            check = true;
            wake.release();
        }

        void close(String reason) {
            if (closeReason == null) {
                closeReason = reason;
            }
            wake.release();
        }

        /**
         * Serves the stream until it ends and returns the reason. {@code out} is the response; only this thread writes to it. An exception
         * of the output (the client went away) ends the stream with the reason {@code client_closed}.
         */
        public String serve(OutputStream out) {
            String reason;
            try {
                if (kind == Kind.LISTEN) {
                    send(out, envelope("notifications/subscriptions/acknowledged", acknowledgement()));
                } else {
                    out.write(OPEN);
                    out.flush();
                }
                reason = loop(out);
                if (kind == Kind.LISTEN && !"client_closed".equals(reason)) {
                    send(out, completion());
                }
            } catch (IOException e) {
                reason = "client_closed";
            } finally {
                open.remove(this);
                openCount.decrementAndGet();
            }
            meters.counter("mcp_gateway_streams_closed_total", "reason", reason).increment();
            return reason;
        }

        private String loop(OutputStream out) throws IOException {
            long nextBeat = millis.getAsLong() + heartbeat.toMillis();
            while (true) {
                long now = millis.getAsLong();
                if (closeReason != null) {
                    return closeReason;
                }
                if (now >= expiresAtMillis) {
                    return "token_expired";
                }
                long wakeAt = Math.min(nextBeat, Math.min(expiresAtMillis, tracker.nextDueAt()));
                try {
                    wake.tryAcquire(Math.max(1, wakeAt - now), TimeUnit.MILLISECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return "interrupted";
                }
                wake.drainPermits();
                now = millis.getAsLong();
                if (closeReason != null) {
                    return closeReason;
                }
                List<Long> sends = List.of();
                if (check) {
                    check = false;
                    try {
                        sends = tracker.observe(now, lists.of(user));
                    } catch (RuntimeException e) {
                        log.warn("the list of a stream could not be computed: {}", e.getClass().getName());
                    }
                }
                if (sends.isEmpty()) {
                    sends = tracker.advance(now);
                }
                for (int i = 0; i < sends.size(); i++) {
                    if (toolsListChanged) {
                        send(out, envelope("notifications/tools/list_changed", null));
                        meters.counter("mcp_gateway_stream_notifications_total").increment();
                    }
                }
                if (now >= nextBeat) {
                    out.write(KEEPALIVE);
                    out.flush();
                    nextBeat = now + heartbeat.toMillis();
                    if (kind == Kind.SESSION && !alive()) {
                        return "session_deleted";
                    }
                }
            }
        }

        private boolean alive() {
            try {
                return sessionExists.test(sessionId);
            } catch (RuntimeException e) {
                log.warn("a stream ends: the store of the sessions did not answer ({})", e.getClass().getName());
                return false;
            }
        }

        private ObjectNode acknowledgement() {
            ObjectNode notifications = json.createObjectNode();
            if (toolsListChanged) {
                notifications.put("toolsListChanged", true);
            }
            return notifications;
        }

        private ObjectNode envelope(String method, ObjectNode notifications) {
            ObjectNode message = json.createObjectNode();
            message.put("jsonrpc", "2.0");
            message.put("method", method);
            if (kind == Kind.LISTEN) {
                ObjectNode params = message.putObject("params");
                params.putObject("_meta").set(META_SUBSCRIPTION, subscriptionId);
                if (notifications != null) {
                    params.set("notifications", notifications);
                }
            }
            return message;
        }

        /** The response to the subscriptions/listen request, which says that the subscription ended on the initiative of the server. */
        private ObjectNode completion() {
            ObjectNode message = json.createObjectNode();
            message.put("jsonrpc", "2.0");
            message.set("id", subscriptionId);
            ObjectNode result = message.putObject("result");
            result.put("resultType", "complete");
            result.putObject("_meta").set(META_SUBSCRIPTION, subscriptionId);
            return message;
        }

        private void send(OutputStream out, ObjectNode message) throws IOException {
            out.write(("event: message\ndata: " + json.writeValueAsString(message) + "\n\n").getBytes(StandardCharsets.UTF_8));
            out.flush();
        }
    }
}
