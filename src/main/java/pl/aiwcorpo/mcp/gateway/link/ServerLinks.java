package pl.aiwcorpo.mcp.gateway.link;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pl.aiwcorpo.mcp.gateway.jwt.InternalTokenIssuer;
import pl.aiwcorpo.mcp.gateway.jwt.UuidV7;
import pl.aiwcorpo.mcp.gateway.net.AddressPolicy;
import pl.aiwcorpo.mcp.gateway.tls.ServerCertificate;
import pl.aiwcorpo.mcp.gateway.tls.ServerTls;
import pl.aiwcorpo.mcp.gateway.upstream.BoundedInputStream;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Everything the gateway does to reach a server outside its MCP endpoint (C14, CC-249): the address check, the TLS probe, the pull of
 * {@code /.well-known/mcp-manifest} and the push of {@code /.well-known/mcp-policy-data}. The well-known paths are at the origin of the
 * {@code internalUrl}, not under its path. The name is resolved and every address judged right before each connection, so a name that
 * now resolves to a refused address is not connected to. The HTTP client resolves the name again when it connects (a window that is
 * not closed): for {@code ca} and {@code pinned} the TLS handshake stops a rebinding name from being trusted, {@code plain} accepts the
 * window. Every request carries a new token of the right purpose and no client certificate.
 *
 * <p>Clients are cached only for the approved trust: one per {@code ca} and per {@code plain}, one per approved pinned fingerprint. A
 * pull before the approval of a connection trusts a fingerprint that the server chose, so it gets a client of its own that is closed
 * after the request; a server that presents a new certificate at every handshake must not leave a client and a selector thread behind
 * for each. The headers of a response are bound by the request timeout; the body gets the rest of the same budget, after which the
 * stream is closed under the reader, so a server that sends one byte at a time cannot hold a caller.
 */
public final class ServerLinks {

    private static final Logger log = LoggerFactory.getLogger(ServerLinks.class);
    private static final int MAX_MANIFEST_BYTES = 1024 * 1024;
    private static final int MAX_ACK_BYTES = 64 * 1024;
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(5);
    private static final Duration DEFAULT_REQUEST_TIMEOUT = Duration.ofSeconds(10);
    private static final ScheduledExecutorService DEADLINES = Executors.newSingleThreadScheduledExecutor(
            Thread.ofPlatform().daemon().name("server-link-deadline").factory());

    /** Why a pull or a push did not reach the server's answer. */
    public enum Failure { ADDRESS_REFUSED, TLS_HANDSHAKE_FAILED, UNREACHABLE, REJECTED, INVALID }

    /** The result of a pull: the manifest and the certificate the connection was made with, or a failure. */
    public record Pull(JsonNode manifest, Optional<ServerCertificate> certificate, Failure failure, String message) {
        public boolean succeeded() {
            return failure == null;
        }

        static Pull failed(Failure failure, String message) {
            return new Pull(null, Optional.empty(), failure, message);
        }
    }

    /** The result of a push; {@code ack} is the answer of the server when it gave one. */
    public record Push(boolean delivered, int status, JsonNode ack, Failure failure) {
    }

    private final AddressPolicy addresses;
    private final ServerTls tls;
    private final InternalTokenIssuer tokens;
    private final JsonMapper json;
    private final Duration requestTimeout;
    private final Map<String, HttpClient> clients = new ConcurrentHashMap<>();

    public ServerLinks(AddressPolicy addresses, ServerTls tls, InternalTokenIssuer tokens, JsonMapper json) {
        this(addresses, tls, tokens, json, DEFAULT_REQUEST_TIMEOUT);
    }

    /** @param requestTimeout the budget of one pull or push, the headers and the body together */
    public ServerLinks(AddressPolicy addresses, ServerTls tls, InternalTokenIssuer tokens, JsonMapper json, Duration requestTimeout) {
        this.requestTimeout = requestTimeout;
        this.addresses = addresses;
        this.tls = tls;
        this.tokens = tokens;
        this.json = json;
    }

    public AddressPolicy addresses() {
        return addresses;
    }

    public ServerTls tls() {
        return tls;
    }

    /** The host of an address as the address policy wants it: without the brackets of an IPv6 literal. */
    public static String hostOf(URI url) {
        String host = url.getHost();
        return host != null && host.startsWith("[") ? host.substring(1, host.length() - 1) : host;
    }

    public static int portOf(URI url) {
        return url.getPort() != -1 ? url.getPort() : "https".equals(url.getScheme()) ? 443 : 80;
    }

    /** Empty when the host of the address may be connected to now: it is resolved and every address judged, right before a connection. */
    public Optional<AddressPolicy.Refusal> checkAddress(URI url) {
        return addresses.check(hostOf(url));
    }

    /**
     * The HTTP client for the APPROVED trust of a server, shared by the servers that use it: one per {@code ca}, one per {@code plain}, one
     * per approved pinned fingerprint. Never call it with a fingerprint the server chose before the approval.
     */
    public HttpClient client(String tlsMode, String fingerprint) {
        return clients.computeIfAbsent(cacheKey(tlsMode, fingerprint), key -> tls.client(tlsMode, fingerprint, CONNECT_TIMEOUT));
    }

    private static String cacheKey(String tlsMode, String fingerprint) {
        return ServerTls.PINNED.equals(tlsMode) ? tlsMode + "|" + fingerprint : tlsMode;
    }

    /**
     * Forgets the client of a pinned fingerprint that no approval holds any more. The client is only dropped from the cache, not shut down:
     * another server may still hold it through its upstream client, and a client that nothing references is released with its selector thread.
     */
    public void evict(String tlsMode, String fingerprint) {
        if (ServerTls.PINNED.equals(tlsMode) && fingerprint != null) {
            clients.remove(cacheKey(tlsMode, fingerprint));
        }
    }

    int cachedClients() {
        return clients.size();
    }


    /** The address check that refused a connection. */
    public static final class AddressRefused extends IOException {
        private final transient AddressPolicy.Refusal refusal;

        AddressRefused(AddressPolicy.Refusal refusal) {
            super(refusal.message());
            this.refusal = refusal;
        }

        public AddressPolicy.Refusal refusal() {
            return refusal;
        }
    }

    /** A handshake that reads the certificate of an {@code https} address; the address is checked first ({@link AddressRefused}). */
    public ServerTls.Presented probe(URI url) throws IOException {
        Optional<AddressPolicy.Refusal> refusal = checkAddress(url);
        if (refusal.isPresent()) {
            throw new AddressRefused(refusal.get());
        }
        return tls.probe(hostOf(url), portOf(url), CONNECT_TIMEOUT);
    }

    private static URI wellKnown(URI internalUrl, String name) {
        return internalUrl.resolve("/.well-known/" + name);
    }

    /** {@code GET /.well-known/mcp-manifest} under the approved trust, without a token: the server serves its manifest openly (C14). */
    public Pull pullManifest(URI internalUrl, String tlsMode, String fingerprint) {
        return pull(internalUrl, client(tlsMode, fingerprint));
    }

    /**
     * The same pull before the connection is approved, under what a probe proposes. A pinned fingerprint here is whatever the server presented,
     * so the client is built for this one request and closed after it; {@code ca} and {@code plain} hold nothing the server chose and use the
     * shared client.
     */
    public Pull pullManifestBeforeApproval(URI internalUrl, String tlsMode, String fingerprint) {
        if (!ServerTls.PINNED.equals(tlsMode)) {
            return pull(internalUrl, client(tlsMode, fingerprint));
        }
        Optional<AddressPolicy.Refusal> refusal = checkAddress(internalUrl);
        if (refusal.isPresent()) {
            return Pull.failed(Failure.ADDRESS_REFUSED, refusal.get().message());
        }
        try (HttpClient once = tls.client(tlsMode, fingerprint, CONNECT_TIMEOUT)) {
            return pull(internalUrl, once);
        }
    }

    private Pull pull(URI internalUrl, HttpClient http) {
        Optional<AddressPolicy.Refusal> refusal = checkAddress(internalUrl);
        if (refusal.isPresent()) {
            return Pull.failed(Failure.ADDRESS_REFUSED, refusal.get().message());
        }
        String requestId = UuidV7.next();
        HttpRequest request = HttpRequest.newBuilder(wellKnown(internalUrl, "mcp-manifest")).timeout(requestTimeout)
                .header("X-Request-Id", requestId).header("Accept", "application/json").GET().build();
        try {
            long deadline = System.nanoTime() + requestTimeout.toNanos();
            HttpResponse<InputStream> response = http.send(request, HttpResponse.BodyHandlers.ofInputStream());
            byte[] body = readBody(response, MAX_MANIFEST_BYTES, deadline);
            if (response.statusCode() != 200) {
                return Pull.failed(Failure.REJECTED, "GET /.well-known/mcp-manifest answered " + response.statusCode());
            }
            return new Pull(json.readTree(body), ServerTls.leafOf(response.sslSession()), null, null);
        } catch (JacksonException | BoundedInputStream.LimitExceededException e) {
            return Pull.failed(Failure.INVALID, "the manifest is not a JSON document of a size the gateway takes");
        } catch (IOException e) {
            log.warn("manifest of {} not fetched: {}", hostOf(internalUrl), describe(e));
            return Pull.failed(tlsFailure(e) ? Failure.TLS_HANDSHAKE_FAILED : Failure.UNREACHABLE,
                    tlsFailure(e) ? "the TLS handshake with the server failed" : "the server could not be reached");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Pull.failed(Failure.UNREACHABLE, "interrupted");
        }
    }

    /**
     * Whether the answer to a push says that the server did not take the data because it holds a higher revision than the one pushed
     * (vectors policy-data-push/ack-*); {@code accepted: false} with the same or a lower revision is the periodic push of unchanged data.
     */
    public static boolean serverHoldsNewer(JsonNode ack, long pushedRevision) {
        return ack != null && !ack.path("accepted").asBoolean(true) && ack.path("revision").asLong(0) > pushedRevision;
    }

    /**
     * Reads the body of a response up to {@code maxBytes} and no later than {@code deadlineNanos} ({@link System#nanoTime}): at the deadline the
     * stream is closed under the reader, which ends the read with an {@link IOException}.
     */
    private static byte[] readBody(HttpResponse<InputStream> response, int maxBytes, long deadlineNanos) throws IOException {
        InputStream raw = response.body();
        AtomicBoolean expired = new AtomicBoolean();
        ScheduledFuture<?> guard = DEADLINES.schedule(() -> {
            expired.set(true);
            try {
                raw.close();
            } catch (IOException e) {
                // the reader sees the closed stream either way
            }
        }, Math.max(0, deadlineNanos - System.nanoTime()), TimeUnit.NANOSECONDS);
        try (InputStream in = new BoundedInputStream(raw, maxBytes)) {
            return in.readAllBytes();
        } catch (IOException e) {
            if (expired.get() && !(e instanceof BoundedInputStream.LimitExceededException)) {
                throw new IOException("the body did not arrive in time", e);
            }
            throw e;
        } finally {
            guard.cancel(false);
        }
    }

    /**
     * {@code POST /.well-known/mcp-policy-data} under the approved trust; {@code revision} is the revision of {@code body} and of the token.
     * An answer {@code accepted: false} with a revision above the one pushed means that the server holds data this gateway does not have: that
     * is not a delivery, it is logged, and the caller treats it like a push that failed.
     */
    public Push pushPolicyData(URI internalUrl, String serverId, String tlsMode, String fingerprint, long revision, JsonNode body) {
        if (checkAddress(internalUrl).isPresent()) {
            return new Push(false, 0, null, Failure.ADDRESS_REFUSED);
        }
        String requestId = UuidV7.next();
        HttpRequest request = HttpRequest.newBuilder(wellKnown(internalUrl, "mcp-policy-data")).timeout(requestTimeout)
                .header("Authorization", "Bearer " + tokens.forPolicyData(serverId, requestId, revision)).header("X-Request-Id", requestId)
                .header("Content-Type", "application/json").header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json.writeValueAsString(body))).build();
        try {
            long deadline = System.nanoTime() + requestTimeout.toNanos();
            HttpResponse<InputStream> response = client(tlsMode, fingerprint).send(request, HttpResponse.BodyHandlers.ofInputStream());
            byte[] answer = readBody(response, MAX_ACK_BYTES, deadline);
            if (response.statusCode() != 200) {
                log.warn("policy data of {} was refused with {}", serverId, response.statusCode());
                return new Push(false, response.statusCode(), null, Failure.REJECTED);
            }
            JsonNode ack = answer.length == 0 ? null : json.readTree(answer);
            if (serverHoldsNewer(ack, revision)) {
                log.warn("{} answered the policy data of revision {} with accepted false and revision {}: it holds data this gateway does not have",
                        serverId, revision, ack.path("revision").asLong());
                return new Push(false, 200, ack, Failure.REJECTED);
            }
            return new Push(true, 200, ack, null);
        } catch (JacksonException | BoundedInputStream.LimitExceededException e) {
            return new Push(false, 200, null, Failure.INVALID);
        } catch (IOException e) {
            log.warn("policy data of {} not pushed: {}", serverId, describe(e));
            return new Push(false, 0, null, tlsFailure(e) ? Failure.TLS_HANDSHAKE_FAILED : Failure.UNREACHABLE);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new Push(false, 0, null, Failure.UNREACHABLE);
        }
    }

    /** The class of a failure and what its root cause says, for the log: no address or secret is in either. */
    private static String describe(Throwable error) {
        Throwable root = error;
        while (root.getCause() != null && root.getCause() != root) {
            root = root.getCause();
        }
        return error.getClass().getSimpleName() + (root == error ? "" : " caused by " + root.getClass().getSimpleName() + ": " + root.getMessage());
    }

    /** Whether a failure of the connection is a failure of TLS (the certificate, the protocol) and not of the network. */
    public static boolean tlsFailure(Throwable error) {
        for (Throwable cause = error; cause != null; cause = cause.getCause() == cause ? null : cause.getCause()) {
            if (cause instanceof javax.net.ssl.SSLException) {
                return true;
            }
        }
        return false;
    }
}
