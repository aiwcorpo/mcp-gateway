package pl.aiwcorpo.mcp.gateway.link;

import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;

import pl.aiwcorpo.mcp.gateway.policy.PolicyService;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.server.ServerRegistry;
import tools.jackson.databind.json.JsonMapper;

/**
 * Pushes the policy data to every server whose connection is approved (C14, CC-249): when the revision changed since the last push that
 * reached the server, and in any case every {@code period} (a server keeps the data in memory and loses it with a restart). A push that
 * failed is tried again after {@code retryAfterFailure}. The tool-call path pushes at once when a server answers
 * {@code 409 policy_data_stale} ({@link #push}); nothing is ever fetched by a server.
 */
public final class PolicyDataPusher implements DisposableBean {

    private static final Logger log = LoggerFactory.getLogger(PolicyDataPusher.class);

    private record Last(long revision, long atNanos, boolean delivered) {
    }

    private final PolicyService policies;
    private final ServerRegistry servers;
    private final ServerLinks links;
    private final JsonMapper json;
    private final Duration period;
    private final Duration retryAfterFailure;
    private final LongSupplier nanos;
    private final Map<String, Last> last = new ConcurrentHashMap<>();
    private final Set<String> inFlight = ConcurrentHashMap.newKeySet();
    private final ExecutorService pushes = Executors.newVirtualThreadPerTaskExecutor();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread thread = new Thread(r, "policy-data-pusher");
        thread.setDaemon(true);
        return thread;
    });

    public PolicyDataPusher(PolicyService policies, ServerRegistry servers, ServerLinks links, JsonMapper json, Duration poll,
                            Duration period, Duration retryAfterFailure, LongSupplier nanos) {
        this.policies = policies;
        this.servers = servers;
        this.links = links;
        this.json = json;
        this.period = period;
        this.retryAfterFailure = retryAfterFailure;
        this.nanos = nanos;
        scheduler.scheduleWithFixedDelay(this::tick, poll.toMillis(), poll.toMillis(), TimeUnit.MILLISECONDS);
    }

    /** Pushes the current data to the server now; true when the server answered {@code 200}. Never throws. */
    public boolean push(McpServer server) {
        if (!server.connectionApproved()) {
            return false;
        }
        try {
            Optional<PolicyService.ServerData> data = policies.dataFor(server.serverId());
            if (data.isEmpty()) {
                last.put(server.serverId(), new Last(0, nanos.getAsLong(), false));
                return false;
            }
            ServerLinks.Push result = links.pushPolicyData(server.internalUrl(), server.serverId(), server.connection().tlsMode(),
                    server.connection().fingerprint(), data.get().revision(), PolicyDataDocument.of(json, data.get()));
            Last before = last.put(server.serverId(), new Last(data.get().revision(), nanos.getAsLong(), result.delivered()));
            boolean wasDown = before != null && !before.delivered();
            if (!result.delivered()) {
                // One line when a server stops taking the data, not one at every retry of a server that stays down.
                if (wasDown) {
                    log.debug("policy data of revision {} still does not reach {} ({})", data.get().revision(), server.serverId(), result.failure());
                } else {
                    log.warn("policy data of revision {} did not reach {} ({})", data.get().revision(), server.serverId(), result.failure());
                }
            } else if (wasDown) {
                log.info("policy data reaches {} again", server.serverId());
            }
            return result.delivered();
        } catch (RuntimeException e) {
            log.warn("policy data of {} not pushed: {}", server.serverId(), e.getClass().getName());
            last.put(server.serverId(), new Last(0, nanos.getAsLong(), false));
            return false;
        }
    }

    /** One look at every server; public for the tests, which do not wait for the timer. */
    public void tick() {
        try {
            long revision = policies.snapshot().revision();
            long now = nanos.getAsLong();
            Set<String> present = ConcurrentHashMap.newKeySet();
            for (McpServer server : servers.all()) {
                present.add(server.serverId());
                if (!server.connectionApproved() || !server.enabled() || !due(last.get(server.serverId()), revision, now)) {
                    continue;
                }
                if (inFlight.add(server.serverId())) {
                    pushes.execute(() -> {
                        try {
                            push(server);
                        } finally {
                            inFlight.remove(server.serverId());
                        }
                    });
                }
            }
            last.keySet().removeIf(serverId -> !present.contains(serverId));
        } catch (RuntimeException e) {
            log.warn("the push of policy data could not be planned: {}", e.getClass().getName());
        }
    }

    private boolean due(Last previous, long revision, long now) {
        if (previous == null) {
            return true;
        }
        Duration age = Duration.ofNanos(now - previous.atNanos());
        if (!previous.delivered()) {
            return age.compareTo(retryAfterFailure) >= 0;
        }
        return previous.revision() != revision || age.compareTo(period) >= 0;
    }

    @Override
    public void destroy() {
        scheduler.shutdownNow();
        pushes.shutdownNow();
    }
}
