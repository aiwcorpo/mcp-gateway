package pl.aiwcorpo.mcp.gateway.registry;

import java.io.IOException;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;

import pl.aiwcorpo.mcp.gateway.audit.AuditEvent;
import pl.aiwcorpo.mcp.gateway.audit.AuditLog;
import pl.aiwcorpo.mcp.gateway.jwt.UuidV7;
import pl.aiwcorpo.mcp.gateway.link.ServerLinks;
import pl.aiwcorpo.mcp.gateway.tls.ServerCertificate;
import pl.aiwcorpo.mcp.gateway.tls.ServerTls;
import tools.jackson.databind.JsonNode;

/**
 * What the gateway does to know how a server is (C5, CC-249): connect under the approved trust, pull the manifest, apply what it brings
 * and note the status. It runs when an administrator asks ({@code refreshServer}), after the approval of a connection and in a loop, at
 * most every {@code interval} per server (the runtime pinning loop that replaced the registration by a pipeline).
 *
 * <p>A changed definition or policy hash makes the entry pending, so the tools wait. A pinned server that presents another certificate is
 * {@code certificate_changed} and the new certificate is a pending connection; a {@code ca} server that renews its certificate stays
 * connected. A check that fails changes nothing the registry holds except the status and the error.
 */
public final class ServerChecks implements DisposableBean {

    private static final Logger log = LoggerFactory.getLogger(ServerChecks.class);

    /** A first contact with an address: what the probe saw and what the pull brought, or why it failed. */
    public sealed interface Contact {
        record Reached(ServerConfig.PendingConnection pending, JsonNode manifest) implements Contact {
        }

        /** {@code reason} is a reason of {@code server_rejected}: address_refused, tls_handshake_failed, manifest_unreachable, manifest_invalid. */
        record Failed(String reason, String message) implements Contact {
        }
    }

    /** What one look at a server found, before it is stored. */
    record Observation(String status, String lastError, JsonNode manifest, ServerConfig.PendingConnection pending, boolean clearPending,
                       ServerCertificate renewed) {
        static Observation failed(String status, String lastError) {
            return new Observation(status, lastError, null, null, false, null);
        }
    }

    private static final Duration RETRY_AFTER_FAILURE = Duration.ofSeconds(5);

    private final RegistryStore store;
    private final RegistryService registry;
    private final ServerLinks links;
    private final AuditLog audit;
    private final String componentId;
    private final Clock clock;
    private final Duration interval;
    private final Map<String, Instant> lastLooked = new ConcurrentHashMap<>();
    private final Set<String> inFlight = ConcurrentHashMap.newKeySet();
    private final ExecutorService checks = Executors.newVirtualThreadPerTaskExecutor();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread thread = new Thread(r, "server-checks");
        thread.setDaemon(true);
        return thread;
    });

    /**
     * @param interval at most this long between two looks at a server by the loop; the loop looks at the timer every {@code poll}
     */
    public ServerChecks(RegistryStore store, RegistryService registry, ServerLinks links, AuditLog audit, String componentId, Clock clock,
                        Duration interval, Duration poll) {
        this.store = store;
        this.registry = registry;
        this.links = links;
        this.audit = audit;
        this.componentId = componentId;
        this.clock = clock;
        this.interval = interval;
        scheduler.scheduleWithFixedDelay(this::tick, poll.toMillis(), poll.toMillis(), TimeUnit.MILLISECONDS);
    }

    /**
     * When the loop counts the last look at a server from. A server that could not be reached is looked at again after
     * {@link #RETRY_AFTER_FAILURE} instead of a whole interval: at startup the first look can come before the gateway serves its own key set,
     * and a minute without tools for that is longer than the cause lasts.
     */
    static Instant lookedAt(Instant now, Duration interval, String status) {
        if (!ServerConfig.UNREACHABLE.equals(status)) {
            return now;
        }
        return now.minus(interval).plus(interval.compareTo(RETRY_AFTER_FAILURE) < 0 ? interval : RETRY_AFTER_FAILURE);
    }

    /** Drops the cached client of a connection that no approval of this server holds any more. */
    public void forgetClient(ServerConfig.Connection connection) {
        links.evict(connection.tlsMode(), connection.fingerprint());
    }

    /** The loop's look at the timer; public for the tests, which do not wait for it. */
    public void tick() {
        try {
            Instant now = clock.instant();
            Set<String> present = ConcurrentHashMap.newKeySet();
            for (ServerConfig config : store.configs()) {
                present.add(config.serverId());
                Instant last = lastLooked.get(config.serverId());
                if (!config.enabled() || (last != null && Duration.between(last, now).compareTo(interval) < 0)) {
                    continue;
                }
                if (inFlight.add(config.serverId())) {
                    lastLooked.put(config.serverId(), now);
                    checks.execute(() -> {
                        try {
                            Optional<ServerConfig> after = check(UuidV7.next(), config.serverId());
                            after.ifPresent(seen -> lastLooked.put(config.serverId(), lookedAt(clock.instant(), interval, seen.status())));
                        } catch (RuntimeException e) {
                            log.warn("{}: the check failed: {}", config.serverId(), e.getClass().getName());
                        } finally {
                            inFlight.remove(config.serverId());
                        }
                    });
                }
            }
            lastLooked.keySet().removeIf(serverId -> !present.contains(serverId));
        } catch (RuntimeException e) {
            log.warn("the servers could not be listed for a check: {}", e.getClass().getName());
        }
    }

    /**
     * First contact with an address that is not a server of the registry yet: for {@code https} a handshake that reads the certificate, then
     * the pull of the manifest under what that certificate proposes ({@code ca} when it validates for the host, else pinned to what was read:
     * the administrator approves the fingerprint afterwards, and nothing of the answer is approved by the pull).
     */
    public Contact contact(URI url, Instant now) {
        if (!"https".equals(url.getScheme())) {
            ServerLinks.Pull pull = links.pullManifest(url, ServerTls.PLAIN, null);
            return pull.succeeded() ? new Contact.Reached(new ServerConfig.PendingConnection(ServerTls.PLAIN, null, null, null, java.util.List.of(), null,
                    false, "first_connection", now), pull.manifest()) : failed(pull, false);
        }
        ServerTls.Presented presented;
        try {
            presented = links.probe(url);
        } catch (ServerLinks.AddressRefused e) {
            return new Contact.Failed("address_refused", e.refusal().message());
        } catch (IOException e) {
            return new Contact.Failed("tls_handshake_failed", e instanceof javax.net.ssl.SSLException
                    ? "the TLS handshake with the server failed" : "no TLS handshake could be made with the address");
        }
        String mode = ConnectionRules.proposal(true, presented.validatesAsCa());
        ServerLinks.Pull pull = links.pullManifestBeforeApproval(url, mode, presented.leaf().fingerprint());
        if (!pull.succeeded()) {
            return failed(pull, true);
        }
        return new Contact.Reached(pendingOf(mode, presented, "first_connection", now), pull.manifest());
    }

    private static Contact failed(ServerLinks.Pull pull, boolean https) {
        return switch (pull.failure()) {
            case ADDRESS_REFUSED -> new Contact.Failed("address_refused", pull.message());
            case TLS_HANDSHAKE_FAILED -> new Contact.Failed("tls_handshake_failed", pull.message());
            case INVALID -> new Contact.Failed("manifest_invalid", pull.message());
            case UNREACHABLE -> new Contact.Failed(https ? "tls_handshake_failed" : "manifest_unreachable", pull.message());
            case REJECTED -> new Contact.Failed("manifest_unreachable", pull.message());
        };
    }

    private static ServerConfig.PendingConnection pendingOf(String mode, ServerTls.Presented presented, String reason, Instant now) {
        ServerCertificate leaf = presented.leaf();
        return new ServerConfig.PendingConnection(mode, leaf.fingerprint(), leaf.subject(), leaf.issuer(), leaf.sans(), leaf.notAfter(),
                presented.validatesAsCa(), reason, now);
    }

    /** Looks at a server now, applies what it brings and stores the status. Empty when the server is not in the registry. */
    public Optional<ServerConfig> check(String requestId, String serverId) {
        Optional<ServerConfig> found = store.config(serverId);
        if (found.isEmpty()) {
            return Optional.empty();
        }
        ServerConfig config = found.get();
        Instant now = clock.instant();
        lastLooked.put(serverId, now);
        Observation seen = observe(config, now);
        String status = seen.status();
        String error = seen.lastError();
        if (seen.manifest() != null) {
            RegistryService.Result result = registry.applyPulled(requestId, serverId, seen.manifest());
            if (result instanceof RegistryService.Result.UnknownServer) {
                return Optional.empty();
            }
            if (result instanceof RegistryService.Result.Rejected rejected) {
                status = ServerConfig.MANIFEST_INVALID;
                error = "manifest_invalid";
                log.warn("{}: the manifest it serves is not taken: {}", serverId, rejected.reason() == null ? "schema or rule" : rejected.reason());
            }
        }
        return applyObservation(requestId, serverId, config.connection(), seen, status, error, now);
    }

    /**
     * Stores what one look found, unless the connection of the server changed since the look was made: {@code observedWith} is the
     * connection the look was judged against, and an approval that landed meanwhile makes the observation stale.
     */
    Optional<ServerConfig> applyObservation(String requestId, String serverId, ServerConfig.Connection observedWith, Observation seen,
                                            String finalStatus, String finalError, Instant now) {
        boolean[] changed = {false};
        ServerConfig.PendingConnection[] recorded = {null};
        store.locked(serverId, tx -> {
            Optional<ServerConfig> current = tx.config();
            if (current.isEmpty()) {
                return null;
            }
            ServerConfig before = current.get();
            if (!sameTrust(observedWith, before.connection())) {
                // An approval landed while this look was on the network: what it saw was judged against a connection that is not the
                // one the server has now, so it must not renew, clear or record anything (it could pin another certificate).
                return null;
            }
            if (before.lastCheckedAt() != null && now.isBefore(before.lastCheckedAt())) {
                // A look that began before the one already stored (the loop's, overtaken by a refresh): what it saw is older than what
                // the server is known to serve now, so it must not put the earlier status back.
                return null;
            }
            ServerConfig.Connection connection = before.connection();
            if (seen.renewed() != null && connection != null) {
                ServerCertificate leaf = seen.renewed();
                connection = new ServerConfig.Connection(connection.tlsMode(), leaf.fingerprint(), leaf.subject(), leaf.issuer(), leaf.sans(),
                        leaf.notAfter(), connection.approvedBy(), connection.approvedAt());
            }
            ServerConfig.PendingConnection pending = before.pendingConnection();
            if (seen.pending() != null && !(before.connection() != null && "first_connection".equals(seen.pending().reason()))) {
                pending = samePending(pending, seen.pending()) ? pending : seen.pending();
            } else if (seen.clearPending()) {
                pending = null;
            }
            String statusNow = before.connectionApproved() || !ServerConfig.CONNECTED.equals(finalStatus) ? finalStatus
                    : ServerConfig.PENDING_APPROVAL;
            ServerConfig after = new ServerConfig(before.serverId(), before.system(), before.internalUrl(), before.credential(), before.enabled(),
                    before.adapter(), before.allowPlainHttp(), statusNow, now, finalError, connection, pending);
            if (!sameObservation(before, after)) {
                tx.saveState(after);
                changed[0] = true;
                if (pending != null && !samePending(before.pendingConnection(), pending) && !"first_connection".equals(pending.reason())) {
                    recorded[0] = pending;
                }
            } else {
                tx.touchChecked(now);
            }
            return null;
        });
        if (recorded[0] != null) {
            audit.emit(AuditEvent.of("admin_change", requestId, componentId).server(serverId).reason("server_connection_changed")
                    .tlsMode(recorded[0].tlsMode()).fingerprint(recorded[0].fingerprint()).outcome("ok"));
        }
        if (changed[0]) {
            try {
                registry.reloadChanged();
            } catch (RuntimeException e) {
                log.warn("{}: the new state was stored but could not be read back: {}", serverId, e.getClass().getName());
            }
        }
        return store.config(serverId);
    }

    private static boolean sameTrust(ServerConfig.Connection observed, ServerConfig.Connection current) {
        if (observed == null || current == null) {
            return observed == current;
        }
        return observed.tlsMode().equals(current.tlsMode()) && Objects.equals(observed.fingerprint(), current.fingerprint());
    }

    private static boolean sameObservation(ServerConfig before, ServerConfig after) {
        return before.status().equals(after.status()) && Objects.equals(before.lastError(), after.lastError())
                && Objects.equals(before.connection(), after.connection()) && Objects.equals(before.pendingConnection(), after.pendingConnection());
    }

    private static boolean samePending(ServerConfig.PendingConnection a, ServerConfig.PendingConnection b) {
        return a != null && b != null && a.tlsMode().equals(b.tlsMode()) && Objects.equals(a.fingerprint(), b.fingerprint())
                && a.reason().equals(b.reason()) && a.validatesAsCa() == b.validatesAsCa();
    }

    /** One look at a server, over the network and nothing else. */
    Observation observe(ServerConfig config, Instant now) {
        URI url = config.internalUrl();
        ServerConfig.Connection approved = config.connection();
        boolean https = "https".equals(url.getScheme());
        String serverId = config.serverId();
        if (!https) {
            if (!config.allowPlainHttp()) {
                return Observation.failed(ServerConfig.UNREACHABLE, "plain_http_not_allowed");
            }
            return afterPull(links.pullManifest(url, ServerTls.PLAIN, null), config, null, false, null);
        }
        if (approved == null) {
            ServerTls.Presented presented;
            try {
                presented = links.probe(url);
            } catch (ServerLinks.AddressRefused e) {
                return Observation.failed(ServerConfig.UNREACHABLE, "address_refused");
            } catch (IOException e) {
                return Observation.failed(ServerConfig.UNREACHABLE, "tls_handshake_failed");
            }
            String mode = ConnectionRules.proposal(true, presented.validatesAsCa());
            ServerLinks.Pull pull = links.pullManifestBeforeApproval(url, mode, presented.leaf().fingerprint());
            return afterPull(pull, config, pendingOf(mode, presented, "first_connection", now), false, null);
        }
        ServerLinks.Pull pull = links.pullManifest(url, approved.tlsMode(), approved.fingerprint());
        if (pull.succeeded()) {
            ServerCertificate leaf = pull.certificate().orElse(null);
            boolean renewed = ServerTls.CA.equals(approved.tlsMode()) && leaf != null && !leaf.fingerprint().equals(approved.fingerprint());
            return afterPull(pull, config, null, config.pendingConnection() != null, renewed ? leaf : null);
        }
        if (pull.failure() != ServerLinks.Failure.TLS_HANDSHAKE_FAILED) {
            return afterPull(pull, config, null, false, null);
        }
        ServerTls.Presented presented;
        try {
            presented = links.probe(url);
        } catch (ServerLinks.AddressRefused e) {
            return Observation.failed(ServerConfig.UNREACHABLE, "address_refused");
        } catch (IOException e) {
            return Observation.failed(ServerConfig.UNREACHABLE, "tls_handshake_failed");
        }
        ConnectionRules.Check verdict = ConnectionRules.check(approved.tlsMode(), approved.fingerprint(),
                new ConnectionRules.Seen(presented.leaf().fingerprint(), presented.validatesAsCa()));
        if (verdict.pendingMode() == null) {
            return Observation.failed(ServerConfig.UNREACHABLE, "tls_handshake_failed");
        }
        return new Observation(ServerConfig.CERTIFICATE_CHANGED, "certificate_changed", null,
                pendingOf(verdict.pendingMode(), presented, verdict.pendingReason(), now), false, null);
    }

    private static Observation afterPull(ServerLinks.Pull pull, ServerConfig config, ServerConfig.PendingConnection pending,
                                         boolean clearPending, ServerCertificate renewed) {
        if (pull.succeeded()) {
            return new Observation(ServerConfig.CONNECTED, null, pull.manifest(), pending, clearPending, renewed);
        }
        boolean https = "https".equals(config.internalUrl().getScheme());
        return switch (pull.failure()) {
            case ADDRESS_REFUSED -> Observation.failed(ServerConfig.UNREACHABLE, "address_refused");
            case TLS_HANDSHAKE_FAILED -> Observation.failed(ServerConfig.UNREACHABLE, "tls_handshake_failed");
            case UNREACHABLE -> Observation.failed(ServerConfig.UNREACHABLE, https ? "tls_handshake_failed" : "manifest_unreachable");
            case REJECTED -> Observation.failed(ServerConfig.UNREACHABLE, "manifest_unreachable");
            case INVALID -> Observation.failed(ServerConfig.MANIFEST_INVALID, "manifest_invalid");
        };
    }

    @Override
    public void destroy() {
        scheduler.shutdownNow();
        checks.shutdownNow();
    }
}
