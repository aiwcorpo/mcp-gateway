package pl.aiwcorpo.mcp.gateway.policy;

import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.util.EnumMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;

import io.micrometer.core.instrument.MeterRegistry;
import pl.aiwcorpo.mcp.gateway.config.GatewayProperties;
import pl.aiwcorpo.mcp.policy.bundle.BundleRejectedException;
import pl.aiwcorpo.mcp.policy.bundle.BundleVerifier;
import pl.aiwcorpo.mcp.policy.bundle.Channel;
import pl.aiwcorpo.mcp.policy.bundle.PolicyStore;

/**
 * The policies of the gateway (C7): two signed bundles, main and overrides, pulled on an interval, verified by
 * {@link PolicyStore} and swapped atomically; a bundle that fails any check leaves the previous one in force. There is no
 * start without a main bundle (CC-068), a revision below the loaded or the persisted one is refused (CC-066), and after a
 * restart with overrides active the gateway waits for them (their forbid rules must not vanish silently).
 */
public final class PolicyService implements DisposableBean {

    private static final Logger log = LoggerFactory.getLogger(PolicyService.class);

    private final GatewayProperties.Policy config;
    private final PolicyStore store;
    private final BundleFetcher fetcher;
    private final MeterRegistry meters;
    private final Map<Channel, String> etags = new EnumMap<>(Channel.class);
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2, r -> {
        Thread thread = new Thread(r, "policy-sync");
        thread.setDaemon(true);
        return thread;
    });
    private volatile boolean overridesGraceExpired;

    /**
     * @param developmentStack true under the devstack profile: only there a missing state directory is accepted (a restart
     *                         then takes an older signed bundle, CC-066)
     */
    public PolicyService(GatewayProperties.Policy configured, BundleFetcher fetcher, MeterRegistry meters, boolean developmentStack) {
        GatewayProperties.Policy config = normalized(configured);
        this.config = config;
        this.fetcher = fetcher;
        this.meters = meters;
        BundleVerifier main = verifier(Channel.MAIN, config.mainKeyId(), config.mainKeyFile(), config);
        BundleVerifier overrides = verifier(Channel.OVERRIDES, config.overridesKeyId() == null ? "none" : config.overridesKeyId(),
                config.overridesKeyFile() == null ? config.mainKeyFile() : config.overridesKeyFile(), config);
        PolicyStore.Persistence persistence = persistence(config);
        if (persistence == null) {
            if (!developmentStack) {
                throw new IllegalStateException("gateway.policy.state-dir is required outside the devstack profile: without it a "
                        + "restart accepts an older signed bundle (CC-066)");
            }
            log.warn("gateway.policy.state-dir is not set: the protection against an older bundle holds only while the process runs");
        }
        this.store = persistence == null ? new PolicyStore(main, overrides) : new PolicyStore(main, overrides, persistence);
    }

    /** A directory URL ends with a slash (files are resolved against it); an empty overrides URL means there are none. */
    private static GatewayProperties.Policy normalized(GatewayProperties.Policy p) {
        URI overrides = p.overridesUrl() == null || p.overridesUrl().toString().isBlank() ? null : directory(p.overridesUrl());
        return new GatewayProperties.Policy(directory(p.mainUrl()), overrides, p.mainKeyId(), p.mainKeyFile(), blankToNull(p.overridesKeyId()),
                blankToNull(p.overridesKeyFile()), p.allowTestKeys(), blankToNull(p.stateDir()), blankToNull(p.minimumMainRevision()),
                blankToNull(p.minimumOverridesRevision()), p.mainInterval(), p.overridesInterval(), p.startupTimeout(), p.overridesGrace());
    }

    private static URI directory(URI uri) {
        return uri.toString().endsWith("/") ? uri : URI.create(uri + "/");
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }

    private static BundleVerifier verifier(Channel channel, String keyId, String keyFile, GatewayProperties.Policy config) {
        try {
            String pem = java.nio.file.Files.readString(java.nio.file.Path.of(keyFile));
            return BundleVerifier.of(channel, BundleVerifier.ed25519PublicKeyFromPem(pem), keyId, config.allowTestKeys());
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalStateException("gateway.policy: the " + channel + " public key at " + keyFile + " cannot be read", e);
        }
    }

    private static PolicyStore.Persistence persistence(GatewayProperties.Policy config) {
        if (config.stateDir() == null || config.stateDir().isBlank()) {
            return null;
        }
        Map<Channel, String> minimum = new EnumMap<>(Channel.class);
        if (config.minimumMainRevision() != null && !config.minimumMainRevision().isBlank()) {
            minimum.put(Channel.MAIN, config.minimumMainRevision());
        }
        if (config.minimumOverridesRevision() != null && !config.minimumOverridesRevision().isBlank()) {
            minimum.put(Channel.OVERRIDES, config.minimumOverridesRevision());
        }
        return new PolicyStore.Persistence(java.nio.file.Path.of(config.stateDir()), minimum,
                warning -> LoggerFactory.getLogger("AUDIT-POLICY").warn("policy state: {}", warning));
    }

    /** Waits for the main bundle (and the overrides, when they are awaited) and then keeps both current. */
    public PolicyService start() {
        long deadline = System.nanoTime() + config.startupTimeout().toNanos();
        while (store.current().isEmpty()) {
            sync(Channel.MAIN);
            if (store.current().isPresent()) {
                break;
            }
            if (System.nanoTime() > deadline) {
                throw new IllegalStateException("no signed policy bundle could be loaded from " + config.mainUrl()
                        + " within " + config.startupTimeout() + ": the gateway does not start without policies (CC-068)");
            }
            sleep(Duration.ofSeconds(1));
        }
        if (config.overridesUrl() != null) {
            long graceEnd = System.nanoTime() + config.overridesGrace().toNanos();
            sync(Channel.OVERRIDES);
            while (store.awaitingOverrides() && System.nanoTime() < graceEnd) {
                sleep(Duration.ofMillis(500));
                sync(Channel.OVERRIDES);
            }
            if (store.awaitingOverrides()) {
                overridesGraceExpired = true;
                log.error("ALARM: the overrides bundle that was active before the restart could not be loaded; serving without its forbid rules");
            }
            scheduler.scheduleWithFixedDelay(() -> sync(Channel.OVERRIDES), config.overridesInterval().toMillis(),
                    config.overridesInterval().toMillis(), TimeUnit.MILLISECONDS);
        }
        scheduler.scheduleWithFixedDelay(() -> sync(Channel.MAIN), config.mainInterval().toMillis(), config.mainInterval().toMillis(),
                TimeUnit.MILLISECONDS);
        return this;
    }

    /** One pull of a channel. Never throws: a failure keeps the policies in force and is counted. */
    public synchronized void sync(Channel channel) {
        URI directory = channel == Channel.MAIN ? config.mainUrl() : config.overridesUrl();
        if (directory == null) {
            return;
        }
        try {
            Optional<BundleFetcher.Fetched> fetched = fetcher.fetch(directory, etags.get(channel));
            if (fetched.isEmpty()) {
                return;
            }
            BundleFetcher.Fetched bundle = fetched.get();
            if (channel == Channel.MAIN) {
                store.loadMain(bundle.pointer(), bundle.archive(), bundle.signature());
            } else {
                store.loadOverrides(bundle.pointer(), bundle.archive(), bundle.signature());
            }
            // The ETag is kept only for a bundle that was accepted, so a rejected one is looked at again (and rejected again).
            if (bundle.etag() != null) {
                etags.put(channel, bundle.etag());
            }
            log.info("policy bundle {} loaded: revision {}", channel.name().toLowerCase(), bundle.pointer().revision());
        } catch (BundleRejectedException e) {
            etags.remove(channel);
            meters.counter("gateway_policy_bundle_rejected_total", "channel", channel.name().toLowerCase(), "reason", e.reason().wireCode())
                    .increment();
            log.error("policy bundle {} rejected ({}); the previous one stays", channel.name().toLowerCase(), e.reason().wireCode());
        } catch (IOException e) {
            meters.counter("gateway_policy_bundle_fetch_failures_total", "channel", channel.name().toLowerCase()).increment();
            log.warn("policy bundle {} not fetched: {}", channel.name().toLowerCase(), e.getClass().getSimpleName());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (RuntimeException e) {
            log.error("policy bundle {} failed: {}", channel.name().toLowerCase(), e.getClass().getName());
        }
    }

    /** The active policies; empty only before the first load, and then nothing is allowed. */
    public Optional<PolicyStore.Snapshot> snapshot() {
        return store.current();
    }

    /** False while the overrides that were active before a restart are awaited (until the grace period ends). */
    public boolean ready() {
        return store.current().isPresent() && (store.isReady() || overridesGraceExpired);
    }

    /** Revision of the main bundle in force; null before the first load. */
    public String revision() {
        return store.current().map(s -> s.main().revision()).orElse(null);
    }

    private static void sleep(Duration duration) {
        try {
            Thread.sleep(duration.toMillis());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted while waiting for the policy bundle", e);
        }
    }

    @Override
    public void destroy() {
        scheduler.shutdownNow();
    }
}
