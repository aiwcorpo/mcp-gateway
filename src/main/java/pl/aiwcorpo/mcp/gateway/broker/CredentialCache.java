package pl.aiwcorpo.mcp.gateway.broker;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.micrometer.core.instrument.FunctionCounter;
import io.micrometer.core.instrument.MeterRegistry;

/**
 * In-memory cache of resolved credentials, key (sub, system, scopes) (ws-05 item 8). An entry lives at most
 * {@code min(cacheTtlSeconds, maxTtl, expiresAt)} and is not served after that; a timer removes expired entries from the map
 * at most {@code sweepInterval} (10 s) later whether or not they are read again. That drops the reference only: the bytes of the
 * credential stay on the heap until the next garbage collection (and are not zeroed, a String cannot be), so a heap dump can still
 * hold a credential for a while after the map forgot it. The timer stops in {@link #close()} and survives a failed run. {@code credential.invalidated} drops an entry at once. Every invalidation bumps a
 * generation counter so a resolve that was in flight while it happened cannot put the old credential back.
 */
public final class CredentialCache implements AutoCloseable {

    public record Key(String sub, String system, List<String> scopes) {
    }

    private record Entry(Credential credential, Instant expiresAt) {
    }

    /** Upper bound of entries, a second line behind the timer: a burst of distinct keys within one TTL cannot grow the map. */
    static final int MAX_ENTRIES = 10_000;
    private static final Logger log = LoggerFactory.getLogger(CredentialCache.class);
    static final Duration DEFAULT_SWEEP_INTERVAL = Duration.ofSeconds(10);

    private final Map<Key, Entry> entries = new ConcurrentHashMap<>();
    private final AtomicLong generation = new AtomicLong();
    private final Duration maxTtl;
    private final Clock clock;
    private final AtomicLong refusedWhenFull = new AtomicLong();
    private final ScheduledExecutorService sweeper;

    public CredentialCache(Duration maxTtl, Clock clock) {
        this(maxTtl, clock, DEFAULT_SWEEP_INTERVAL);
    }

    public CredentialCache(Duration maxTtl, Clock clock, Duration sweepInterval) {
        if (maxTtl.compareTo(Duration.ofSeconds(60)) > 0) {
            throw new IllegalStateException("credential cache TTL must not exceed 60 s (C4)");
        }
        this.maxTtl = maxTtl;
        this.clock = clock;
        this.sweeper = Executors.newSingleThreadScheduledExecutor(task -> {
            Thread thread = new Thread(task, "credential-cache-sweeper");
            thread.setDaemon(true);
            return thread;
        });
        long period = Math.max(1, sweepInterval.toMillis());
        sweeper.scheduleWithFixedDelay(this::sweepAndSurvive, period, period, TimeUnit.MILLISECONDS);
    }

    /** A failed run must not end the timer (the executor stops scheduling after an exception), so it is logged without any value. */
    private void sweepAndSurvive() {
        try {
            sweep();
        } catch (RuntimeException e) {
            log.warn("credential cache sweep failed, the next run goes on: {}", e.getClass().getName());
        }
    }

    /** Removes every expired entry; run by the timer. */
    void sweep() {
        Instant now = Instant.now(clock);
        entries.values().removeIf(entry -> !now.isBefore(entry.expiresAt()));
    }

    @Override
    public void close() {
        sweeper.shutdownNow();
    }

    /** Registers the size and the refusals when full; no tag, so no user or key reaches the metrics. */
    public void bindTo(MeterRegistry meters) {
        meters.gauge("mcp.gateway.credential.cache.size", this, CredentialCache::size);
        FunctionCounter.builder("mcp.gateway.credential.cache.refused", this, CredentialCache::refusedWhenFull).register(meters);
    }

    /** Credentials not cached because the cache was full of live entries; no key and no user in it. */
    public long refusedWhenFull() {
        return refusedWhenFull.get();
    }

    public Credential get(Key key) {
        Entry entry = entries.get(key);
        if (entry == null) {
            return null;
        }
        if (!Instant.now(clock).isBefore(entry.expiresAt())) {
            entries.remove(key, entry);
            return null;
        }
        return entry.credential();
    }

    public long generation() {
        return generation.get();
    }

    /** Stores the credential unless an invalidation happened after {@code generationAtLookup}. */
    public void put(Key key, Credential credential, long generationAtLookup) {
        Instant now = Instant.now(clock);
        Duration ttl = Duration.ofSeconds(credential.cacheTtlSeconds());
        if (ttl.compareTo(maxTtl) > 0) {
            ttl = maxTtl;
        }
        Instant expiresAt = now.plus(ttl);
        if (credential.expiresAt() != null && credential.expiresAt().isBefore(expiresAt)) {
            expiresAt = credential.expiresAt();
        }
        if (!expiresAt.isAfter(now)) {
            return;
        }
        synchronized (generation) {
            if (generation.get() != generationAtLookup) {
                return;
            }
            if (entries.size() >= MAX_ENTRIES && !entries.containsKey(key)) {
                entries.values().removeIf(entry -> !now.isBefore(entry.expiresAt()));
                if (entries.size() >= MAX_ENTRIES) {
                    refusedWhenFull.incrementAndGet();
                    return;
                }
            }
            entries.put(key, new Entry(credential, expiresAt));
        }
    }

    public void invalidate(String sub, String system) {
        synchronized (generation) {
            generation.incrementAndGet();
            entries.keySet().removeIf(k -> k.sub().equals(sub) && k.system().equals(system));
        }
    }

    /** Drops every credential of the user (offboarding, this instance); other instances drop theirs on credential.invalidated or by TTL. */
    public void invalidateUser(String sub) {
        synchronized (generation) {
            generation.incrementAndGet();
            entries.keySet().removeIf(k -> k.sub().equals(sub));
        }
    }

    public void clear() {
        synchronized (generation) {
            generation.incrementAndGet();
            entries.clear();
        }
    }

    public int size() {
        return entries.size();
    }
}
