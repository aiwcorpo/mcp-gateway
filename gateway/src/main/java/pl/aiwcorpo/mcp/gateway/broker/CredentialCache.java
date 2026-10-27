package pl.aiwcorpo.mcp.gateway.broker;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * In-memory cache of resolved credentials, key (sub, system, scopes) (ws-05 item 8). An entry lives at most
 * {@code min(cacheTtlSeconds, maxTtl, expiresAt)}; {@code credential.invalidated} drops it at once. Every
 * invalidation bumps a generation counter so a resolve that was in flight while it happened cannot put the old
 * credential back.
 */
public final class CredentialCache {

    public record Key(String sub, String system, List<String> scopes) {
    }

    private record Entry(Credential credential, Instant expiresAt) {
    }

    private final Map<Key, Entry> entries = new ConcurrentHashMap<>();
    private final AtomicLong generation = new AtomicLong();
    private final Duration maxTtl;
    private final Clock clock;

    public CredentialCache(Duration maxTtl, Clock clock) {
        if (maxTtl.compareTo(Duration.ofSeconds(60)) > 0) {
            throw new IllegalStateException("credential cache TTL must not exceed 60 s (C4)");
        }
        this.maxTtl = maxTtl;
        this.clock = clock;
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
            if (generation.get() == generationAtLookup) {
                entries.put(key, new Entry(credential, expiresAt));
            }
        }
    }

    public void invalidate(String sub, String system) {
        synchronized (generation) {
            generation.incrementAndGet();
            entries.keySet().removeIf(k -> k.sub().equals(sub) && k.system().equals(system));
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
