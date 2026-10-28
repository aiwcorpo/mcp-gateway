package pl.aiwcorpo.mcp.gateway.registry;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Remembers, per server, which tools kept their approved definition at the last check, for a short while: a call does not
 * repeat the check of the whole server every time. A new approval forgets the result.
 */
public final class DefinitionGuard {

    private record Checked(Instant at, Map<String, Boolean> intact) {
    }

    private final Map<String, Checked> checks = new ConcurrentHashMap<>();
    private final Clock clock;
    private final Duration ttl;

    public DefinitionGuard(Clock clock, Duration ttl) {
        this.clock = clock;
        this.ttl = ttl;
    }

    public void record(String serverId, Map<String, Boolean> intact) {
        checks.put(serverId, new Checked(clock.instant(), Map.copyOf(intact)));
    }

    /** The result of a check younger than the TTL; empty when there is none (the caller checks). */
    public Optional<Boolean> fresh(String serverId, String tool) {
        Checked checked = checks.get(serverId);
        if (checked == null || Duration.between(checked.at(), clock.instant()).compareTo(ttl) > 0) {
            return Optional.empty();
        }
        return Optional.of(checked.intact().getOrDefault(tool, false));
    }

    /** The last result whatever its age, for the catalog; false only when the last check found a change. */
    public boolean lastKnownIntact(String serverId, String tool) {
        Checked checked = checks.get(serverId);
        return checked == null || checked.intact().getOrDefault(tool, true);
    }

    public void forget(String serverId) {
        checks.remove(serverId);
    }
}
