package pl.aiwcorpo.mcp.gateway.registry;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import tools.jackson.databind.JsonNode;

/**
 * The last read of the tool list of each server (CC-133): the definitions it presented, and for every approved tool whether
 * that definition is the approved one. A read counts for {@code ttl} (at most 60 s, the window in which a changed server may
 * still serve a call); the last read stays known whatever its age, because a server that cannot be reached is no proof of a
 * change or of a missing tool. A new approval forgets the verdicts, so the next request reads again.
 */
public final class DefinitionGuard {

    public enum Verdict {
        INTACT, CHANGED, NOT_SERVED;

        /** The reason of the audit event of a refused call. */
        public String reason() {
            return this == CHANGED ? "definition_changed" : "tool_not_served";
        }
    }

    /** {@code definitions}: what the server presented, by tool name; {@code serverVersion}: its own version from initialize or null. */
    public record Reading(Instant at, Map<String, JsonNode> definitions, String serverVersion, Map<String, Verdict> verdicts) {
    }

    private final Map<String, Reading> readings = new ConcurrentHashMap<>();
    private final Clock clock;
    private final Duration ttl;

    public DefinitionGuard(Clock clock, Duration ttl) {
        if (ttl.isNegative() || ttl.isZero() || ttl.compareTo(Duration.ofSeconds(60)) > 0) {
            throw new IllegalStateException("gateway.registry.definition-check-ttl must be between 1 ms and 60 s (CC-161)");
        }
        this.clock = clock;
        this.ttl = ttl;
    }

    public Reading record(String serverId, Map<String, JsonNode> definitions, String serverVersion, Map<String, Verdict> verdicts) {
        Reading reading = new Reading(clock.instant(), Map.copyOf(definitions), serverVersion, Map.copyOf(verdicts));
        readings.put(serverId, reading);
        return reading;
    }

    /** The reading of a server if it is younger than the TTL; empty when there is none (the caller reads). */
    public Optional<Reading> fresh(String serverId) {
        Reading reading = readings.get(serverId);
        if (reading == null || Duration.between(reading.at(), clock.instant()).compareTo(ttl) > 0) {
            return Optional.empty();
        }
        return Optional.of(reading);
    }

    /** The last reading whatever its age. */
    public Optional<Reading> last(String serverId) {
        return Optional.ofNullable(readings.get(serverId));
    }

    /** True unless the last reading found this tool changed or not served (a tool never read counts as usable: no proof). */
    public boolean lastKnownIntact(String serverId, String tool) {
        Reading reading = readings.get(serverId);
        return reading == null || reading.verdicts().getOrDefault(tool, Verdict.INTACT) == Verdict.INTACT;
    }

    public void forget(String serverId) {
        readings.remove(serverId);
    }
}
