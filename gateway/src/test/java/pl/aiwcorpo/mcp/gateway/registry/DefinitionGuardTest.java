package pl.aiwcorpo.mcp.gateway.registry;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Clock;
import java.time.Duration;
import java.util.Map;

import org.junit.jupiter.api.Test;

import pl.aiwcorpo.mcp.gateway.registry.DefinitionGuard.Verdict;

/** The readings of the servers' tool lists: valid for the TTL, never kept when the approvals changed while they were made. */
class DefinitionGuardTest {

    private final DefinitionGuard guard = new DefinitionGuard(Clock.systemUTC(), Duration.ofSeconds(30));

    @Test
    void aReadingMadeUnderTheCurrentApprovalsIsKept() {
        long generation = guard.generation("mcp-jira");

        assertThat(guard.record("mcp-jira", generation, Map.of(), "1.0.0", Map.of("get_issue", Verdict.INTACT))).isPresent();

        assertThat(guard.fresh("mcp-jira")).isPresent();
        assertThat(guard.lastKnownIntact("mcp-jira", "get_issue")).isTrue();
    }

    @Test
    void aReadingThatWasInFlightDuringAnApprovalIsDroppedAndTheOldOneForgotten() {
        long generation = guard.generation("mcp-jira");
        guard.record("mcp-jira", generation, Map.of(), null, Map.of("get_issue", Verdict.INTACT));

        long inFlight = guard.generation("mcp-jira");
        guard.forget("mcp-jira");

        assertThat(guard.record("mcp-jira", inFlight, Map.of(), null, Map.of("get_issue", Verdict.INTACT))).isEmpty();
        assertThat(guard.last("mcp-jira")).isEmpty();
        assertThat(guard.record("mcp-jira", guard.generation("mcp-jira"), Map.of(), null, Map.of())).isPresent();
    }

    @Test
    void theTtlIsAtMostSixtySeconds() {
        assertThatThrownBy(() -> new DefinitionGuard(Clock.systemUTC(), Duration.ofSeconds(61))).hasMessageContaining("60 s");
        assertThatThrownBy(() -> new DefinitionGuard(Clock.systemUTC(), Duration.ZERO)).isInstanceOf(IllegalStateException.class);
    }
}
