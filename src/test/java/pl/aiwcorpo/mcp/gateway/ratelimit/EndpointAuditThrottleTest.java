package pl.aiwcorpo.mcp.gateway.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.junit.jupiter.api.Test;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import pl.aiwcorpo.mcp.gateway.audit.AuditLog;
import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.support.Contracts;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** The wrapper: a timer closes the window without further traffic, a shutdown flushes, the budget of one reason does not use up another. */
class EndpointAuditThrottleTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final GatewayUser USER = new GatewayUser("6f1c2a9e-4d4b-4c51-9a53-1e0f0c7d2b11", "alice", "claude-code", List.of(), "t");

    private final List<JsonNode> events = new CopyOnWriteArrayList<>();
    private final SimpleMeterRegistry meters = new SimpleMeterRegistry();

    private EndpointAuditThrottle throttle(Duration interval, int maxTargets) {
        AuditLog audit = new AuditLog();
        audit.listen(event -> events.add(JSON.valueToTree(event.view())));
        return new EndpointAuditThrottle(interval, maxTargets, System::currentTimeMillis, meters, audit, "mcp-gateway", () -> "20261026120000-a1b2c3d");
    }

    @Test
    void theSummaryAppearsAfterTheWindowWithoutAnyFurtherRequest() {
        try (EndpointAuditThrottle throttle = throttle(Duration.ofMillis(300), 50)) {
            assertThat(throttle.admit(USER, "not_granted", "jira__delete_issue")).isTrue();
            for (int i = 0; i < 6; i++) {
                assertThat(throttle.admit(USER, "not_granted", "jira__delete_issue")).isFalse();
            }
            assertThat(throttle.admit(USER, "not_granted", "gitlab__delete_project")).as("another target is not silenced").isTrue();
            await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> assertThat(events).hasSize(1));
            JsonNode summary = events.getFirst();
            assertThat(summary.path("suppressedCount").asInt()).isEqualTo(6);
            assertThat(summary.path("reason").asString()).isEqualTo("not_granted");
            assertThat(summary.path("event").asString()).isEqualTo("policy_decision");
            assertThat(summary.path("errorCode").asString()).isEqualTo("not_found_or_denied");
            assertThat(summary.path("sub").asString()).isEqualTo(USER.sub());
            assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", summary)).isEmpty();
            assertThat(meters.get("mcp_audit_endpoint_suppressed_total").tag("reason", "not_granted").counter().count()).isEqualTo(6.0);
            assertThat(meters.get("mcp_audit_endpoint_summary_targets").summary().totalAmount()).as("one suppressed target").isEqualTo(1.0);
        }
    }

    @Test
    void aShutdownWritesTheSummariesOfTheOpenWindows() {
        EndpointAuditThrottle throttle = throttle(Duration.ofMinutes(10), 50);
        throttle.admit(USER, "invalid_filter", "x");
        throttle.admit(USER, "invalid_filter", "x");
        throttle.admit(USER, "invalid_filter", "x");
        assertThat(events).isEmpty();
        throttle.close();
        assertThat(events).singleElement().satisfies(summary -> {
            assertThat(summary.path("suppressedCount").asInt()).isEqualTo(2);
            assertThat(summary.path("outcome").asString()).isEqualTo("error");
            assertThat(summary.has("errorCode")).isFalse();
            assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", summary)).isEmpty();
        });
    }

    @Test
    void theLimitOfTargetsIsPerUserAndReasonSoCheapFiltersDoNotUseUpTheBudgetOfRefusedTools() {
        try (EndpointAuditThrottle throttle = throttle(Duration.ofMinutes(10), 3)) {
            for (int i = 0; i < 20; i++) {
                throttle.admit(USER, "invalid_filter", "query-" + i);
            }
            assertThat(throttle.admit(USER, "not_granted", "jira__delete_issue")).as("a tool refusal still has its own keys").isTrue();
            assertThat(throttle.admit(USER, "not_granted", "gitlab__delete_project")).isTrue();
            assertThat(throttle.admit(USER, "not_granted", "confluence__delete_page")).isTrue();
        }
    }
}
