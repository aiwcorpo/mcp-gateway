package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.system.CapturedOutput;

import pl.aiwcorpo.mcp.gateway.support.Contracts;
import pl.aiwcorpo.mcp.gateway.support.RateLimitTestConfiguration;
import tools.jackson.databind.JsonNode;

/** Limits per user, per (user, client) and per (user, tool) in Redis (CC-135, CC-156), as the client, the audit and the activity see them. */
class RateLimitTest extends GatewayTestBase {

    private static final List<String> GROUPS = List.of("mcp-jira-read", "mcp-jira-write", "mcp-jira-destructive");
    private static final String SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    private static final int BIG = 1_000_000;

    @AfterEach
    void restore() {
        RateLimitTestConfiguration.restore();
    }

    private static void limits(int perUser, int perClient, int perTool, int destructive, Map<String, Integer> tools) {
        RateLimitTestConfiguration.use(RateLimitTestConfiguration.settings(perUser, perClient, perTool, destructive, tools));
    }

    private static String sub() {
        return UUID.randomUUID().toString();
    }

    private String token(String sub, String client) {
        return env.idp.token(sub, "limited", GROUPS, "mcp-gateway", client);
    }

    private HttpResponse<String> ping(String token) throws Exception {
        return sendModern(token, "ping", null, "{}");
    }

    private JsonNode getIssue(String token) throws Exception {
        HttpResponse<String> response = callGetIssue(token);
        assertThat(response.statusCode()).isEqualTo(200);
        return toolError(response);
    }

    private static List<JsonNode> events(CapturedOutput output, String sub, String reason) {
        return output.getOut().lines().filter(l -> l.startsWith("{") && l.contains(sub) && l.contains("\"reason\":\"" + reason + "\""))
                .map(l -> JSON.readTree(l)).toList();
    }

    @Test
    void aToolCallOverTheLimitOfTheToolIsAC10ErrorThatNeverReachesTheBrokerOrTheServer(CapturedOutput output) throws Exception {
        limits(BIG, BIG, 2, 1, Map.of());
        String sub = sub();
        String token = token(sub, "claude-code");
        assertThat(getIssue(token).path("error").asString("")).isNotEqualTo("rate_limited");
        assertThat(getIssue(token).path("error").asString("")).isNotEqualTo("rate_limited");
        long resolves = resolveCount();
        env.jira.clearRequests();

        JsonNode limited = getIssue(token);

        assertThat(limited.path("error").asString()).isEqualTo("rate_limited");
        assertThat(limited.path("retryAfterSeconds").asInt()).isBetween(1, 30);
        assertThat(Contracts.schemaErrors("schemas/tool-error.schema.json", limited)).isEmpty();
        assertThat(resolveCount()).isEqualTo(resolves);
        assertThat(env.jira.requests()).noneMatch(r -> "tools/call".equals(r.rpcMethod()));
        JsonNode event = events(output, sub, "rate_limited_tool").getFirst();
        assertThat(event.path("event").asString()).isEqualTo("tool_call");
        assertThat(event.path("decision").asString()).isEqualTo("deny");
        assertThat(event.path("outcome").asString()).isEqualTo("denied");
        assertThat(event.path("errorCode").asString()).isEqualTo("rate_limited");
        assertThat(event.path("tool").asString()).isEqualTo("get_issue");
        assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", event)).isEmpty();

        JsonNode calls = JSON.readTree(admin("GET", "/admin/v1/activity/calls", sub, "limited", GROUPS, null).body());
        assertThat(Contracts.gatewayAdminErrors("ActivityCall", calls.get(0))).as(calls.toString()).isEmpty();
        assertThat(calls.get(0).path("result").asString()).isEqualTo("rate_limited");
        JsonNode denied = JSON.readTree(admin("GET", "/admin/v1/activity/calls?result=denied", sub, "limited", GROUPS, null).body());
        assertThat(denied.size()).as("rate_limited is in the group denied").isPositive();
    }

    @Test
    void otherRequestsOverTheUserLimitAre429WithRetryAfterAndNoChallenge(CapturedOutput output) throws Exception {
        limits(3, BIG, BIG, BIG, Map.of());
        String sub = sub();
        String token = token(sub, "claude-code");
        for (int i = 0; i < 3; i++) {
            assertThat(ping(token).statusCode()).isEqualTo(200);
        }

        HttpResponse<String> limited = ping(token);

        assertThat(limited.statusCode()).isEqualTo(429);
        assertThat(Integer.parseInt(limited.headers().firstValue("Retry-After").orElseThrow())).isBetween(1, 30);
        assertThat(limited.headers().firstValue("WWW-Authenticate")).isEmpty();
        assertThat(limited.headers().map().keySet()).noneMatch(h -> h.toLowerCase().startsWith("x-ratelimit"));
        assertThat(limited.headers().firstValue("Cache-Control")).hasValue("no-store");
        assertThat(limited.headers().firstValue("X-Request-Id")).isPresent();
        JsonNode body = JSON.readTree(limited.body());
        assertThat(body.path("error").asString()).isEqualTo("rate_limited");
        assertThat(body.path("retryAfterSeconds").asInt()).isEqualTo(Integer.parseInt(limited.headers().firstValue("Retry-After").orElseThrow()));
        assertThat(Contracts.schemaErrors("schemas/tool-error.schema.json", body)).isEmpty();
        assertThat(sendModern(token, "tools/list", null, "{}").statusCode()).isEqualTo(429);
        assertThat(send(token, "/s/mcp-jira/mcp", initializeBody(), Map.of()).statusCode()).as("initialize too").isEqualTo(429);
        assertThat(getIssue(token).path("error").asString()).as("a tool call shares the budget of the user").isEqualTo("rate_limited");

        JsonNode event = events(output, sub, "rate_limited_user").getFirst();
        assertThat(event.path("event").asString()).isEqualTo("policy_decision");
        assertThat(event.path("decision").asString()).isEqualTo("deny");
        assertThat(event.path("errorCode").asString()).isEqualTo("rate_limited");
        assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", event)).isEmpty();
        assertThat(ping(token(sub(), "claude-code")).statusCode()).as("another user").isEqualTo(200);
    }

    @Test
    void theLimitOfTheClientIsPerUserAndClient(CapturedOutput output) throws Exception {
        limits(BIG, 2, BIG, BIG, Map.of());
        String sub = sub();
        String claude = token(sub, "claude-code");
        assertThat(ping(claude).statusCode()).isEqualTo(200);
        assertThat(ping(claude).statusCode()).isEqualTo(200);

        assertThat(ping(claude).statusCode()).isEqualTo(429);

        assertThat(ping(token(sub, "another-client")).statusCode()).as("the same user, another client").isEqualTo(200);
        assertThat(events(output, sub, "rate_limited_client")).isNotEmpty();
    }

    @Test
    void aDestructiveToolHasItsOwnLowerLimit() throws Exception {
        limits(BIG, BIG, BIG, 1, Map.of());
        String sub = sub();
        env.broker.enroll(sub, SECRET);
        String token = token(sub, "claude-code");
        String delete = "{\"name\":\"jira__delete_issue\",\"arguments\":{\"issueKey\":\"ABC-1\"}}";

        JsonNode first = toolError(sendModern(token, "tools/call", "jira__delete_issue", delete));
        JsonNode second = toolError(sendModern(token, "tools/call", "jira__delete_issue", delete));

        assertThat(first.path("error").asString()).isEqualTo("confirmation_required");
        assertThat(second.path("error").asString()).isEqualTo("rate_limited");
        assertThat(getIssue(token).path("error").asString("")).as("a read-only tool is not under that limit").isNotEqualTo("rate_limited");
    }

    @Test
    void aSingleToolCanBeLimitedByItsName() throws Exception {
        limits(BIG, BIG, BIG, BIG, Map.of("jira__get_issue", 1));
        String token = token(sub(), "claude-code");

        assertThat(getIssue(token).path("error").asString("")).isNotEqualTo("rate_limited");
        assertThat(getIssue(token).path("error").asString()).isEqualTo("rate_limited");
        HttpResponse<String> other = sendModern(token, "tools/call", "jira__search_issues",
                "{\"name\":\"jira__search_issues\",\"arguments\":{\"project\":\"ABC\"}}");
        assertThat(toolError(other).path("error").asString("")).isNotEqualTo("rate_limited");
    }

    @Test
    void aRefusedRequestDoesNotUseUpTheOtherBudgets() throws Exception {
        limits(3, BIG, 1, 1, Map.of());
        String token = token(sub(), "claude-code");

        assertThat(getIssue(token).path("error").asString("")).isNotEqualTo("rate_limited");
        for (int i = 0; i < 5; i++) {
            assertThat(getIssue(token).path("error").asString()).isEqualTo("rate_limited");
        }
        assertThat(ping(token).statusCode()).as("the user used two of three").isEqualTo(200);
        assertThat(ping(token).statusCode()).isEqualTo(200);
        assertThat(ping(token).statusCode()).isEqualTo(429);
    }

    @Test
    void theExcessIsAuditedOncePerIntervalAndTheRestIsCounted(CapturedOutput output) throws Exception {
        limits(BIG, BIG, 1, 1, Map.of());
        String sub = sub();
        String token = token(sub, "claude-code");
        getIssue(token);
        for (int i = 0; i < 6; i++) {
            assertThat(getIssue(token).path("error").asString()).isEqualTo("rate_limited");
        }

        assertThat(events(output, sub, "rate_limited_tool")).hasSize(1);
        assertThat(meters().counter("mcp_audit_rate_limited_suppressed_total", "reason", "rate_limited_tool").count()).isGreaterThanOrEqualTo(5);
    }

    @Test
    void whenRedisDoesNotAnswerTheRequestIsRefusedNotLetThrough(CapturedOutput output) throws Exception {
        limits(BIG, BIG, BIG, BIG, Map.of());
        String sub = sub();
        String token = token(sub, "claude-code");
        assertThat(ping(token).statusCode()).isEqualTo(200);
        var docker = env.redis.getDockerClient();
        docker.pauseContainerCmd(env.redis.getContainerId()).exec();
        try {
            HttpResponse<String> refused = ping(token);
            assertThat(refused.statusCode()).isEqualTo(503);
            assertThat(JSON.readTree(refused.body()).path("error").asString()).isEqualTo("upstream_unavailable");
            assertThat(refused.headers().firstValue("Retry-After")).isPresent();
            assertThat(refused.headers().firstValue("WWW-Authenticate")).isEmpty();
            env.jira.clearRequests();
            JsonNode call = getIssue(token);
            assertThat(call.path("error").asString()).isEqualTo("upstream_unavailable");
            assertThat(env.jira.requests()).as("the server is not reached").noneMatch(r -> "tools/call".equals(r.rpcMethod()));
            assertThat(Contracts.schemaErrors("schemas/tool-error.schema.json", call)).isEmpty();
        } finally {
            docker.unpauseContainerCmd(env.redis.getContainerId()).exec();
        }
        org.awaitility.Awaitility.await().atMost(java.time.Duration.ofSeconds(20)).until(invalidations::live);
        assertThat(ping(token).statusCode()).as("and it works again").isEqualTo(200);
        assertThat(meters().counter("mcp.gateway.rate.unavailable").count()).isPositive();
        assertThat(output.getOut()).contains("the request is refused");
    }

    @Test
    void theConfigurationOfTheLimitsIsChecked() {
        java.time.Duration minute = java.time.Duration.ofMinutes(1);
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> new pl.aiwcorpo.mcp.gateway.config.GatewayProperties.RateLimit(true, minute,
                10, 10, 5, 6, Map.of(), minute)).hasMessageContaining("destructive-per-tool");
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> new pl.aiwcorpo.mcp.gateway.config.GatewayProperties.RateLimit(true,
                java.time.Duration.ZERO, 10, 10, 5, 5, Map.of(), minute)).hasMessageContaining("window");
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> new pl.aiwcorpo.mcp.gateway.config.GatewayProperties.RateLimit(true, minute,
                10, 10, 5, 5, Map.of("jira__get_issue", 0), minute)).hasMessageContaining("jira__get_issue");
        new pl.aiwcorpo.mcp.gateway.config.GatewayProperties.RateLimit(true, minute, 10, 10, 5, 5, Map.of("jira__get_issue", 3), minute);
    }

    @org.springframework.beans.factory.annotation.Autowired
    io.micrometer.core.instrument.MeterRegistry meterRegistry;

    private io.micrometer.core.instrument.MeterRegistry meters() {
        return meterRegistry;
    }
}
