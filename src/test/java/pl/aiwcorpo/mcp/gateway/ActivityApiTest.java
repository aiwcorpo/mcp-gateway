package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.Test;

import pl.aiwcorpo.mcp.gateway.support.Contracts;
import pl.aiwcorpo.mcp.testserver.Totp;
import tools.jackson.databind.JsonNode;

/** CC-095 end to end: one row per call from the real audit events, the caller's own calls only, a cursor that is a MAC. */
class ActivityApiTest extends GatewayTestBase {

    private static final String SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    private static final List<String> FULL = List.of("mcp-jira-read", "mcp-jira-write", "mcp-jira-destructive");

    private String sub;
    private String name;

    private void newUser() {
        sub = UUID.randomUUID().toString();
        name = "act" + UUID.randomUUID().toString().substring(0, 6);
        env.broker.enroll(sub, SECRET);
    }

    private HttpResponse<String> call(List<String> groups, String tool, String arguments) throws Exception {
        return sendModern(env.idp.token(sub, name, groups), "tools/call", "jira__" + tool,
                "{\"name\":\"jira__" + tool + "\",\"arguments\":" + arguments + "}");
    }

    private HttpResponse<String> calls(String sub, String query) throws Exception {
        return admin("GET", "/admin/v1/activity/calls" + query, sub, "whoever", FULL, null);
    }

    private List<JsonNode> rows(HttpResponse<String> response) {
        assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
        List<JsonNode> rows = new ArrayList<>();
        JSON.readTree(response.body()).forEach(rows::add);
        rows.forEach(row -> assertThat(Contracts.gatewayAdminErrors("ActivityCall", row)).as(row.toString()).isEmpty());
        return rows;
    }

    /** A user with an ok call, a denied call, a confirmed destructive call (one wrong code) and a pending one. */
    private void makeHistory() throws Exception {
        newUser();
        redisEpochProven();
        assertThat(call(FULL, "get_issue", "{\"issueKey\":\"ABC-1\"}").statusCode()).isEqualTo(200);
        Thread.sleep(5);
        call(List.of("mcp-jira-read"), "add_comment", "{\"issueKey\":\"ABC-1\",\"body\":\"x\"}");
        Thread.sleep(5);
        call(FULL, "delete_issue", "{\"issueKey\":\"ABC-2\"}");
        call(FULL, "delete_issue", "{\"issueKey\":\"ABC-2\",\"confirmation_code\":\"000000\"}");
        String code = Totp.currentCode(SECRET, System.currentTimeMillis() / 1000);
        call(FULL, "delete_issue", "{\"issueKey\":\"ABC-2\",\"confirmation_code\":\"" + code + "\"}");
        Thread.sleep(5);
        call(FULL, "delete_issue", "{\"issueKey\":\"ABC-3\"}");
    }

    private void redisEpochProven() {
        io.lettuce.core.RedisClient client = io.lettuce.core.RedisClient.create(io.lettuce.core.RedisURI.builder()
                .withHost(env.redis.getHost()).withPort(env.redis.getMappedPort(6379))
                .withAuthentication("admin", pl.aiwcorpo.mcp.gateway.support.GatewayTestEnvironment.REDIS_ADMIN_PASSWORD.toCharArray()).build());
        try (var connection = client.connect()) {
            connection.sync().set("gw:conf:epoch", Long.toString(System.currentTimeMillis() - 3_600_000L));
        } finally {
            client.shutdown();
        }
    }

    @Test
    void oneRowPerCallNewestFirstWithTheFinalResult() throws Exception {
        makeHistory();
        HttpResponse<String> response = calls(sub, "");
        List<JsonNode> rows = rows(response);
        assertThat(rows).hasSize(4);
        assertThat(rows.stream().map(r -> r.path("result").asString()).toList())
                .containsExactly("confirmation_pending", "confirmed", "denied_not_granted", "ok");
        assertThat(rows.get(0).path("tool").asString()).isEqualTo("jira__delete_issue");
        assertThat(rows.get(0).path("risk").asString()).isEqualTo("DESTRUCTIVE");
        assertThat(rows.get(0).path("resource").path("id").asString()).isEqualTo("ABC-3");
        assertThat(rows.get(1).path("wrongCodeCount").asInt()).isEqualTo(1);
        assertThat(rows.get(1).path("errorCode").isNull()).isTrue();
        assertThat(rows.get(2).path("errorCode").asString()).isEqualTo("not_found_or_denied");
        assertThat(rows.get(3).path("client").asString()).isEqualTo("claude-code");
        assertThat(rows.stream().map(r -> r.path("requestId").asString()).distinct().count()).isEqualTo(4);
        assertThat(response.headers().firstValue("X-Next-Cursor")).isEmpty();
        assertThat(response.headers().firstValue("Cache-Control").orElse("")).contains("no-store");
        assertThat(response.body()).doesNotContain("000000").doesNotContain("confirmation_code").doesNotContain("\"body\"");
    }

    @Test
    void filtersNarrowTheRowsAfterTheAggregation() throws Exception {
        makeHistory();
        assertThat(rows(calls(sub, "?result=confirmation"))).hasSize(2);
        assertThat(rows(calls(sub, "?result=ok"))).hasSize(1);
        assertThat(rows(calls(sub, "?result=denied"))).hasSize(1);
        assertThat(rows(calls(sub, "?result=error"))).isEmpty();
        assertThat(rows(calls(sub, "?q=GET_ISS"))).hasSize(1);
        assertThat(rows(calls(sub, "?q=abc-3"))).hasSize(1);
        assertThat(rows(calls(sub, "?from=" + Instant.now().plusSeconds(60)))).isEmpty();
        assertThat(rows(calls(sub, "?to=" + Instant.now().minusSeconds(3600)))).isEmpty();
    }

    @Test
    void pagesFollowTheCursorAndTheCursorBelongsToTheUser() throws Exception {
        makeHistory();
        HttpResponse<String> first = calls(sub, "?limit=3");
        List<JsonNode> page1 = rows(first);
        assertThat(page1).hasSize(3);
        String cursor = first.headers().firstValue("X-Next-Cursor").orElseThrow();
        List<JsonNode> page2 = rows(calls(sub, "?limit=3&cursor=" + cursor));
        assertThat(page2).hasSize(1);
        assertThat(page2.get(0).path("result").asString()).isEqualTo("ok");

        String other = UUID.randomUUID().toString();
        assertThat(calls(other, "?cursor=" + cursor).statusCode()).as("foreign cursor").isEqualTo(400);
        assertThat(calls(sub, "?cursor=" + cursor.substring(0, cursor.length() - 2) + "AA").statusCode()).as("changed tag").isEqualTo(400);
        String payload = cursor.substring(0, cursor.indexOf('.'));
        assertThat(calls(sub, "?cursor=" + payload.substring(0, payload.length() - 2) + "AA" + cursor.substring(cursor.indexOf('.')))
                .statusCode()).as("changed position").isEqualTo(400);
        assertThat(calls(sub, "?cursor=garbage").statusCode()).isEqualTo(400);
    }

    @Test
    void badParametersAreRejected() throws Exception {
        newUser();
        for (String query : List.of("?limit=0", "?limit=201", "?result=maybe", "?from=yesterday", "?q=", "?limit=abc")) {
            assertThat(calls(sub, query).statusCode()).as(query).isEqualTo(400);
        }
    }

    @Test
    void someoneElseSeesNothingOfMyCalls() throws Exception {
        makeHistory();
        String stranger = UUID.randomUUID().toString();
        assertThat(rows(calls(stranger, ""))).isEmpty();
        assertThat(rows(calls(sub, ""))).hasSize(4);
    }

    @Test
    void theEventListHoldsTheCallersEventsWithoutArguments() throws Exception {
        makeHistory();
        HttpResponse<String> response = admin("GET", "/admin/v1/activity?limit=100", sub, "x", FULL, null);
        assertThat(response.statusCode()).isEqualTo(200);
        JsonNode events = JSON.readTree(response.body());
        assertThat(events.size()).isGreaterThan(4);
        for (JsonNode event : events) {
            assertThat(event.path("sub").asString()).isEqualTo(sub);
            assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", event)).isEmpty();
        }
        assertThat(response.body()).doesNotContain("000000");
    }
}
