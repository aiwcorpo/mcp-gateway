package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.system.CapturedOutput;

import io.micrometer.core.instrument.MeterRegistry;
import pl.aiwcorpo.mcp.gateway.killswitch.KillSwitchStore;
import pl.aiwcorpo.mcp.gateway.killswitch.KillSwitches;
import pl.aiwcorpo.mcp.gateway.support.SseClient;
import pl.aiwcorpo.mcp.gateway.support.Vectors;
import tools.jackson.databind.JsonNode;

/**
 * The streams of the gateway (CC-192, CC-207) over HTTP: the {@code GET} of a legacy session and the {@code POST subscriptions/listen} of the
 * stateless protocol. How a stream is opened (the vectors {@code endpoint-filter/stream-open-*}), what it announces and to whom, the heartbeat,
 * the end of a stream, and that no stream takes a place of the limit of requests in flight.
 */
class StreamEndpointTest extends GatewayTestBase {

    @org.springframework.beans.factory.annotation.Autowired
    pl.aiwcorpo.mcp.gateway.registry.DefinitionGuard definitions;

    private static final Duration FIVE_SECONDS = Duration.ofSeconds(5);
    private static final String JIRA = "/admin/v1/registry/servers/mcp-jira";

    @Autowired
    KillSwitchStore store;

    @Autowired
    KillSwitches switches;

    @Autowired
    MeterRegistry meters;

    private final List<SseClient> open = new ArrayList<>();

    @AfterEach
    void closeStreamsAndLiftSwitches() {
        open.forEach(SseClient::close);
        open.clear();
        store.all().forEach(entry -> store.delete(entry.serverId(), entry.tool()));
        switches.refresh();
    }

    private String token(String sub) {
        return env.idp.token(sub, "streamer", List.of("mcp-jira-read", "mcp-jira-write", "mcp-gitlab-read"));
    }

    private String sessionOn(String token, String pathWithQuery) throws Exception {
        HttpResponse<String> response = send(token, pathWithQuery, initializeBody(), Map.of());
        assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
        return response.headers().firstValue("Mcp-Session-Id").orElseThrow();
    }

    private SseClient stream(String token, String pathWithQuery, String session) throws Exception {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Authorization", "Bearer " + token);
        headers.put("MCP-Protocol-Version", "2025-11-25");
        if (session != null) {
            headers.put("Mcp-Session-Id", session);
        }
        SseClient client = SseClient.get(http, "http://localhost:" + port + pathWithQuery, headers);
        open.add(client);
        return client;
    }

    private SseClient listen(String token, String pathWithQuery, int id, boolean tools) throws Exception {
        return listen(token, pathWithQuery, Integer.toString(id), tools);
    }

    /** As above with the id as JSON text. */
    private SseClient listen(String token, String pathWithQuery, String id, boolean tools) throws Exception {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"method\":\"subscriptions/listen\",\"params\":{\"_meta\":{"
                + "\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{}},"
                + "\"notifications\":{" + (tools ? "\"toolsListChanged\":true" : "") + "}}}";
        SseClient client = SseClient.post(http, "http://localhost:" + port + pathWithQuery, body, Map.of("Authorization", "Bearer " + token,
                "MCP-Protocol-Version", "2026-07-28", "Mcp-Method", "subscriptions/listen"));
        open.add(client);
        return client;
    }

    private HttpResponse<String> asAdmin(String method, String path, String body) throws Exception {
        return admin(method, path, "3b0d6f2e-91c4-4d7a-8a52-6c1e4f7a9d10", "a.admin", List.of("mcp-platform-admin"), body);
    }

    private void switchOff(String tool) throws Exception {
        assertThat(asAdmin("PUT", JIRA + "/tools/" + tool + "/kill-switch", "{\"reason\":\"test\"}").statusCode()).isEqualTo(204);
    }

    private void switchOn(String tool) throws Exception {
        assertThat(asAdmin("DELETE", JIRA + "/tools/" + tool + "/kill-switch", null).statusCode()).isEqualTo(204);
    }

    @Test
    void bothProtocolsDeclareListChanged() throws Exception {
        HttpResponse<String> initialize = send(token(UUID.randomUUID().toString()), "/mcp", initializeBody(), Map.of());
        assertThat(JSON.readTree(initialize.body()).path("result").path("capabilities").path("tools").path("listChanged").asBoolean()).isTrue();
        HttpResponse<String> discover = sendModern(token(UUID.randomUUID().toString()), "/mcp", "server/discover", null, "{}");
        assertThat(JSON.readTree(discover.body()).path("result").path("capabilities").path("tools").path("listChanged").asBoolean()).isTrue();
    }

    @TestFactory
    List<DynamicTest> theOpeningOfAStreamAsTheVectorsWantIt() {
        List<Vectors.Vector> vectors = Vectors.of("endpoint-filter").stream().filter(v -> "stream-open".equals(v.document().path("kind").asString())).toList();
        assertThat(vectors).hasSize(9);
        return vectors.stream().map(v -> DynamicTest.dynamicTest(v.name(), () -> opening(v.document()))).toList();
    }

    private void opening(JsonNode vector) throws Exception {
        JsonNode input = vector.path("input");
        JsonNode expected = vector.path("expected");
        String query = input.path("requestQuery").asString();
        if ("stateless".equals(input.path("variant").asString())) {
            SseClient client = listen(token(UUID.randomUUID().toString()), "/mcp?" + query, 1, true);
            if ("continue".equals(expected.path("status").asString())) {
                assertThat(client.status()).isEqualTo(200);
                assertThat(client.response().headers().firstValue("Content-Type").orElse("")).startsWith("text/event-stream");
            } else {
                assertThat(client.status()).isEqualTo(expected.path("status").asInt());
                String body = String.join("", client.untilEnd(Duration.ofSeconds(2)));
                assertThat(JSON.readTree(body).path("reason").asString()).isEqualTo(expected.path("reason").asString());
            }
            return;
        }
        String callerSub = UUID.randomUUID().toString();
        JsonNode stored = input.path("session");
        String route = input.path("route").asString();
        String sessionId = null;
        if (!stored.isNull() && !stored.isMissingNode()) {
            String ownerSub = stored.path("sub").asString().equals(input.path("callerSub").asString()) ? callerSub : UUID.randomUUID().toString();
            String initializeQuery = stored.path("initializeQuery").asString();
            sessionId = sessionOn(token(ownerSub), stored.path("route").asString() + (initializeQuery.isEmpty() ? "" : "?" + initializeQuery));
        }
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Authorization", "Bearer " + token(callerSub));
        headers.put("Accept", input.path("accept").asString());
        if (sessionId != null) {
            headers.put("Mcp-Session-Id", sessionId);
        }
        SseClient client = SseClient.get(http, "http://localhost:" + port + route + (query.isEmpty() ? "" : "?" + query), headers);
        open.add(client);
        if ("continue".equals(expected.path("status").asString())) {
            assertThat(client.status()).isEqualTo(200);
            assertThat(client.response().headers().firstValue("Content-Type").orElse("")).startsWith("text/event-stream");
            return;
        }
        assertThat(client.status()).isEqualTo(expected.path("status").asInt());
        if (expected.has("headers")) {
            expected.path("headers").properties().forEach(h -> assertThat(client.response().headers().firstValue(h.getKey())).contains(h.getValue().asString()));
        }
    }

    @Test
    void aChangeOfTheListIsAnnouncedOnTheStreamOfASessionAndOnlyToThoseWhoseListItChanges() throws Exception {
        String sub = UUID.randomUUID().toString();
        String token = token(sub);
        SseClient all = stream(token, "/mcp", sessionOn(token, "/mcp"));
        SseClient jiraOnly = stream(token, "/mcp?systems=jira", sessionOn(token, "/mcp?systems=jira"));
        SseClient gitlabOnly = stream(token, "/mcp?systems=gitlab", sessionOn(token, "/mcp?systems=gitlab"));
        assertThat(all.status()).isEqualTo(200);
        assertThat(all.response().headers().firstValue("Content-Type").orElse("")).startsWith("text/event-stream");
        assertThat(all.nextLine(Duration.ofSeconds(2))).isEqualTo(": open");

        switchOff("get_issue");

        JsonNode notification = all.nextMessage(FIVE_SECONDS);
        assertThat(notification).as("within 5 s of the 204").isNotNull();
        assertThat(notification.path("method").asString()).isEqualTo("notifications/tools/list_changed");
        assertThat(notification.has("id")).isFalse();
        assertThat(notification.has("params")).as("empty: nothing of the change is revealed").isFalse();
        assertThat(jiraOnly.nextMessage(FIVE_SECONDS)).isNotNull();
        assertThat(gitlabOnly.nextMessage(Duration.ofMillis(2500))).as("the filter cuts the tool: no notification").isNull();

        switchOn("get_issue");

        assertThat(all.nextMessage(FIVE_SECONDS)).isNotNull();
        assertThat(all.keepalive(Duration.ofSeconds(3))).as("heartbeat").isTrue();
        assertThat(gitlabOnly.nextMessage(Duration.ofMillis(500))).isNull();
    }

    @Test
    void theStreamOfASessionEndsWithTheSessionAndWithItsUser() throws Exception {
        String token = token(UUID.randomUUID().toString());
        String session = sessionOn(token, "/mcp");
        SseClient stream = stream(token, "/mcp", session);
        assertThat(stream.nextLine(Duration.ofSeconds(2))).isEqualTo(": open");
        HttpResponse<String> deleted = http.send(java.net.http.HttpRequest.newBuilder(java.net.URI.create("http://localhost:" + port + "/mcp"))
                .DELETE().header("Authorization", "Bearer " + token).header("Mcp-Session-Id", session).build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(deleted.statusCode()).isEqualTo(204);
        await().atMost(Duration.ofSeconds(3)).until(stream::ended);

        String sub = UUID.randomUUID().toString();
        String other = token(sub);
        SseClient second = stream(other, "/mcp", sessionOn(other, "/mcp"));
        SseClient third = listen(other, "/mcp", 3, true);
        assertThat(second.nextLine(Duration.ofSeconds(2))).isEqualTo(": open");
        assertThat(third.nextMessage(Duration.ofSeconds(2)).path("method").asString()).isEqualTo("notifications/subscriptions/acknowledged");
        HttpResponse<String> purge = admin(env.offboardingTls, "POST", "/admin/v1/users/" + sub + "/purge", null, null);
        assertThat(purge.statusCode()).isIn(200, 204);
        await().atMost(Duration.ofSeconds(3)).until(second::ended);
        JsonNode closing = third.nextMessage(Duration.ofSeconds(3));
        assertThat(closing.path("result").path("resultType").asString()).isEqualTo("complete");
        await().atMost(Duration.ofSeconds(3)).until(third::ended);
    }

    @Test
    void theStatelessStreamAcknowledgesAnnouncesAndEndsGracefullyWhenItsTokenEnds() throws Exception {
        String sub = UUID.randomUUID().toString();
        SseClient stream = listen(env.idp.token(sub, "streamer", List.of("mcp-jira-read", "mcp-jira-write"), "mcp-gateway", "claude-code", 6), "/mcp", 7, true);
        SseClient jiraOnly = listen(token(UUID.randomUUID().toString()), "/mcp?systems=gitlab", 9, true);
        SseClient nothingAsked = listen(token(UUID.randomUUID().toString()), "/mcp", 11, false);

        JsonNode acknowledged = stream.nextMessage(Duration.ofSeconds(2));
        assertThat(acknowledged.path("method").asString()).isEqualTo("notifications/subscriptions/acknowledged");
        assertThat(acknowledged.path("params").path("_meta").path("io.modelcontextprotocol/subscriptionId").asInt()).isEqualTo(7);
        assertThat(acknowledged.path("params").path("notifications").path("toolsListChanged").asBoolean()).isTrue();
        JsonNode silent = nothingAsked.nextMessage(Duration.ofSeconds(2));
        assertThat(silent.path("params").path("notifications").has("toolsListChanged")).as("only what the client asked for").isFalse();
        assertThat(jiraOnly.nextMessage(Duration.ofSeconds(2)).path("params").path("_meta").path("io.modelcontextprotocol/subscriptionId").asInt()).isEqualTo(9);

        switchOff("search_issues");

        JsonNode notification = stream.nextMessage(FIVE_SECONDS);
        assertThat(notification.path("method").asString()).isEqualTo("notifications/tools/list_changed");
        assertThat(notification.path("params").path("_meta").path("io.modelcontextprotocol/subscriptionId").asInt()).isEqualTo(7);
        assertThat(nothingAsked.nextMessage(Duration.ofMillis(1500))).as("it asked for nothing").isNull();
        assertThat(jiraOnly.nextMessage(Duration.ofMillis(500))).isNull();

        JsonNode closing = stream.nextMessage(Duration.ofSeconds(10));
        assertThat(closing).as("the token ended: the server answers the request and closes").isNotNull();
        assertThat(closing.path("id").asInt()).isEqualTo(7);
        assertThat(closing.path("result").path("resultType").asString()).isEqualTo("complete");
        await().atMost(Duration.ofSeconds(3)).until(stream::ended);
    }

    @Test
    void aListenWhoseIdIsNotAStringOrANumberOpensNoStream() throws Exception {
        double before = meters.get("mcp_gateway_open_streams").gauge().value();
        for (String id : List.of("[{},{}]", "{\"a\":1}", "true", "\"" + "x".repeat(129) + "\"")) {
            SseClient client = listen(token(UUID.randomUUID().toString()), "/mcp", id, true);
            assertThat(client.status()).as(id).isEqualTo(400);
            JsonNode error = JSON.readTree(String.join("", client.untilEnd(Duration.ofSeconds(2))));
            assertThat(error.path("error").path("code").asInt()).as(id).isEqualTo(-32600);
            assertThat(error.has("id")).as(id).isFalse();
        }
        assertThat(meters.get("mcp_gateway_open_streams").gauge().value()).isLessThanOrEqualTo(before);

        String longest = "x".repeat(128);
        SseClient stream = listen(token(UUID.randomUUID().toString()), "/mcp", "\"" + longest + "\"", true);
        assertThat(stream.status()).isEqualTo(200);
        assertThat(stream.nextMessage(Duration.ofSeconds(2)).path("params").path("_meta").path("io.modelcontextprotocol/subscriptionId")
                .asString()).isEqualTo(longest);
    }

    @Test
    void aStreamOnTheRouteOfOneSystemHearsOnlyOfThatSystem() throws Exception {
        String token = token(UUID.randomUUID().toString());
        SseClient jira = stream(token, "/s/mcp-jira/mcp", sessionOn(token, "/s/mcp-jira/mcp"));
        SseClient everything = stream(token, "/mcp", sessionOn(token, "/mcp"));
        assertThat(jira.nextLine(Duration.ofSeconds(2))).isEqualTo(": open");

        assertThat(asAdmin("PUT", "/admin/v1/registry/servers/mcp-gitlab/tools/get_issue/kill-switch", "{\"reason\":\"test\"}").statusCode()).isEqualTo(204);

        assertThat(everything.nextMessage(FIVE_SECONDS)).as("the list of all systems changed").isNotNull();
        assertThat(jira.nextMessage(Duration.ofMillis(2000))).as("the list of the route did not").isNull();
    }

    @Test
    void aTokenWithOtherGroupsOnTheSessionChangesTheListOfItsStream() throws Exception {
        // The write tool of the server is in its manifest; the server serves it only now, and the list of the stream follows what it served last.
        env.jira.updateTool(true);
        try {
            String sub = UUID.randomUUID().toString();
            String wide = env.idp.token(sub, "streamer", List.of("mcp-jira-read", "mcp-jira-write"));
            String narrow = env.idp.token(sub, "streamer", List.of("mcp-jira-read"));
            definitions.forget("mcp-jira");
            assertThat(sendModern(wide, "/mcp", "tools/list", null, "{}").body()).contains("jira__add_comment");
            String session = sessionOn(wide, "/mcp");
            SseClient stream = stream(wide, "/mcp", session);
            assertThat(stream.nextLine(Duration.ofSeconds(2))).isEqualTo(": open");

            HttpResponse<String> ping = send(narrow, "/mcp", "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"ping\"}",
                    Map.of("Mcp-Session-Id", session, "MCP-Protocol-Version", "2025-11-25"));
            assertThat(ping.statusCode()).isEqualTo(200);

            assertThat(stream.nextMessage(FIVE_SECONDS)).as("the user lost the write tools").isNotNull();
        } finally {
            env.jira.updateTool(false);
            definitions.forget("mcp-jira");
        }
    }

    @Test
    void openingAStreamCountsForTheLimitsOfRequestsOfTheUserLikeAnyRequest() throws Exception {
        pl.aiwcorpo.mcp.gateway.support.RateLimitTestConfiguration.use(pl.aiwcorpo.mcp.gateway.support.RateLimitTestConfiguration
                .settings(4, 1_000_000, 1_000_000, 1_000_000, Map.of()));
        try {
            String sub = UUID.randomUUID().toString();
            String token = token(sub);
            String session = sessionOn(token, "/mcp");
            assertThat(stream(token, "/mcp", session).status()).isEqualTo(200);
            assertThat(stream(token, "/mcp", session).status()).isEqualTo(200);
            assertThat(listen(token, "/mcp", 1, true).status()).isEqualTo(200);

            SseClient fourth = stream(token, "/mcp", session);
            assertThat(fourth.status()).as("the fourth request of the user in the window").isEqualTo(429);
            assertThat(fourth.response().headers().firstValue("Retry-After")).isPresent();
            SseClient fifth = listen(token, "/mcp", 2, true);
            assertThat(fifth.status()).isEqualTo(429);
        } finally {
            pl.aiwcorpo.mcp.gateway.support.RateLimitTestConfiguration.restore();
        }
    }

    @Test
    void noStreamTakesAPlaceOfTheLimitOfRequestsInFlight() throws Exception {
        double before = meters.get("mcp_gateway_open_streams").gauge().value();
        String token = token(UUID.randomUUID().toString());
        stream(token, "/mcp", sessionOn(token, "/mcp"));
        listen(token, "/mcp", 1, true);
        listen(token, "/s/mcp-jira/mcp", 2, true);

        await().atMost(Duration.ofSeconds(3)).untilAsserted(() ->
                assertThat(meters.get("mcp_gateway_open_streams").gauge().value()).isEqualTo(before + 3));
        assertThat(meters.get("mcp_gateway_requests_in_flight").gauge().value()).as("the streams gave their places back").isZero();

        open.forEach(SseClient::close);
        await().atMost(Duration.ofSeconds(5)).untilAsserted(() ->
                assertThat(meters.get("mcp_gateway_open_streams").gauge().value()).isEqualTo(before));
    }
}
