package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import java.net.http.HttpClient;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import pl.aiwcorpo.mcp.gateway.support.GatewayProcess;
import pl.aiwcorpo.mcp.gateway.support.GatewayTestEnvironment;
import pl.aiwcorpo.mcp.gateway.support.SseClient;
import tools.jackson.databind.json.JsonMapper;

/**
 * The limit of open streams of an instance (MCP_MAX_OPEN_STREAMS, decision of 2026-11-03), on a gateway of its own that allows two: both kinds of
 * stream count, the refusal is the 503 of an instance that is busy (CC-199) with Retry-After, and a place is free again when a stream closes.
 */
class StreamLimitTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final HttpClient HTTP = HttpClient.newHttpClient();
    private static GatewayTestEnvironment env;
    private static GatewayProcess gateway;

    @BeforeAll
    static void start() throws Exception {
        env = GatewayTestEnvironment.get();
        Path dir = Files.createTempDirectory("mcp-gateway-streams");
        Map<String, String> properties = new LinkedHashMap<>(env.properties());
        properties.remove("gateway.internal-endpoint.port");
        properties.put("gateway.mcp.max-open-streams", "2");
        properties.put("gateway.policy.state-dir", Files.createDirectories(dir.resolve("state")).toString());
        gateway = GatewayProcess.start("streams-limit", dir, properties, GatewayProcess.freePort(), GatewayProcess.freePort());
    }

    @AfterAll
    static void stop() {
        if (gateway != null) {
            gateway.close();
        }
    }

    private SseClient listen(String token, int id) throws Exception {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"method\":\"subscriptions/listen\",\"params\":{\"_meta\":{"
                + "\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{}},"
                + "\"notifications\":{\"toolsListChanged\":true}}}";
        return SseClient.post(HTTP, "http://localhost:" + gateway.port() + "/mcp", body, Map.of("Authorization", "Bearer " + token,
                "MCP-Protocol-Version", "2026-07-28", "Mcp-Method", "subscriptions/listen"));
    }

    @Test
    void streamsOfBothKindsCountAndTheRefusalIsTheBusyInstance() throws Exception {
        String token = env.idp.token(UUID.randomUUID().toString(), "streams", List.of("mcp-jira-read"));
        java.net.http.HttpResponse<String> init = HTTP.send(java.net.http.HttpRequest.newBuilder(
                java.net.URI.create("http://localhost:" + gateway.port() + "/mcp")).header("Authorization", "Bearer " + token)
                .header("Content-Type", "application/json").header("Accept", "application/json, text/event-stream")
                .POST(java.net.http.HttpRequest.BodyPublishers.ofString("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":"
                        + "{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"t\",\"version\":\"1\"}}}")).build(),
                java.net.http.HttpResponse.BodyHandlers.ofString());
        String session = init.headers().firstValue("Mcp-Session-Id").orElseThrow();

        try (SseClient first = listen(token, 1); SseClient second = SseClient.get(HTTP, "http://localhost:" + gateway.port() + "/mcp",
                Map.of("Authorization", "Bearer " + token, "Mcp-Session-Id", session))) {
            assertThat(first.status()).isEqualTo(200);
            assertThat(second.status()).isEqualTo(200);

            try (SseClient refusedListen = listen(token, 2); SseClient refusedGet = SseClient.get(HTTP, "http://localhost:" + gateway.port() + "/mcp",
                    Map.of("Authorization", "Bearer " + token, "Mcp-Session-Id", session))) {
                for (SseClient refused : List.of(refusedListen, refusedGet)) {
                    assertThat(refused.status()).isEqualTo(503);
                    assertThat(refused.response().headers().firstValue("Retry-After")).hasValue("2");
                    assertThat(refused.response().headers().firstValue("WWW-Authenticate")).isEmpty();
                    assertThat(JSON.readTree(String.join("", refused.untilEnd(Duration.ofSeconds(2)))).path("error").asString())
                            .isEqualTo("upstream_unavailable");
                }
            }

            first.close();
            await().atMost(Duration.ofSeconds(20)).pollInterval(Duration.ofMillis(500)).untilAsserted(() -> {
                try (SseClient again = listen(token, 3)) {
                    assertThat(again.status()).as("a place is free after a stream closed").isEqualTo(200);
                }
            });
        }
    }
}
