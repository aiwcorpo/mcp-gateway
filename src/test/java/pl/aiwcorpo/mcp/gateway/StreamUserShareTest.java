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
 * The share of one user in the open streams of an instance (MCP_MAX_OPEN_STREAMS_PER_USER), on a gateway of its own that allows two streams
 * and one per user (CC-254): the second stream of a user is refused with 429 like a request over a limit of the user, audited as
 * rate_limited_user, and another user still gets a place.
 */
class StreamUserShareTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final HttpClient HTTP = HttpClient.newHttpClient();
    private static GatewayTestEnvironment env;
    private static GatewayProcess gateway;

    @BeforeAll
    static void start() throws Exception {
        env = GatewayTestEnvironment.get();
        Path dir = Files.createTempDirectory("mcp-gateway-stream-share");
        Map<String, String> properties = new LinkedHashMap<>(env.properties());
        properties.remove("gateway.internal-endpoint.port");
        properties.put("gateway.mcp.max-open-streams", "2");
        properties.put("gateway.mcp.max-open-streams-per-user", "1");
        gateway = GatewayProcess.start("streams-share", dir, properties, GatewayProcess.freePort(), GatewayProcess.freePort());
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
    void aUserBeyondItsShareIsRefusedAndAnotherUserStillOpensAStream() throws Exception {
        String a = env.idp.token(UUID.randomUUID().toString(), "share-a", List.of("mcp-jira-read"));
        String b = env.idp.token(UUID.randomUUID().toString(), "share-b", List.of("mcp-jira-read"));

        try (SseClient first = listen(a, 1)) {
            assertThat(first.status()).isEqualTo(200);
            try (SseClient beyond = listen(a, 2)) {
                assertThat(beyond.status()).as("the second stream of one user").isEqualTo(429);
                assertThat(beyond.response().headers().firstValue("Retry-After")).hasValue("2");
                assertThat(beyond.response().headers().firstValue("WWW-Authenticate")).isEmpty();
                assertThat(beyond.response().headers().firstValue("X-RateLimit-Limit")).isEmpty();
                assertThat(JSON.readTree(String.join("", beyond.untilEnd(Duration.ofSeconds(2)))).path("error").asString())
                        .isEqualTo("rate_limited");
            }
            try (SseClient other = listen(b, 3)) {
                assertThat(other.status()).as("a place of the instance is left for another user").isEqualTo(200);
            }
            await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> assertThat(gateway.output().lines()
                    .filter(line -> line.contains("\"event\":\"policy_decision\"") && line.contains("\"username\":\"share-a\""))
                    .anyMatch(line -> line.contains("\"reason\":\"rate_limited_user\"") && line.contains("\"errorCode\":\"rate_limited\"")))
                    .as("the refusal is audited as the limit of the user").isTrue());
        }
    }
}
