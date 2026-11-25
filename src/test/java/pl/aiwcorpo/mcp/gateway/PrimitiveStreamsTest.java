package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.Map;

import org.junit.jupiter.api.Test;

import pl.aiwcorpo.mcp.gateway.support.SseClient;
import tools.jackson.databind.JsonNode;

/**
 * The streams announce a change of the lists of resources and of prompts (CC-259): what the client asks for in {@code subscriptions/listen}
 * is acknowledged, and what changes in the registry reaches it as the notification of that list and of no other.
 */
class PrimitiveStreamsTest extends DocsServerTestBase {

    @Test
    void aStreamAnnouncesAChangeOfTheListsOfResourcesAndPrompts() throws Exception {
        String token = reader();
        String body = "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"subscriptions/listen\",\"params\":{\"_meta\":{"
                + "\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{}},"
                + "\"notifications\":{\"resourcesListChanged\":true,\"promptsListChanged\":true}}}";
        try (SseClient stream = SseClient.post(http, "http://localhost:" + port + "/mcp", body, Map.of("Authorization", "Bearer " + token,
                "MCP-Protocol-Version", "2026-07-28", "Mcp-Method", "subscriptions/listen"))) {
            JsonNode acknowledged = stream.nextMessage(Duration.ofSeconds(5));
            assertThat(acknowledged.path("method").asString()).isEqualTo("notifications/subscriptions/acknowledged");
            assertThat(acknowledged.path("params").path("notifications").path("resourcesListChanged").asBoolean()).isTrue();
            assertThat(acknowledged.path("params").path("notifications").path("promptsListChanged").asBoolean()).isTrue();
            assertThat(acknowledged.path("params").path("notifications").has("toolsListChanged")).isFalse();

            assertThat(adminCall("PUT", REGISTRY + "/prompts/summarize_issue/kill-switch", "{\"reason\":\"test\"}").statusCode()).isEqualTo(204);

            assertThat(stream.nextMessage(Duration.ofSeconds(8)).path("method").asString()).isEqualTo("notifications/prompts/list_changed");
            assertThat(adminCall("PUT", REGISTRY + "/resources/runbook/kill-switch", "{\"reason\":\"test\"}").statusCode()).isEqualTo(204);
            assertThat(stream.nextMessage(Duration.ofSeconds(8)).path("method").asString()).isEqualTo("notifications/resources/list_changed");
        }
    }
}
