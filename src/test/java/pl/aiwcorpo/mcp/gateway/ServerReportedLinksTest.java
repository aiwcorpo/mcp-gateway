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
import pl.aiwcorpo.mcp.gateway.support.GatewayTestEnvironment;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * A server may report step_up_required, credential_required and confirmation_required in a tool result, but every link the client gets
 * is built by the gateway (CC-253): a link of the server's choosing never reaches the client, and a confirmation the gateway does not hold
 * is an internal_error.
 */
class ServerReportedLinksTest extends GatewayTestBase {

    private static final String ELSEWHERE = "https://other.invalid";

    @AfterEach
    void answerNormally() {
        env.jira.reportError(null);
    }

    private JsonNode callWithServerError(String json, String requestId) throws Exception {
        env.jira.reportError((ObjectNode) JSON.readTree(json));
        String token = env.idp.token(UUID.randomUUID().toString(), "rita", List.of("mcp-jira-read"));
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"jira__get_issue\","
                + "\"arguments\":{\"issueKey\":\"ABC-1\"},\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\","
                + "\"io.modelcontextprotocol/clientCapabilities\":{}}}}";
        HttpResponse<String> response = send(token, "/mcp", body, Map.of("MCP-Protocol-Version", "2026-07-28", "Mcp-Method", "tools/call",
                "Mcp-Name", "jira__get_issue", "X-Request-Id", requestId));
        assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
        JsonNode error = toolError(response);
        assertThat(Contracts.schemaErrors("schemas/tool-error.schema.json", error)).as(error.toString()).isEmpty();
        return error;
    }

    @Test
    void aStepUpLinkOfTheServerIsReplacedByTheGatewaysAndTheCodeIsAudited(CapturedOutput output) throws Exception {
        String requestId = pl.aiwcorpo.mcp.gateway.jwt.UuidV7.next();
        JsonNode error = callWithServerError("{\"error\":\"step_up_required\",\"message\":\"Sign in again with MFA.\",\"stepUpUrl\":\""
                + ELSEWHERE + "/login\"}", requestId);
        assertThat(error.path("error").asString()).isEqualTo("step_up_required");
        assertThat(error.path("message").asString()).isEqualTo("Sign in again with MFA.");
        assertThat(error.path("stepUpUrl").asString()).isEqualTo(GatewayTestEnvironment.PUBLIC_URL + "/api/v1/auth/login?stepUp=true&returnPath=/");
        assertThat(auditEvents(output, requestId).stream().filter(e -> "tool_call".equals(e.path("event").asString()))
                .map(e -> e.path("errorCode").asString())).containsExactly("step_up_required");
    }

    @Test
    void aRegisterLinkOfTheServerIsReplacedByTheGatewaysAndAPendingCallOfTheServerIsAnInternalError() throws Exception {
        JsonNode register = callWithServerError("{\"error\":\"confirmation_required\",\"message\":\"Register the authenticator.\","
                + "\"registerUrl\":\"" + ELSEWHERE + "/register\"}", pl.aiwcorpo.mcp.gateway.jwt.UuidV7.next());
        assertThat(register.path("error").asString()).isEqualTo("confirmation_required");
        assertThat(register.path("registerUrl").asString()).isEqualTo(GatewayTestEnvironment.PUBLIC_URL + "/authenticator");

        JsonNode pending = callWithServerError("{\"error\":\"confirmation_required\",\"message\":\"Type the code.\",\"confirmationId\":"
                + "\"cnf_0123456789abcdef\",\"description\":\"x\",\"previewUrl\":\"" + ELSEWHERE + "/confirm/1\",\"expiresAt\":"
                + "\"2026-11-13T12:00:00Z\"}", pl.aiwcorpo.mcp.gateway.jwt.UuidV7.next());
        assertThat(pending.path("error").asString()).isEqualTo("internal_error");
        assertThat(pending.toString()).doesNotContain(ELSEWHERE);
    }

    @Test
    void aConnectLinkAndSystemOfTheServerAreReplacedByTheCalledSystem() throws Exception {
        JsonNode error = callWithServerError("{\"error\":\"credential_required\",\"message\":\"Connect your account.\",\"system\":\"other\","
                + "\"connectUrl\":\"" + ELSEWHERE + "/connect\"}", pl.aiwcorpo.mcp.gateway.jwt.UuidV7.next());
        assertThat(error.path("error").asString()).isEqualTo("credential_required");
        assertThat(error.path("system").asString()).isEqualTo("jira");
        assertThat(error.path("connectUrl").asString()).isEqualTo(GatewayTestEnvironment.PUBLIC_URL + "/connections?system=jira");
    }
}
