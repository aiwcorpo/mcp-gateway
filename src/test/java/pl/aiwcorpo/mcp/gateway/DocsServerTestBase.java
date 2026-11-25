package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.test.util.ReflectionTestUtils;

import pl.aiwcorpo.mcp.gateway.agent.AgentRegistry;
import pl.aiwcorpo.mcp.gateway.agent.AgentStore;
import pl.aiwcorpo.mcp.gateway.killswitch.KillSwitchStore;
import pl.aiwcorpo.mcp.gateway.killswitch.KillSwitches;
import pl.aiwcorpo.mcp.gateway.mcp.PrimitiveService;
import pl.aiwcorpo.mcp.testserver.TestMcpServer;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * A server of its own, {@code mcp-docs}, that publishes one static resource ({@code runbook}), one template ({@code issue}) and one prompt
 * ({@code summarize_issue}) and whose entries the administrator approves one by one, for the tests of what the gateway makes of them.
 */
abstract class DocsServerTestBase extends GatewayTestBase {

    protected static final String SERVER_PATH = "/admin/v1/servers/mcp-docs";
    protected static final String REGISTRY = "/admin/v1/registry/servers/mcp-docs";
    protected static final List<String> READER = List.of("mcp-docs-read");
    protected static final String RUNBOOK = "docs://docs/runbook";
    protected static final String ISSUE = "docs://issue/ABC-123";
    protected static final String CLIENT_AGENT = "agent-docs";
    protected static final String AGENT_SUB = "5e1a9c47-0b3d-4f6a-8c2e-7d9b1a4f6c03";

    @Autowired
    protected PrimitiveService primitives;

    @Autowired
    KillSwitchStore switchStore;

    @Autowired
    KillSwitches switches;

    @Autowired
    AgentStore agentStore;

    @Autowired
    AgentRegistry agents;

    protected TestMcpServer server;

    @BeforeEach
    void publish() throws Exception {
        server = env.startServer("mcp-docs");
        server.servePrimitives(true);
        register();
        await().atMost(Duration.ofSeconds(15)).untilAsserted(() -> assertThat(names(list(reader(), "/mcp", "resources/list", "resources"))).contains("runbook"));
    }

    @AfterEach
    void cleanUp() throws Exception {
        adminCall("DELETE", SERVER_PATH, null);
        server.close();
        switchStore.all().forEach(e -> {
            if (e.resource() != null) {
                switchStore.deleteNamed(e.serverId(), "resource", e.resource());
            } else if (e.prompt() != null) {
                switchStore.deleteNamed(e.serverId(), "prompt", e.prompt());
            }
        });
        switches.refresh();
        jdbc.sql("DELETE FROM agent_clients").update();
        agents.refresh();
        ReflectionTestUtils.setField(primitives, "brokerContractsVersion", "8.0.0");
        env.jira.answerCallsWith(null);
        env.broker.clear();
    }

    /** Adds the server, approves its connection and its policies, then every entry it publishes, as an administrator does one by one. */
    protected void register() throws Exception {
        HttpResponse<String> created = adminCall("POST", "/admin/v1/servers", "{\"internalUrl\":\"https://127.0.0.1:" + server.port() + "/mcp\"}");
        assertThat(created.statusCode()).as(created.body()).isEqualTo(201);
        String fingerprint = JSON.readTree(created.body()).path("pendingConnection").path("fingerprint").asString();
        assertThat(adminCall("POST", SERVER_PATH + "/connection/approve", "{\"tlsMode\":\"ca\",\"fingerprint\":\"" + fingerprint + "\"}").statusCode())
                .isEqualTo(200);
        refresh();
        approveEverything();
    }

    protected void refresh() throws Exception {
        assertThat(adminCall("POST", SERVER_PATH + "/refresh", null).statusCode()).isEqualTo(200);
    }

    protected void approveEverything() throws Exception {
        ObjectNode manifest = server.manifest();
        assertThat(adminCall("POST", REGISTRY + "/policies/approve", "{\"policiesHash\":\"" + manifest.path("policiesHash").asString() + "\"}")
                .statusCode()).isEqualTo(200);
        approve("resources", "runbook", manifest.path("resources").get(0));
        approve("resource-templates", "issue", manifest.path("resourceTemplates").get(0));
        approve("prompts", "summarize_issue", manifest.path("prompts").get(0));
    }

    protected void approve(String kind, String name, JsonNode entry) throws Exception {
        HttpResponse<String> approved = adminCall("POST", REGISTRY + "/" + kind + "/" + name + "/approve",
                "{\"definitionHash\":\"" + entry.path("definitionHash").asString() + "\"}");
        assertThat(approved.statusCode()).as(approved.body()).isEqualTo(204);
    }

    protected String reader() {
        return env.idp.token(UUID.randomUUID().toString(), "dora", READER);
    }

    protected HttpResponse<String> list(String token, String path, String method, String field) throws Exception {
        return sendModern(token, path, method, null, "{}");
    }

    protected static List<String> names(HttpResponse<String> response) {
        List<String> out = new ArrayList<>();
        JsonNode result = JSON.readTree(response.body()).path("result");
        for (String field : List.of("resources", "resourceTemplates", "prompts")) {
            result.path(field).forEach(e -> out.add(e.path("name").asString()));
        }
        return out;
    }

    /** A request of the legacy era on {@code /mcp}: the session of this token is made, then the method is sent with it. */
    protected JsonNode legacy(String token, String method, String params) throws Exception {
        HttpResponse<String> initialized = send(token, "/mcp", initializeBody(), Map.of());
        assertThat(initialized.statusCode()).as(initialized.body()).isEqualTo(200);
        String session = initialized.headers().firstValue("Mcp-Session-Id").orElseThrow();
        assertThat(send(token, "/mcp", "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}",
                Map.of("Mcp-Session-Id", session, "MCP-Protocol-Version", "2025-11-25")).statusCode()).isEqualTo(202);
        HttpResponse<String> response = send(token, "/mcp", "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"" + method + "\",\"params\":" + params + "}",
                Map.of("Mcp-Session-Id", session, "MCP-Protocol-Version", "2025-11-25"));
        assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
        return JSON.readTree(response.body());
    }

    protected HttpResponse<String> read(String token, String path, String uri) throws Exception {
        return sendModern(token, path, "resources/read", uri, "{\"uri\":" + JSON.writeValueAsString(uri) + "}");
    }

    protected HttpResponse<String> getPrompt(String token, String path, String name, String arguments) throws Exception {
        return sendModern(token, path, "prompts/get", name, "{\"name\":\"" + name + "\",\"arguments\":" + arguments + "}");
    }

    protected static JsonNode error(HttpResponse<String> response) {
        return JSON.readTree(response.body()).path("error");
    }

    protected List<TestMcpServer.RecordedRequest> serverCalls(String method) {
        return server.requests().stream().filter(r -> method.equals(r.rpcMethod())).toList();
    }

    protected static List<JsonNode> events(CapturedOutput output, String kind) {
        return output.getOut().lines().filter(l -> l.startsWith("{") && l.contains("\"event\":\"" + kind + "\"")).map(l -> JSON.readTree(l)).toList();
    }

    protected static JsonNode lastEvent(CapturedOutput output, String requestId, String kind) {
        return auditEvents(output, requestId).stream().filter(e -> kind.equals(e.path("event").asString())).reduce((a, b) -> b).orElseThrow();
    }

    protected static String rid(HttpResponse<String> response) {
        return response.headers().firstValue("X-Request-Id").orElseThrow();
    }
}
