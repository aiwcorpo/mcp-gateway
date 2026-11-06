package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.system.CapturedOutput;

import pl.aiwcorpo.mcp.gateway.jwt.UuidV7;
import pl.aiwcorpo.mcp.gateway.support.Contracts;
import pl.aiwcorpo.mcp.gateway.support.Fragments;
import pl.aiwcorpo.mcp.gateway.support.SseClient;
import pl.aiwcorpo.mcp.testserver.TestMcpServer;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * The registry of servers through the admin API (C5 /admin/v1/servers): the only list of servers, changed at runtime. A server made
 * from the template is added, registers its manifest, is approved and called without a restart of anything, and removed again.
 */
class ServerRegistryApiTest extends GatewayTestBase {

    private static final String NOTES = "/admin/v1/servers/mcp-notes";
    private static final List<String> NOTES_USER = List.of("mcp-notes-read", "mcp-notes-write");

    private final List<TestMcpServer> started = new java.util.ArrayList<>();

    @AfterEach
    void removeWhatTheTestAdded() throws Exception {
        for (String serverId : List.of("mcp-notes", "mcp-notesb", "mcp-xnotes")) {
            adminCall("DELETE", "/admin/v1/servers/" + serverId, null);
        }
        started.forEach(TestMcpServer::close);
        jdbc.sql("UPDATE policy_state SET scope_mapping = '[]'::jsonb WHERE id = 1").update();
        policies.reload();
    }

    @org.springframework.beans.factory.annotation.Autowired
    pl.aiwcorpo.mcp.gateway.policy.PolicyService policies;

    private static String serverBody(String serverId, String system, String url) {
        return "{\"serverId\":\"" + serverId + "\",\"system\":\"" + system + "\",\"internalUrl\":\"" + url + "\","
                + "\"credential\":{\"required\":true,\"acceptedTypes\":[\"user-secret\"],\"type\":\"user-secret\"}}";
    }

    private TestMcpServer startNotes() throws Exception {
        TestMcpServer server = env.startServer("mcp-notes");
        started.add(server);
        return server;
    }

    private String notesUrl(TestMcpServer server) {
        return "https://127.0.0.1:" + server.port() + "/mcp";
    }

    private JsonNode json(HttpResponse<String> response) {
        return JSON.readTree(response.body());
    }

    @Test
    void aServerIsCreatedReadChangedAndDeletedWithItsETag(CapturedOutput output) throws Exception {
        String requestId = UuidV7.next();
        Map<String, String> asRequest = Map.of("X-Request-Id", requestId);

        HttpResponse<String> created = adminCall("POST", "/admin/v1/servers", serverBody("mcp-notes", "notes", "https://127.0.0.1:9/mcp"), asRequest);
        assertThat(created.statusCode()).as(created.body()).isEqualTo(201);
        assertThat(created.headers().firstValue("Location")).contains(NOTES);
        JsonNode body = json(created);
        assertThat(body.path("tlsName").asString()).as("default <serverId>.internal").isEqualTo("mcp-notes.internal");
        assertThat(body.path("enabled").asBoolean()).isTrue();
        assertThat(body.path("adapter").asBoolean()).isFalse();
        assertThat(Contracts.gatewayAdminErrors("ServerConfig", body)).isEmpty();

        HttpResponse<String> read = adminCall("GET", NOTES, null);
        assertThat(read.statusCode()).isEqualTo(200);
        assertThat(etag(read)).isEqualTo(etag(created));
        HttpResponse<String> list = adminCall("GET", "/admin/v1/servers", null);
        assertThat(json(list).findValuesAsString("serverId")).contains("mcp-notes", "mcp-jira", "mcp-gitlab");

        String disable = "{\"enabled\":false}";
        assertThat(adminCall("PATCH", NOTES, disable).statusCode()).as("If-Match is required").isEqualTo(428);
        assertThat(adminCall("PATCH", NOTES, disable, Map.of("If-Match", "\"stale-version-0000\"")).statusCode()).isEqualTo(412);
        assertThat(adminCall("PATCH", NOTES, disable, Map.of("If-Match", "not an etag")).statusCode()).isEqualTo(400);
        HttpResponse<String> updated = adminCall("PATCH", NOTES, disable, Map.of("If-Match", etag(created), "X-Request-Id", requestId));
        assertThat(updated.statusCode()).as(updated.body()).isEqualTo(200);
        assertThat(json(updated).path("enabled").asBoolean()).isFalse();
        assertThat(etag(updated)).as("the document changed, so did its ETag").isNotEqualTo(etag(created));
        assertThat(adminCall("PATCH", NOTES, "{\"enabled\":true}", Map.of("If-Match", etag(created))).statusCode())
                .as("the old ETag is stale now").isEqualTo(412);
        assertThat(adminCall("PATCH", NOTES, "{\"serverId\":\"mcp-other\"}", Map.of("If-Match", etag(updated))).statusCode())
                .as("serverId never changes").isEqualTo(400);

        assertThat(adminCall("DELETE", NOTES, null, asRequest).statusCode()).isEqualTo(204);
        assertThat(adminCall("GET", NOTES, null).statusCode()).isEqualTo(404);
        assertThat(adminCall("DELETE", NOTES, null).statusCode()).isEqualTo(404);

        List<String> reasons = auditEvents(output, requestId).stream().filter(e -> "admin_change".equals(e.path("event").asString()))
                .map(e -> e.path("reason").asString()).toList();
        assertThat(reasons).containsExactly("server_created", "server_updated", "server_deleted");
        assertThat(auditEvents(output, requestId)).allSatisfy(event -> {
            assertThat(event.path("server").asString()).isEqualTo("mcp-notes");
            assertThat(event.path("sub").asString()).isEqualTo(ADMIN_SUB);
        });
    }

    @Test
    void reservedSystemsMismatchesAndInconsistentCredentialsAreRefused() throws Exception {
        for (String system : List.of("gateway", "offboarding", "portal", "broker", "prometheus", "platform", "admin", "registry", "adapter",
                "internal", "ci")) {
            HttpResponse<String> response = adminCall("POST", "/admin/v1/servers", serverBody("mcp-" + system, system, "https://127.0.0.1:9/mcp"));
            assertThat(response.statusCode()).as(system).isEqualTo(422);
            assertThat(json(response).path("error").asString()).isEqualTo("server_rejected");
            assertThat(json(response).path("reason").asString()).as(system).isEqualTo("system_reserved");
        }
        assertThat(json(adminCall("POST", "/admin/v1/servers", serverBody("mcp-notes", "other", "https://127.0.0.1:9/mcp"))).path("reason").asString())
                .isEqualTo("server_id_mismatch");
        String mixed = "{\"serverId\":\"mcp-notes\",\"system\":\"notes\",\"internalUrl\":\"https://127.0.0.1:9/mcp\",\"credential\":"
                + "{\"required\":true,\"acceptedTypes\":[\"service-account\",\"user-secret\"],\"type\":\"service-account\"}}";
        assertThat(json(adminCall("POST", "/admin/v1/servers", mixed)).path("reason").asString()).isEqualTo("credential_types_mixed");
        String notAccepted = "{\"serverId\":\"mcp-notes\",\"system\":\"notes\",\"internalUrl\":\"https://127.0.0.1:9/mcp\",\"credential\":"
                + "{\"required\":true,\"acceptedTypes\":[\"user-secret\"],\"type\":\"user-oauth\"}}";
        assertThat(json(adminCall("POST", "/admin/v1/servers", notAccepted)).path("reason").asString()).isEqualTo("credential_type_not_accepted");

        for (String bad : List.of("{}", "[]", "not json", serverBody("mcp-notes", "notes", "http://127.0.0.1:9/mcp"),
                serverBody("MCP-notes", "notes", "https://127.0.0.1:9/mcp"), serverBody("mcp-n", "n", "https://127.0.0.1:9/mcp"),
                "{\"serverId\":\"mcp-notes\",\"system\":\"notes\",\"internalUrl\":\"https://127.0.0.1:9/mcp\",\"credential\":"
                        + "{\"required\":true,\"acceptedTypes\":[],\"type\":\"user-secret\"},\"extra\":1}")) {
            assertThat(adminCall("POST", "/admin/v1/servers", bad).statusCode()).as(bad).isEqualTo(400);
        }
        assertThat(adminCall("GET", NOTES, null).statusCode()).as("nothing was stored").isEqualTo(404);
    }

    @Test
    void aServerThatExistsIsAConflictAndOnlyAnAdministratorChangesTheRegistry() throws Exception {
        assertThat(adminCall("POST", "/admin/v1/servers", serverBody("mcp-notes", "notes", "https://127.0.0.1:9/mcp")).statusCode()).isEqualTo(201);
        HttpResponse<String> again = adminCall("POST", "/admin/v1/servers", serverBody("mcp-notes", "notes", "https://127.0.0.1:9/mcp"));
        assertThat(again.statusCode()).isEqualTo(409);
        assertThat(json(again).path("error").asString()).isEqualTo("server_exists");

        String user = env.idp.token(BOB_SUB, "bob", List.of("mcp-jira-read"), "mcp-gateway-admin", "mcp-portal-bff");
        for (String[] call : new String[][] {{"GET", "/admin/v1/servers"}, {"POST", "/admin/v1/servers"}, {"GET", NOTES}, {"DELETE", NOTES}}) {
            HttpResponse<String> refused = admin(env.bffTls, call[0], call[1], user, call[0].equals("POST") ? "{}" : null);
            assertThat(refused.statusCode()).as(call[0] + " " + call[1]).isEqualTo(403);
        }
        assertThat(admin(env.otherComponentTls, "GET", "/admin/v1/servers", user, null).statusCode()).as("another certificate").isEqualTo(403);
        assertThat(admin(env.bffTls, "GET", "/admin/v1/servers", null, null).statusCode()).as("no token").isEqualTo(401);
    }

    @Test
    void aServerAddedAtRuntimeServesItsToolsWithoutARestartAndLeavesNothingWhenRemoved(CapturedOutput output) throws Exception {
        TestMcpServer notes = startNotes();
        String sub = UUID.randomUUID().toString();
        String token = env.idp.token(sub, "nora", NOTES_USER);
        assertThat(listedTools(token)).as("no such server yet").noneMatch(name -> name.startsWith("notes__"));
        SseClient stream = listen(token);
        assertThat(stream.nextMessage(Duration.ofSeconds(2)).path("method").asString()).isEqualTo("notifications/subscriptions/acknowledged");
        assertThat(stream.nextMessage(Duration.ofSeconds(1))).as("nothing changed yet").isNull();

        assertThat(adminCall("POST", "/admin/v1/servers", serverBody("mcp-notes", "notes", notesUrl(notes))).statusCode()).isEqualTo(201);
        ObjectNode manifest = notes.manifest();
        HttpResponse<String> registered = admin(env.pipelineTls("mcp-notes"), "PUT", "/admin/v1/registry/servers/mcp-notes", null,
                JSON.writeValueAsString(manifest));
        assertThat(registered.statusCode()).as(registered.body()).isEqualTo(200);
        assertThat(json(registered).path("policiesStatus").asString()).isEqualTo("pending_approval");
        assertThat(listedTools(token)).as("tools are invisible until the policies are approved").noneMatch(name -> name.startsWith("notes__"));
        assertThat(toolError(callNotes(token, "{\"issueKey\":\"ABC-1\"}")).path("error").asString()).isEqualTo("tool_disabled");

        HttpResponse<String> approved = asAdminWithBody("POST", "/admin/v1/registry/servers/mcp-notes/policies/approve",
                "{\"policiesHash\":\"" + manifest.path("policiesHash").asString() + "\"}");
        assertThat(approved.statusCode()).as(approved.body()).isEqualTo(200);

        assertThat(stream.nextMessage(Duration.ofSeconds(6))).as("the list of the client changed: no restart, no reconnect").isNotNull();
        assertThat(listedTools(token)).contains("notes__get_issue", "notes__search_issues").doesNotContain("notes__delete_issue");
        HttpResponse<String> result = callNotes(token, "{\"issueKey\":\"ABC-1\"}");
        assertThat(JSON.readTree(result.body()).path("result").path("isError").asBoolean(false)).as(result.body()).isFalse();
        assertThat(notes.requests().stream().filter(r -> "tools/call".equals(r.rpcMethod()))).hasSize(1);

        HttpResponse<String> catalog = admin("GET", "/admin/v1/registry/servers", ADMIN_SUB, "a.admin", List.of("mcp-platform-admin"), null);
        JsonNode listed = json(catalog);
        JsonNode entry = null;
        for (JsonNode server : listed) {
            if ("mcp-notes".equals(server.path("serverId").asString())) {
                entry = server;
            }
        }
        assertThat(entry).isNotNull();
        assertThat(entry.path("policiesStatus").asString()).isEqualTo("approved");
        assertThat(entry.path("policiesHash").asString()).isEqualTo(manifest.path("policiesHash").asString());

        String requestId = UuidV7.next();
        assertThat(adminCall("DELETE", NOTES, null, Map.of("X-Request-Id", requestId)).statusCode()).isEqualTo(204);

        assertThat(stream.nextMessage(Duration.ofSeconds(6))).as("listChanged to the clients that held the tools").isNotNull();
        assertThat(listedTools(token)).noneMatch(name -> name.startsWith("notes__"));
        assertThat(toolError(callNotes(token, "{\"issueKey\":\"ABC-1\"}")).path("error").asString()).isEqualTo("not_found_or_denied");
        assertThat(jdbc.sql("SELECT count(*) FROM registry_tools WHERE server_id = 'mcp-notes'").query(Long.class).single()).isZero();
        assertThat(jdbc.sql("SELECT count(*) FROM registry_policies WHERE server_id = 'mcp-notes'").query(Long.class).single()).isZero();
        assertThat(auditEvents(output, requestId).stream().map(e -> e.path("reason").asString())).contains("server_deleted");
        stream.close();
    }

    @Test
    void deletingAServerRemovesItsMappingEntriesAndFreesItsNamespace(CapturedOutput output) throws Exception {
        TestMcpServer notes = startNotes();
        assertThat(adminCall("POST", "/admin/v1/servers", serverBody("mcp-notes", "notes", notesUrl(notes))).statusCode()).isEqualTo(201);
        ObjectNode manifest = notes.manifest();
        assertThat(admin(env.pipelineTls("mcp-notes"), "PUT", "/admin/v1/registry/servers/mcp-notes", null, JSON.writeValueAsString(manifest))
                .statusCode()).isEqualTo(200);
        assertThat(asAdminWithBody("POST", "/admin/v1/registry/servers/mcp-notes/policies/approve",
                "{\"policiesHash\":\"" + manifest.path("policiesHash").asString() + "\"}").statusCode()).isEqualTo(200);
        String mapping = "{\"scopeMapping\":[{\"group\":\"mcp-notes-proj-ABC\",\"scopes\":[\"Notes::Project/ABC\"]},"
                + "{\"group\":\"mcp-team\",\"scopes\":[\"Jira::Project/ABC\",\"Notes::Project/XYZ\"]}]}";
        HttpResponse<String> put = adminCall("PUT", "/admin/v1/policy/scope-mapping", mapping, Map.of("If-Match", etag(adminCall("GET",
                "/admin/v1/policy/scope-mapping", null))));
        assertThat(put.statusCode()).as(put.body()).isEqualTo(200);

        // A second server cannot take the namespace of the first one, whatever its manifest says.
        assertThat(adminCall("POST", "/admin/v1/servers", serverBody("mcp-xnotes", "xnotes", "https://127.0.0.1:8443/mcp")).statusCode()).isEqualTo(201);
        ObjectNode thief = xnotesManifest();
        HttpResponse<String> refused = registerAs("mcp-xnotes", thief);
        assertThat(refused.statusCode()).as(refused.body()).isEqualTo(422);
        assertThat(json(refused).path("reason").asString()).as(refused.body()).isEqualTo("namespace_conflict");

        String requestId = UuidV7.next();
        assertThat(adminCall("DELETE", NOTES, null, Map.of("X-Request-Id", requestId)).statusCode()).isEqualTo(204);

        JsonNode after = json(adminCall("GET", "/admin/v1/policy/scope-mapping", null));
        assertThat(after.path("scopeMapping").toString()).contains("Jira::Project/ABC").doesNotContain("Notes::");
        assertThat(after.path("scopeMapping").size()).as("the group that had only Notes scopes is gone").isEqualTo(1);
        List<JsonNode> removed = auditEvents(output, requestId).stream()
                .filter(e -> "scope_mapping_entry_removed".equals(e.path("reason").asString())).toList();
        assertThat(removed.stream().map(e -> e.path("resource").path("type").asString() + "/" + e.path("resource").path("id").asString()))
                .containsExactlyInAnyOrder("Notes::Project/ABC", "Notes::Project/XYZ");
        assertThat(registerAs("mcp-xnotes", thief).statusCode()).as("the namespace is free again").isEqualTo(200);
    }

    // --- helpers -----------------------------------------------------------------------------------------------

    private ObjectNode xnotesManifest() {
        ObjectNode manifest = pl.aiwcorpo.mcp.gateway.support.Manifests.manifest("mcp-xnotes", "xnotes", "1.0.0", List.of("user-secret"),
                pl.aiwcorpo.mcp.gateway.support.Manifests.Tool.readOnly("get_note"));
        manifest.set("resourceTypes", Fragments.resourceTypes("notes"));
        manifest.set("policies", Fragments.policies("notes"));
        manifest.put("policiesHash", Fragments.hash((ObjectNode) manifest.get("policies"), (tools.jackson.databind.node.ArrayNode) manifest.get("resourceTypes")));
        return manifest;
    }

    private HttpResponse<String> registerAs(String serverId, ObjectNode manifest) throws Exception {
        return admin(env.pipelineTls(serverId), "PUT", "/admin/v1/registry/servers/" + serverId, null, JSON.writeValueAsString(manifest));
    }

    private HttpResponse<String> asAdminWithBody(String method, String path, String body) throws Exception {
        return adminCall(method, path, body);
    }

    private List<String> listedTools(String token) throws Exception {
        HttpResponse<String> response = sendModern(token, "/mcp", "tools/list", null, "{}");
        assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
        return JSON.readTree(response.body()).path("result").path("tools").findValuesAsString("name");
    }

    private HttpResponse<String> callNotes(String token, String arguments) throws Exception {
        return sendModern(token, "/mcp", "tools/call", "notes__get_issue",
                "{\"name\":\"notes__get_issue\",\"arguments\":" + arguments + "}");
    }

    private SseClient listen(String token) throws Exception {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"subscriptions/listen\",\"params\":{\"_meta\":{"
                + "\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{}},"
                + "\"notifications\":{\"toolsListChanged\":true}}}";
        SseClient client = SseClient.post(http, "http://localhost:" + port + "/mcp", body, Map.of("Authorization", "Bearer " + token,
                "MCP-Protocol-Version", "2026-07-28", "Mcp-Method", "subscriptions/listen"));
        await().atMost(Duration.ofSeconds(3)).until(() -> client.status() == 200);
        return client;
    }
}
