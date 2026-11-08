package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import pl.aiwcorpo.mcp.gateway.registry.RegistryService;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.system.CapturedOutput;

import pl.aiwcorpo.mcp.gateway.support.Contracts;
import pl.aiwcorpo.mcp.manifest.DefinitionHash;
import pl.aiwcorpo.mcp.testserver.TestMcpServer;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * A server behind an adapter and the classification by an administrator over HTTP (C5, CC-193, CC-207, CC-249): the gateway pulls the
 * manifest of the adapter like any other, and the adapter mode is derived from the {@code source} of the first manifest. mcp-opensearch is
 * a row of the registry whose address is the adapter test server, which stands in for the foreign one.
 */
class AdapterServerTest extends GatewayTestBase {

    private static final String SERVER = "/admin/v1/servers/mcp-opensearch";
    private static final List<String> ADMIN = List.of("mcp-platform-admin");
    private static final String ADMIN_SUB = "3b0d6f2e-91c4-4d7a-8a52-6c1e4f7a9d10";

    @Autowired
    RegistryService registry;

    @BeforeEach
    @AfterEach
    void startFromNothing() throws Exception {
        // A manifest has at least one tool, so the state is emptied where the operator would: in the tables.
        env.forgetRegistryOf("mcp-opensearch");
        jdbc.sql("DELETE FROM registry_risk_floor WHERE server_id = ?").param("mcp-opensearch").update();
        jdbc.sql("UPDATE servers SET connection = NULL, pending_connection = NULL, status = 'pending_approval', last_error = NULL "
                + "WHERE server_id = 'mcp-opensearch'").update();
        jdbc.sql("UPDATE registry_changes SET version = version + 1 WHERE id = 1").update();
        registry.reloadChanged();
    }

    /** The gateway pulls the manifest of the adapter and the administrator approves the connection as the gateway proposed it. */
    private void connect() throws Exception {
        HttpResponse<String> refreshed = adminCall("POST", SERVER + "/refresh", null);
        assertThat(refreshed.statusCode()).as(refreshed.body()).isEqualTo(200);
        JsonNode pending = JSON.readTree(refreshed.body()).path("pendingConnection");
        HttpResponse<String> approved = adminCall("POST", SERVER + "/connection/approve", "{\"tlsMode\":\"" + pending.path("tlsMode").asString()
                + "\",\"fingerprint\":\"" + pending.path("fingerprint").asString() + "\"}");
        assertThat(approved.statusCode()).as(approved.body()).isEqualTo(200);
    }

    private HttpResponse<String> asAdmin(String method, String path, String body) throws Exception {
        return admin(method, path, ADMIN_SUB, "a.admin", ADMIN, body);
    }

    private JsonNode registryServer() throws Exception {
        for (JsonNode server : JSON.readTree(asAdmin("GET", "/admin/v1/registry/servers", null).body())) {
            if ("mcp-opensearch".equals(server.path("serverId").asString())) {
                return server;
            }
        }
        throw new AssertionError("mcp-opensearch is not in the registry");
    }

    private static JsonNode toolOf(JsonNode server, String name) {
        for (JsonNode tool : server.path("tools")) {
            if (name.equals(tool.path("name").asString())) {
                return tool;
            }
        }
        return null;
    }

    private JsonNode registryEntry(String tool) throws Exception {
        for (JsonNode server : JSON.readTree(asAdmin("GET", "/admin/v1/registry/servers", null).body())) {
            if ("mcp-opensearch".equals(server.path("serverId").asString())) {
                return toolOf(server, tool);
            }
        }
        return null;
    }

    private String readerToken() {
        return env.idp.token(UUID.randomUUID().toString(), "reader", List.of("mcp-opensearch-read"));
    }

    private List<String> listed() throws Exception {
        List<String> names = new ArrayList<>();
        JSON.readTree(sendModern(readerToken(), "/s/mcp-opensearch/mcp", "tools/list", null, "{}").body()).path("result").path("tools")
                .forEach(t -> names.add(t.path("name").asString()));
        return names;
    }

    private static List<JsonNode> events(CapturedOutput output, String event, String reason) {
        List<JsonNode> found = new ArrayList<>();
        for (String line : output.getOut().split("\n")) {
            if (line.startsWith("{") && line.contains("\"event\":\"" + event + "\"") && line.contains("\"reason\":\"" + reason + "\"")) {
                found.add(JSON.readTree(line));
            }
        }
        return found;
    }

    @Test
    void theAdapterModeIsDerivedFromTheFirstManifestAndNeverChanges(CapturedOutput output) throws Exception {
        TestMcpServer adapter = env.startAdapterServer("mcp-adapted");
        TestMcpServer plain = env.startServer("mcp-adapted");
        try {
            HttpResponse<String> added = adminCall("POST", "/admin/v1/servers", "{\"internalUrl\":\"https://127.0.0.1:" + adapter.port() + "/mcp\"}");
            assertThat(added.statusCode()).as(added.body()).isEqualTo(201);
            JsonNode server = JSON.readTree(added.body());
            assertThat(server.path("adapter").asBoolean()).as("the first manifest says source adapter").isTrue();
            assertThat(Contracts.gatewayAdminErrors("ServerConfig", server)).isEmpty();
            JsonNode view = null;
            for (JsonNode candidate : JSON.readTree(asAdmin("GET", "/admin/v1/registry/servers", null).body())) {
                if ("mcp-adapted".equals(candidate.path("serverId").asString())) {
                    view = candidate;
                }
            }
            assertThat(view).isNotNull();
            assertThat(Contracts.gatewayAdminErrors("RegistryServer", view)).isEmpty();
            for (JsonNode tool : view.path("tools")) {
                assertThat(tool.path("status").asString()).isEqualTo("pending_approval");
                assertThat(tool.path("source").asString()).isEqualTo("adapter");
                assertThat(tool.path("change").asString()).isEqualTo("new");
                assertThat(tool.has("risk") || tool.has("action") || tool.has("classifiedBy")).as("nothing is classified by a pull").isFalse();
            }
            assertThat(events(output, "admin_change", "definition_submitted").stream().filter(e -> "mcp-adapted".equals(e.path("server").asString())))
                    .hasSize(view.path("tools").size());

            // The same address later serves a manifest of a starter server: refused, the registry keeps what it has.
            adapter.serveManifest(plain.manifest());
            HttpResponse<String> mismatch = adminCall("POST", "/admin/v1/servers/mcp-adapted/refresh", null);
            assertThat(mismatch.statusCode()).isEqualTo(200);
            assertThat(JSON.readTree(mismatch.body()).path("status").asString()).isEqualTo("manifest_invalid");
            assertThat(JSON.readTree(mismatch.body()).path("lastError").asString()).isEqualTo("manifest_invalid");
            assertThat(JSON.readTree(mismatch.body()).path("adapter").asBoolean()).isTrue();
            assertThat(events(output, "admin_change", "adapter_source_mismatch")).isNotEmpty();
        } finally {
            adminCall("DELETE", "/admin/v1/servers/mcp-adapted", null);
            adapter.close();
            plain.close();
        }
    }

    /** The {@code add-derives-*} vectors of adapter-registry/: the mode of a server comes from the first manifest it serves. */
    @org.junit.jupiter.api.TestFactory
    List<org.junit.jupiter.api.DynamicTest> theAddVectors() {
        List<org.junit.jupiter.api.DynamicTest> tests = new ArrayList<>();
        for (pl.aiwcorpo.mcp.gateway.support.Vectors.Vector vector : pl.aiwcorpo.mcp.gateway.support.Vectors.of("adapter-registry")) {
            if (!vector.name().startsWith("add-derives-")) {
                continue;
            }
            tests.add(org.junit.jupiter.api.DynamicTest.dynamicTest(vector.name(), () -> {
                JsonNode input = vector.document().path("input");
                JsonNode expected = vector.document().path("expected");
                boolean adapter = "adapter".equals(input.path("manifestSource").asString(null));
                List<pl.aiwcorpo.mcp.gateway.support.Manifests.Tool> tools = new ArrayList<>();
                input.path("tools").forEach(t -> tools.add(new pl.aiwcorpo.mcp.gateway.support.Manifests.Tool(t.path("name").asString(),
                        t.path("risk").asString(), "Does " + t.path("name").asString() + ".")));
                pl.aiwcorpo.mcp.gateway.support.Manifests.Tool[] all = tools.toArray(new pl.aiwcorpo.mcp.gateway.support.Manifests.Tool[0]);
                TestMcpServer server = adapter ? env.startAdapterServer("mcp-vecadd") : env.startServer("mcp-vecadd");
                try {
                    server.serveManifest(adapter ? pl.aiwcorpo.mcp.gateway.support.Manifests.adapter("mcp-vecadd", "vecadd", "1.0.0", all)
                            : pl.aiwcorpo.mcp.gateway.support.Manifests.manifest("mcp-vecadd", "vecadd", "1.0.0",
                                    List.of(pl.aiwcorpo.mcp.gateway.support.Manifests.USER_SECRET), all));

                    HttpResponse<String> added = adminCall("POST", "/admin/v1/servers", "{\"internalUrl\":\"https://127.0.0.1:" + server.port() + "/mcp\"}");

                    assertThat(added.statusCode()).as(added.body()).isEqualTo(201);
                    assertThat(JSON.readTree(added.body()).path("adapter").asBoolean()).isEqualTo(expected.path("adapter").asBoolean());
                    List<String> pending = new ArrayList<>();
                    for (JsonNode entry : JSON.readTree(asAdmin("GET", "/admin/v1/registry/servers", null).body())) {
                        if ("mcp-vecadd".equals(entry.path("serverId").asString())) {
                            entry.path("tools").forEach(tool -> {
                                if ("pending_approval".equals(tool.path("status").asString())) {
                                    pending.add(tool.path("name").asString());
                                    assertThat(tool.path("source").asString()).isEqualTo(expected.path("pendingSource").asString());
                                }
                            });
                        }
                    }
                    List<String> wanted = new ArrayList<>();
                    expected.path("pending").forEach(name -> wanted.add(name.asString()));
                    assertThat(pending).as("every tool is pending, a READ_ONLY one included").containsExactlyInAnyOrderElementsOf(wanted);
                } finally {
                    adminCall("DELETE", "/admin/v1/servers/mcp-vecadd", null);
                    server.close();
                }
            }));
        }
        assertThat(tests).hasSize(2);
        return tests;
    }

    @Test
    void aStarterServerThatLaterServesAnAdapterManifestIsRefused() throws Exception {
        TestMcpServer starter = env.startServer("mcp-starter");
        try {
            assertThat(adminCall("POST", "/admin/v1/servers", "{\"internalUrl\":\"https://127.0.0.1:" + starter.port() + "/mcp\"}").statusCode())
                    .isEqualTo(201);
            ObjectNode adapterManifest = env.opensearch.adapterManifest();
            adapterManifest.put("serverId", "mcp-starter").put("system", "starter");
            starter.serveManifest(adapterManifest);

            JsonNode server = JSON.readTree(adminCall("POST", "/admin/v1/servers/mcp-starter/refresh", null).body());

            assertThat(server.path("status").asString()).isEqualTo("manifest_invalid");
            assertThat(server.path("adapter").asBoolean()).isFalse();
        } finally {
            adminCall("DELETE", "/admin/v1/servers/mcp-starter", null);
            starter.close();
        }
    }

    @Test
    void aPulledToolIsPendingAndAClassifiedToolIsServed(CapturedOutput output) throws Exception {
        ObjectNode manifest = env.opensearch.adapterManifest();
        connect();
        JsonNode body = registryServer();
        assertThat(Contracts.gatewayAdminErrors("RegistryServer", body)).isEmpty();
        for (JsonNode tool : body.path("tools")) {
            assertThat(tool.path("status").asString()).isEqualTo("pending_approval");
            assertThat(tool.path("source").asString()).isEqualTo("adapter");
            assertThat(tool.path("change").asString()).isEqualTo("new");
            assertThat(tool.has("risk") || tool.has("action") || tool.has("classifiedBy")).isFalse();
        }
        assertThat(events(output, "admin_change", "definition_submitted").stream().filter(e -> "mcp-opensearch".equals(e.path("server").asString())))
                .hasSize(body.path("tools").size());
        assertThat(listed()).isEmpty();
        JsonNode unclassified = toolError(sendModern(readerToken(), "/s/mcp-opensearch/mcp", "tools/call", "opensearch__get_issue",
                "{\"name\":\"opensearch__get_issue\",\"arguments\":{\"issueKey\":\"ABC-1\"}}"));
        assertThat(unclassified.path("error").asString()).as("judged as the most dangerous kind, so it tells a reader nothing").isEqualTo("not_found_or_denied");
        JsonNode listing = registryEntry("get_issue");
        assertThat(Contracts.gatewayAdminErrors("RegistryTool", listing)).isEmpty();
        String hash = listing.path("definitionHash").asString();

        String approve = "/admin/v1/registry/servers/mcp-opensearch/tools/get_issue/approve";
        // A floor above READ_ONLY (a voided classification, or one from before the tool left the manifest): the views say that approving lowers the risk.
        jdbc.sql("INSERT INTO registry_risk_floor (server_id, tool, risk) VALUES ('mcp-opensearch', 'get_issue', 1) ON CONFLICT (server_id, tool) DO UPDATE SET risk = 1").update();
        assertThat(registryEntry("get_issue").path("riskLowered").asBoolean(false)).as("the list of the registry").isTrue();
        JsonNode lowering = JSON.readTree(asAdmin("GET", "/admin/v1/registry/servers/mcp-opensearch/tools/get_issue/pending", null).body());
        assertThat(lowering.path("riskLowered").asBoolean(false)).as("the diff").isTrue();
        assertThat(Contracts.gatewayAdminErrors("PendingTool", lowering)).isEmpty();
        HttpResponse<String> withoutFlag = asAdmin("POST", approve, "{\"definitionHash\":\"" + hash + "\",\"risk\":\"READ_ONLY\",\"action\":\"read\"}");
        assertThat(withoutFlag.statusCode()).isEqualTo(422);
        assertThat(JSON.readTree(withoutFlag.body()).path("reason").asString()).isEqualTo("risk_lowered");
        jdbc.sql("DELETE FROM registry_risk_floor WHERE server_id = 'mcp-opensearch' AND tool = 'get_issue'").update();
        assertThat(registryEntry("get_issue").path("riskLowered").asBoolean(false)).as("no floor, no lowering").isFalse();

        HttpResponse<String> required = asAdmin("POST", approve, "{\"definitionHash\":\"" + hash + "\"}");
        assertThat(required.statusCode()).isEqualTo(422);
        assertThat(JSON.readTree(required.body()).path("reason").asString()).isEqualTo("classification_required");
        HttpResponse<String> inconsistent = asAdmin("POST", approve, "{\"definitionHash\":\"" + hash + "\",\"risk\":\"READ_ONLY\",\"action\":\"delete\"}");
        assertThat(inconsistent.statusCode()).isEqualTo(422);
        assertThat(JSON.readTree(inconsistent.body()).path("reason").asString()).isEqualTo("classification_inconsistent");
        HttpResponse<String> writes = asAdmin("POST", approve, "{\"definitionHash\":\"" + hash + "\",\"risk\":\"UPDATE\",\"action\":\"update\"}");
        assertThat(writes.statusCode()).as("a tool of an adapter is read only (CC-227)").isEqualTo(422);
        assertThat(JSON.readTree(writes.body()).path("reason").asString()).isEqualTo("classification_not_allowed");
        assertThat(asAdmin("POST", approve, "{\"definitionHash\":\"" + hash + "\",\"risk\":\"BOGUS\",\"action\":\"read\"}").statusCode()).isEqualTo(400);

        HttpResponse<String> approved = asAdmin("POST", approve, "{\"definitionHash\":\"" + hash + "\",\"risk\":\"READ_ONLY\",\"action\":\"read\"}");
        assertThat(approved.statusCode()).as(approved.body()).isEqualTo(204);
        await().atMost(Duration.ofSeconds(8)).untilAsserted(() -> assertThat(listed()).containsExactly("opensearch__get_issue"));
        assertThat(events(output, "admin_change", "definition_approved").stream().filter(e -> "mcp-opensearch".equals(e.path("server").asString())
                && "read".equals(e.path("action").asString()))).singleElement().satisfies(e -> {
            assertThat(e.path("risk").asString()).isEqualTo("READ_ONLY");
            assertThat(e.path("sub").asString()).isEqualTo(ADMIN_SUB);
            assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", e)).isEmpty();
        });
        JsonNode classified = registryEntry("get_issue");
        assertThat(Contracts.gatewayAdminErrors("RegistryTool", classified)).isEmpty();
        assertThat(classified.path("risk").asString()).isEqualTo("READ_ONLY");
        assertThat(classified.path("classifiedBy").asString()).isEqualTo(ADMIN_SUB);

        JsonNode served = toolError(sendModern(readerToken(), "/s/mcp-opensearch/mcp", "tools/call", "opensearch__get_issue",
                "{\"name\":\"opensearch__get_issue\",\"arguments\":{\"issueKey\":\"ABC-1\"}}"));
        assertThat(served.has("error")).as(served.toString()).isFalse();
        assertThat(env.opensearch.requests()).anyMatch(r -> "tools/call".equals(r.rpcMethod()) && "get_issue".equals(r.toolName()));
        JsonNode token = claims(env.opensearch.requests().stream().filter(r -> "tools/call".equals(r.rpcMethod()) && "get_issue".equals(r.toolName()))
                .reduce((a, b) -> b).orElseThrow().header("authorization"));
        assertThat(token.path("mcp_risk").asString()).as("the classification of the administrator, for the sidecar").isEqualTo("READ_ONLY");
        assertThat(token.path("mcp_action").asString()).isEqualTo("read");

        assertThat(adminCall("POST", SERVER + "/refresh", null).statusCode()).isEqualTo(200);
        JsonNode stays = toolOf(registryServer(), "get_issue");
        assertThat(stays.path("status").asString()).as("the same hash stays approved, with its classification").isEqualTo("approved");
        assertThat(stays.path("risk").asString()).isEqualTo("READ_ONLY");
        assertThat(listed()).contains("opensearch__get_issue");

        ObjectNode changed = manifest.deepCopy();
        ObjectNode entry = (ObjectNode) toolOf(changed, "get_issue");
        ((ObjectNode) entry.get("definition")).put("description", "Returns one issue, and this text is new.");
        entry.put("definitionHash", DefinitionHash.ofManifestTool(JSON.writeValueAsString(changed), "get_issue"));
        env.opensearch.serveManifest(changed);
        try {
            assertThat(adminCall("POST", SERVER + "/refresh", null).statusCode()).isEqualTo(200);
        } finally {
            env.opensearch.serveManifest(null);
        }
        assertThat(toolOf(registryServer(), "get_issue").path("status").asString()).isEqualTo("pending_approval");
        JsonNode diff = JSON.readTree(asAdmin("GET", "/admin/v1/registry/servers/mcp-opensearch/tools/get_issue/pending", null).body());
        assertThat(Contracts.gatewayAdminErrors("PendingTool", diff)).isEmpty();
        assertThat(diff.path("source").asString()).isEqualTo("adapter");
        assertThat(diff.path("approvedEntry").path("risk").asString()).as("the earlier classification, as a suggestion").isEqualTo("READ_ONLY");
        assertThat(diff.path("pendingEntry").has("risk")).isFalse();
    }
}
