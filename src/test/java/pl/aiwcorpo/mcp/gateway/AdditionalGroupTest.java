package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.http.HttpResponse;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import pl.aiwcorpo.mcp.testserver.TestMcpServer;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * A tool whose manifest entry names an additionalGroup (CC-242) is called only by members of that group as well as of the group of its risk.
 * The group is part of the definition hash, so a change of it goes through the approval of the tool like any other change, and a pulled
 * manifest approves nothing (CC-249).
 */
class AdditionalGroupTest extends GatewayTestBase {

    private static final String REGISTRY = "/admin/v1/registry/servers/mcp-ops";

    private TestMcpServer ops;
    private ObjectNode manifest;

    @BeforeEach
    void addTheServer() throws Exception {
        ops = env.startServer("mcp-ops");
        ops.additionalGroup("get_issue", "ops");
        addAndApprove();
    }

    /** Adds the server by its address and approves the connection, the policies and the two read tools, as an administrator would. */
    private void addAndApprove() throws Exception {
        String body = "{\"internalUrl\":\"https://127.0.0.1:" + ops.port() + "/mcp\"}";
        HttpResponse<String> added = adminCall("POST", "/admin/v1/servers", body);
        assertThat(added.statusCode()).as(added.body()).isEqualTo(201);
        JsonNode pending = JSON.readTree(added.body()).path("pendingConnection");
        assertThat(adminCall("POST", "/admin/v1/servers/mcp-ops/connection/approve", "{\"tlsMode\":\"" + pending.path("tlsMode").asString()
                + "\",\"fingerprint\":\"" + pending.path("fingerprint").asString() + "\"}").statusCode()).isEqualTo(200);
        manifest = ops.manifest();
        assertThat(adminCall("POST", REGISTRY + "/policies/approve", "{\"policiesHash\":\"" + manifest.path("policiesHash").asString() + "\"}")
                .statusCode()).isEqualTo(200);
        for (String tool : List.of("get_issue", "search_issues")) {
            assertThat(adminCall("POST", REGISTRY + "/tools/" + tool + "/approve", "{\"definitionHash\":\"" + hashOf(manifest, tool) + "\"}")
                    .statusCode()).isEqualTo(204);
        }
    }

    private static String hashOf(ObjectNode manifest, String tool) {
        return pl.aiwcorpo.mcp.gateway.support.Manifests.tool(manifest, tool).path("definitionHash").asString();
    }

    @AfterEach
    void removeTheServer() throws Exception {
        adminCall("DELETE", "/admin/v1/servers/mcp-ops", null);
        ops.close();
    }

    /** The server serves this manifest from now on and the gateway pulls it. */
    private HttpResponse<String> register(ObjectNode body) throws Exception {
        ops.serveManifest(body);
        return adminCall("POST", "/admin/v1/servers/mcp-ops/refresh", null);
    }

    private String token(String... groups) {
        return env.idp.token(UUID.randomUUID().toString(), "olga", List.of(groups));
    }

    private List<String> listed(String token) throws Exception {
        return JSON.readTree(sendModern(token, "/mcp?systems=ops", "tools/list", null, "{}").body()).path("result").path("tools")
                .findValuesAsString("name");
    }

    private HttpResponse<String> call(String token) throws Exception {
        return sendModern(token, "/mcp", "tools/call", "ops__get_issue", "{\"name\":\"ops__get_issue\",\"arguments\":{\"issueKey\":\"ABC-1\"}}");
    }

    private static JsonNode tool(JsonNode registry, String name) {
        for (JsonNode server : registry) {
            if ("mcp-ops".equals(server.path("serverId").asString())) {
                for (JsonNode tool : server.path("tools")) {
                    if (name.equals(tool.path("name").asString())) {
                        return tool;
                    }
                }
            }
        }
        throw new AssertionError(name);
    }

    @Test
    void theCallNeedsTheGroupOfTheRiskAndTheAdditionalOne() throws Exception {
        String both = token("mcp-ops-read", "mcp-ops-ops");
        String riskOnly = token("mcp-ops-read");
        String additionalOnly = token("mcp-ops-ops");

        assertThat(toolError(call(both)).path("error").asString()).as("both groups").isEmpty();
        assertThat(toolError(call(riskOnly)).path("error").asString()).as("only the group of the risk").isEqualTo("not_found_or_denied");
        assertThat(toolError(call(additionalOnly)).path("error").asString()).as("the additional group narrows, it never replaces").isEqualTo("not_found_or_denied");
        assertThat(listed(both)).contains("ops__get_issue", "ops__search_issues");
        assertThat(listed(riskOnly)).as("a tool the user may not call is not listed").contains("ops__search_issues").doesNotContain("ops__get_issue");
    }

    @Test
    void theCatalogShowsTheAccessAndBothGroups() throws Exception {
        JsonNode catalog = JSON.readTree(admin("GET", "/admin/v1/catalog", UUID.randomUUID().toString(), "olga", List.of("mcp-ops-read"), null).body());
        JsonNode riskOnly = null;
        for (JsonNode server : catalog.path("servers")) {
            if ("mcp-ops".equals(server.path("serverId").asString())) {
                for (JsonNode tool : server.path("tools")) {
                    if ("ops__get_issue".equals(tool.path("name").asString())) {
                        riskOnly = tool;
                    }
                }
            }
        }
        assertThat(riskOnly.path("access").asString()).isEqualTo("denied");
        assertThat(riskOnly.path("requiredEntitlements").toString()).isEqualTo("[\"mcp-ops-read\",\"mcp-ops-ops\"]");
    }

    @Test
    void theRegistryShowsTheGroupAndAChangeOfItWaitsForApprovalLikeAnyDefinitionChange() throws Exception {
        JsonNode registry = JSON.readTree(adminCall("GET", "/admin/v1/registry/servers", null).body());
        assertThat(tool(registry, "get_issue").path("additionalGroup").asString()).isEqualTo("mcp-ops-ops");

        // delete_issue is DESTRUCTIVE: its entry waits for an administrator whatever changes in it.
        ops.additionalGroup("delete_issue", "ops");
        ObjectNode withGroup = ops.manifest();
        assertThat(register(withGroup).statusCode()).isEqualTo(200);
        String first = tool(JSON.readTree(adminCall("GET", "/admin/v1/registry/servers", null).body()), "delete_issue").path("definitionHash").asString();
        assertThat(adminCall("POST", REGISTRY + "/tools/delete_issue/approve", "{\"definitionHash\":\"" + first + "\"}").statusCode()).isEqualTo(204);
        assertThat(tool(JSON.readTree(adminCall("GET", "/admin/v1/registry/servers", null).body()), "delete_issue").path("status").asString())
                .isEqualTo("approved");

        ops.additionalGroup("delete_issue", "audit");
        ObjectNode changed = ops.manifest();
        assertThat(register(changed).statusCode()).isEqualTo(200);

        JsonNode pending = tool(JSON.readTree(adminCall("GET", "/admin/v1/registry/servers", null).body()), "delete_issue");
        assertThat(pending.path("status").asString()).isEqualTo("pending_approval");
        assertThat(pending.path("additionalGroup").asString()).isEqualTo("mcp-ops-audit");
        assertThat(pending.path("definitionHash").asString()).isNotEqualTo(first);
        JsonNode diff = JSON.readTree(adminCall("GET", REGISTRY + "/tools/delete_issue/pending", null).body());
        assertThat(diff.path("approvedEntry").path("additionalGroup").asString()).isEqualTo("mcp-ops-ops");
        assertThat(diff.path("pendingEntry").path("additionalGroup").asString()).isEqualTo("mcp-ops-audit");
        assertThat(String.join(",", listed(token("mcp-ops-destructive", "mcp-ops-ops", "mcp-ops-audit")))).as("what was approved stays in force")
                .contains("ops__delete_issue");
    }

    @Test
    void removingOrChangingTheGroupOfAReadOnlyToolWaitsForAnAdministratorAndTheOldEntryStaysInForce() throws Exception {
        ops.additionalGroup("get_issue", null);
        assertThat(register(ops.manifest()).statusCode()).isEqualTo(200);

        JsonNode entry = tool(JSON.readTree(adminCall("GET", "/admin/v1/registry/servers", null).body()), "get_issue");
        assertThat(entry.path("status").asString()).as("a READ_ONLY tool, but the review of a commit does not widen who may call it")
                .isEqualTo("pending_approval");
        JsonNode diff = JSON.readTree(adminCall("GET", REGISTRY + "/tools/get_issue/pending", null).body());
        assertThat(diff.path("approvedEntry").path("additionalGroup").asString()).isEqualTo("mcp-ops-ops");
        assertThat(diff.path("pendingEntry").has("additionalGroup")).isFalse();
        assertThat(toolError(call(token("mcp-ops-read"))).path("error").asString()).as("the approved entry, with its group, is still enforced")
                .isEqualTo("not_found_or_denied");
        assertThat(toolError(call(token("mcp-ops-read", "mcp-ops-ops"))).path("error").asString()).isEmpty();

        ops.additionalGroup("get_issue", "audit");
        assertThat(register(ops.manifest()).statusCode()).isEqualTo(200);
        assertThat(tool(JSON.readTree(adminCall("GET", "/admin/v1/registry/servers", null).body()), "get_issue").path("status").asString())
                .as("changing it is no better than removing it").isEqualTo("pending_approval");
        assertThat(toolError(call(token("mcp-ops-read", "mcp-ops-audit"))).path("error").asString()).isEqualTo("not_found_or_denied");
    }

    @Test
    void addingAGroupToAReadOnlyToolWaitsLikeAnyOtherChangeAndTheOldEntryStaysInForce() throws Exception {
        ops.additionalGroup("search_issues", "ops");
        assertThat(register(ops.manifest()).statusCode()).isEqualTo(200);

        JsonNode entry = tool(JSON.readTree(adminCall("GET", "/admin/v1/registry/servers", null).body()), "search_issues");
        assertThat(entry.path("status").asString()).as("a pulled manifest approves nothing, even a group that only narrows access").isEqualTo("pending_approval");
        assertThat(entry.path("additionalGroup").asString()).isEqualTo("mcp-ops-ops");
        assertThat(listed(token("mcp-ops-read"))).as("the approved entry, without the group, is in force").contains("ops__search_issues");

        assertThat(adminCall("POST", REGISTRY + "/tools/search_issues/approve", "{\"definitionHash\":\"" + entry.path("definitionHash").asString() + "\"}")
                .statusCode()).isEqualTo(204);
        assertThat(listed(token("mcp-ops-read"))).doesNotContain("ops__search_issues");
        assertThat(listed(token("mcp-ops-read", "mcp-ops-ops"))).contains("ops__search_issues");
    }

    private ObjectNode without(ObjectNode manifest, String tool) {
        tools.jackson.databind.node.ArrayNode tools = (tools.jackson.databind.node.ArrayNode) manifest.get("tools");
        for (int i = tools.size() - 1; i >= 0; i--) {
            if (tool.equals(tools.get(i).path("name").asString())) {
                tools.remove(i);
            }
        }
        return manifest;
    }

    private String status(String tool) throws Exception {
        return tool(JSON.readTree(adminCall("GET", "/admin/v1/registry/servers", null).body()), tool).path("status").asString();
    }

    @Test
    void aToolRemovedAndPulledAgainIsNewAndWaitsWhateverItsGroup() throws Exception {
        assertThat(register(without(ops.manifest(), "get_issue")).statusCode()).isEqualTo(200);
        ops.additionalGroup("get_issue", null);
        assertThat(register(ops.manifest()).statusCode()).isEqualTo(200);
        assertThat(status("get_issue")).as("a new tool, with no group").isEqualTo("pending_approval");
        assertThat(listed(token("mcp-ops-read"))).as("never served while it waits").doesNotContain("ops__get_issue");

        assertThat(register(without(ops.manifest(), "get_issue")).statusCode()).isEqualTo(200);
        ops.additionalGroup("get_issue", "ops");
        assertThat(register(ops.manifest()).statusCode()).isEqualTo(200);
        assertThat(status("get_issue")).as("with the same group it is new as well: a pulled manifest approves nothing").isEqualTo("pending_approval");
        String hash = tool(JSON.readTree(adminCall("GET", "/admin/v1/registry/servers", null).body()), "get_issue").path("definitionHash").asString();
        assertThat(adminCall("POST", REGISTRY + "/tools/get_issue/approve", "{\"definitionHash\":\"" + hash + "\"}").statusCode()).isEqualTo(204);
        assertThat(listed(token("mcp-ops-read"))).doesNotContain("ops__get_issue");
        assertThat(listed(token("mcp-ops-read", "mcp-ops-ops"))).contains("ops__get_issue");
    }

    @Test
    void theGroupFloorSurvivesTheDeletionOfTheServer() throws Exception {
        String body = "{\"internalUrl\":\"https://127.0.0.1:" + ops.port() + "/mcp\"}";
        assertThat(adminCall("DELETE", "/admin/v1/servers/mcp-ops", null).statusCode()).isEqualTo(204);
        assertThat(jdbc.sql("SELECT additional_group FROM registry_group_floor WHERE server_id = 'mcp-ops' AND tool = 'get_issue'")
                .query(String.class).single()).isEqualTo("mcp-ops-ops");
        ops.additionalGroup("get_issue", null);
        ops.serveManifest(null);
        ops.restart();
        assertThat(adminCall("POST", "/admin/v1/servers", body).statusCode()).isEqualTo(201);

        assertThat(status("get_issue")).isEqualTo("pending_approval");
        String hash = tool(JSON.readTree(adminCall("GET", "/admin/v1/registry/servers", null).body()), "get_issue").path("definitionHash").asString();
        assertThat(adminCall("POST", REGISTRY + "/tools/get_issue/approve", "{\"definitionHash\":\"" + hash + "\"}").statusCode()).isEqualTo(204);
        assertThat(jdbc.sql("SELECT count(*) FROM registry_group_floor WHERE server_id = 'mcp-ops' AND tool = 'get_issue'").query(Long.class).single())
                .as("an approval by an administrator updates the floor: here there is none now").isZero();
    }
}
