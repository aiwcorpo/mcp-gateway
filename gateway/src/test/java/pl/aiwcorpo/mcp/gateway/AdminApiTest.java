package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import pl.aiwcorpo.mcp.gateway.support.Contracts;
import pl.aiwcorpo.mcp.gateway.support.GatewayTestEnvironment;
import tools.jackson.databind.JsonNode;

/** C5 admin API on the internal TLS port: who may call it, the catalog, and the CRUD of links. */
class AdminApiTest extends GatewayTestBase {

    private static final List<String> BOB_GROUPS = List.of("mcp-jira-read");

    // --- who may call ----------------------------------------------------------------------------------------

    @Test
    void adminApiNeedsTheBffCertificateAndAUserTokenForTheAdminAudience() throws Exception {
        String token = env.idp.token(ALICE_SUB, "alice", ALICE_GROUPS, "mcp-gateway-admin", "mcp-portal-bff");

        assertThat(admin(env.bffTls, "GET", "/admin/v1/catalog", token, null).statusCode()).isEqualTo(200);

        HttpResponse<String> noCertificate = admin(env.noClientCertificateTls, "GET", "/admin/v1/catalog", token, null);
        assertThat(noCertificate.statusCode()).isEqualTo(401);
        assertThat(JSON.readTree(noCertificate.body()).path("error").asString()).isEqualTo("unauthenticated");

        HttpResponse<String> otherComponent = admin(env.otherComponentTls, "GET", "/admin/v1/catalog", token, null);
        assertThat(otherComponent.statusCode()).isEqualTo(403);
        assertThat(JSON.readTree(otherComponent.body()).path("error").asString()).isEqualTo("access_denied");

        assertThatThrownBy(() -> admin(env.foreignCaTls, "GET", "/admin/v1/catalog", token, null))
                .isInstanceOf(IOException.class);

        assertThat(admin(env.bffTls, "GET", "/admin/v1/catalog", null, null).statusCode()).isEqualTo(401);
        String clientToken = env.idp.token(ALICE_SUB, "alice", ALICE_GROUPS, "mcp-gateway", "claude-code");
        HttpResponse<String> wrongAudience = admin(env.bffTls, "GET", "/admin/v1/catalog", clientToken, null);
        assertThat(wrongAudience.statusCode()).as("a token for MCP clients is not an admin token").isEqualTo(401);
        String brokerToken = env.idp.token(ALICE_SUB, "alice", ALICE_GROUPS, "mcp-credential-broker", "mcp-portal-bff");
        assertThat(admin(env.bffTls, "GET", "/admin/v1/catalog", brokerToken, null).statusCode()).isEqualTo(401);
    }

    @Test
    void adminApiIsNotOnThePublicPort() throws Exception {
        String token = env.idp.token(ALICE_SUB, "alice", ALICE_GROUPS, "mcp-gateway-admin", "mcp-portal-bff");
        for (String path : List.of("/admin/v1/catalog", "/admin/v1/virtual-servers", "/s/../admin/v1/catalog",
                "/s/%2e%2e/admin/v1/catalog", "/v/x/mcp/../../../admin/v1/catalog")) {
            HttpResponse<String> response = http.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + path))
                    .header("Authorization", "Bearer " + token).build(), HttpResponse.BodyHandlers.ofString());
            assertThat(response.statusCode()).as(path).isIn(400, 404);
            assertThat(response.body()).as(path).doesNotContain("servers");
        }
    }

    // --- catalog ---------------------------------------------------------------------------------------------

    @Test
    void catalogShowsTheCallersAccessFromPolicy() throws Exception {
        HttpResponse<String> response = admin("GET", "/admin/v1/catalog", ALICE_SUB, "alice", ALICE_GROUPS, null);
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.headers().firstValue("Cache-Control").orElse("")).contains("no-store");
        assertThat(response.headers().firstValue("X-Request-Id").orElse("")).matches("^[0-9a-f-]{36}$");
        JsonNode catalog = JSON.readTree(response.body());
        assertThat(Contracts.gatewayAdminErrors("Catalog", catalog)).isEmpty();
        assertThat(Contracts.gatewayAdminErrors("Catalog", JSON.readTree("{\"servers\":[{\"serverId\":\"x\"}]}")))
                .as("the schema check is live").isNotEmpty();

        JsonNode jira = server(catalog, "mcp-jira");
        assertThat(jira.path("system").asString()).isEqualTo("jira");
        assertThat(jira.path("version").asString()).isEqualTo("1.0.0");
        JsonNode getIssue = tool(jira, "jira__get_issue");
        assertThat(getIssue.path("title").asString()).isEqualTo("Pobranie zg\u0142oszenia");
        assertThat(getIssue.path("description").asString()).isEqualTo("Returns one Jira issue by key.");
        assertThat(getIssue.path("risk").asString()).isEqualTo("READ_ONLY");
        assertThat(getIssue.path("action").asString()).isEqualTo("read");
        assertThat(getIssue.path("access").asString()).isEqualTo("granted");
        assertThat(getIssue.path("requiredEntitlements").toString()).isEqualTo("[\"mcp-jira-read\"]");
        assertThat(getIssue.path("disabled").asBoolean(true)).isFalse();
        assertThat(getIssue.path("requiresConfirmation").asBoolean(true)).isFalse();
        assertThat(tool(jira, "jira__add_comment").path("access").asString()).isEqualTo("granted");
        assertThat(tool(jira, "jira__add_comment").path("action").asString()).isEqualTo("update");

        JsonNode delete = tool(jira, "jira__delete_issue");
        assertThat(delete.path("risk").asString()).isEqualTo("DESTRUCTIVE");
        assertThat(delete.path("action").asString()).isEqualTo("delete");
        assertThat(delete.path("access").asString()).isEqualTo("denied");
        assertThat(delete.path("disabled").asBoolean()).as("calls are refused until confirmations exist").isTrue();
        assertThat(delete.path("requiresConfirmation").asBoolean()).isTrue();
        assertThat(delete.path("requiredEntitlements").toString()).isEqualTo("[\"mcp-jira-destructive\"]");

        assertThat(tool(server(catalog, "mcp-gitlab"), "gitlab__get_issue").path("access").asString()).isEqualTo("denied");
        assertThat(tool(server(catalog, "mcp-confluence"), "confluence__search_issues").path("access").asString())
                .isEqualTo("granted");
        assertThat(tool(server(catalog, "mcp-confluence"), "confluence__search_issues").has("title")).isFalse();
    }

    @Test
    void catalogOfAUserWithoutGroupsGrantsNothingAndDisabledServerStaysVisibleAsDisabled() throws Exception {
        List<String> everything = List.of("mcp-jira-read", "mcp-jira-write", "mcp-servicedesk-read");
        JsonNode catalog = JSON.readTree(admin("GET", "/admin/v1/catalog", BOB_SUB, "bob", List.of(), null).body());
        for (JsonNode server : catalog.path("servers")) {
            for (JsonNode tool : server.path("tools")) {
                assertThat(tool.path("access").asString()).as(tool.path("name").asString()).isEqualTo("denied");
            }
        }
        JsonNode servicedesk = server(JSON.readTree(admin("GET", "/admin/v1/catalog", BOB_SUB, "bob", everything, null).body()),
                "mcp-servicedesk");
        assertThat(servicedesk.path("version").asString()).isEqualTo("2.1.0");
        JsonNode ticket = tool(servicedesk, "servicedesk__get_ticket");
        assertThat(ticket.path("access").asString()).isEqualTo("denied");
        assertThat(ticket.path("disabled").asBoolean()).as("every tool of a disabled server").isTrue();
        assertThat(ticket.path("requiredEntitlements").toString()).isEqualTo("[\"mcp-servicedesk-read\"]");
    }

    // --- virtual servers: create, list, delete ---------------------------------------------------------------

    @Test
    void ownerCreatesListsAndDeletesALink() throws Exception {
        HttpResponse<String> created = createLink(ALICE_SUB, "alice", ALICE_GROUPS, "team-a-dev", "Team A development",
                List.of("jira__search_issues", "jira__get_issue"));
        assertThat(created.statusCode()).isEqualTo(201);
        JsonNode body = JSON.readTree(created.body());
        assertThat(Contracts.gatewayAdminErrors("VirtualServerCreated", body)).isEmpty();
        assertThat(body.path("url").asString()).isEqualTo(GatewayTestEnvironment.PUBLIC_URL + "/v/team-a-dev/mcp");

        JsonNode list = JSON.readTree(admin("GET", "/admin/v1/virtual-servers", ALICE_SUB, "alice", ALICE_GROUPS, null).body());
        assertThat(list.size()).isEqualTo(1);
        assertThat(Contracts.gatewayAdminErrors("VirtualServer", list.get(0))).isEmpty();
        assertThat(list.get(0).path("displayName").asString()).isEqualTo("Team A development");
        assertThat(list.get(0).path("tools").toString()).isEqualTo("[\"jira__search_issues\",\"jira__get_issue\"]");
        assertThat(list.get(0).has("resourceDefaults")).isFalse();

        assertThat(JSON.readTree(admin("GET", "/admin/v1/virtual-servers", BOB_SUB, "bob", BOB_GROUPS, null).body()).size())
                .as("a list holds only the caller's links").isZero();

        assertThat(admin("DELETE", "/admin/v1/virtual-servers/team-a-dev", ALICE_SUB, "alice", ALICE_GROUPS, null).statusCode())
                .isEqualTo(204);
        assertThat(JSON.readTree(admin("GET", "/admin/v1/virtual-servers", ALICE_SUB, "alice", ALICE_GROUPS, null).body()).size())
                .isZero();
        assertThat(admin("DELETE", "/admin/v1/virtual-servers/team-a-dev", ALICE_SUB, "alice", ALICE_GROUPS, null).statusCode())
                .isEqualTo(404);
    }

    @Test
    void takenSlugIs409EvenForAnotherUserAndForeignLinksCannotBeDeleted() throws Exception {
        assertThat(createLink(ALICE_SUB, "alice", ALICE_GROUPS, "shared-name", "Alice", List.of("jira__get_issue"))
                .statusCode()).isEqualTo(201);
        HttpResponse<String> conflict = createLink(BOB_SUB, "bob", BOB_GROUPS, "shared-name", "Bob", List.of("jira__get_issue"));
        assertThat(conflict.statusCode()).isEqualTo(409);
        assertThat(JSON.readTree(conflict.body()).path("error").asString()).isEqualTo("slug_taken");
        assertThat(createLink(ALICE_SUB, "alice", ALICE_GROUPS, "shared-name", "Again", List.of("jira__get_issue"))
                .statusCode()).isEqualTo(409);

        HttpResponse<String> foreignDelete = admin("DELETE", "/admin/v1/virtual-servers/shared-name", BOB_SUB, "bob",
                BOB_GROUPS, null);
        assertThat(foreignDelete.statusCode()).isEqualTo(404);
        assertThat(JSON.readTree(foreignDelete.body()).path("error").asString()).isEqualTo("not_found_or_denied");
        assertThat(JSON.readTree(admin("GET", "/admin/v1/virtual-servers", ALICE_SUB, "alice", ALICE_GROUPS, null).body()).size())
                .as("Alice's link survived").isEqualTo(1);
        assertThat(admin("DELETE", "/admin/v1/virtual-servers/Not_A_Slug", ALICE_SUB, "alice", ALICE_GROUPS, null).statusCode())
                .isEqualTo(404);
    }

    @Test
    void aLinkNeverReachesBeyondTheCreatorsRights() throws Exception {
        List<String> refused = new ArrayList<>(List.of("jira__add_comment", "jira__delete_issue", "gitlab__get_issue",
                "servicedesk__get_ticket", "jira__no_such_tool", "opensearch__search_documents"));
        for (String tool : refused) {
            HttpResponse<String> response = createLink(BOB_SUB, "bob", BOB_GROUPS, "bobs-link", "Bob",
                    List.of("jira__get_issue", tool));
            assertThat(response.statusCode()).as(tool).isEqualTo(403);
            assertThat(JSON.readTree(response.body()).path("error").asString()).as(tool).isEqualTo("access_denied");
        }
        assertThat(JSON.readTree(admin("GET", "/admin/v1/virtual-servers", BOB_SUB, "bob", BOB_GROUPS, null).body()).size())
                .as("nothing is stored when one tool is refused").isZero();
        assertThat(createLink(BOB_SUB, "bob", BOB_GROUPS, "bobs-link", "Bob", List.of("jira__get_issue")).statusCode())
                .as("the slug stayed free").isEqualTo(201);
    }

    @Test
    void malformedCreateRequestsAreInvalidRequest() throws Exception {
        List<String> bodies = List.of(
                "not json",
                "[]",
                "{}",
                "{\"slug\":\"ok\",\"displayName\":\"x\"}",
                "{\"slug\":\"ok\",\"displayName\":\"x\",\"tools\":[]}",
                "{\"slug\":\"ok\",\"displayName\":\"x\",\"tools\":\"jira__get_issue\"}",
                "{\"slug\":\"ok\",\"displayName\":\"x\",\"tools\":[\"jira__get_issue\",\"jira__get_issue\"]}",
                "{\"slug\":\"ok\",\"displayName\":\"x\",\"tools\":[\"get_issue\"]}",
                "{\"slug\":\"ok\",\"displayName\":\"x\",\"tools\":[\"jira__Get_Issue\"]}",
                "{\"slug\":\"ok\",\"displayName\":\"x\",\"tools\":[\"jira__get_issue\"],\"owner\":\"someone\"}",
                "{\"slug\":\"Upper\",\"displayName\":\"x\",\"tools\":[\"jira__get_issue\"]}",
                "{\"slug\":\"-lead\",\"displayName\":\"x\",\"tools\":[\"jira__get_issue\"]}",
                "{\"slug\":\"trail-\",\"displayName\":\"x\",\"tools\":[\"jira__get_issue\"]}",
                "{\"slug\":\"" + "a".repeat(64) + "\",\"displayName\":\"x\",\"tools\":[\"jira__get_issue\"]}",
                "{\"slug\":\"a\\nb\",\"displayName\":\"x\",\"tools\":[\"jira__get_issue\"]}",
                "{\"slug\":\"../v\",\"displayName\":\"x\",\"tools\":[\"jira__get_issue\"]}",
                "{\"slug\":\"ok\",\"displayName\":\"\",\"tools\":[\"jira__get_issue\"]}",
                "{\"slug\":\"ok\",\"displayName\":\"" + "x".repeat(101) + "\",\"tools\":[\"jira__get_issue\"]}",
                "{\"slug\":\"ok\",\"displayName\":\"line\\nbreak\",\"tools\":[\"jira__get_issue\"]}",
                "{\"slug\":\"ok\",\"displayName\":\"a\\u202eb\",\"tools\":[\"jira__get_issue\"]}",
                "{\"slug\":\"ok\",\"displayName\":7,\"tools\":[\"jira__get_issue\"]}");
        for (String body : bodies) {
            HttpResponse<String> response = admin("POST", "/admin/v1/virtual-servers", ALICE_SUB, "alice", ALICE_GROUPS, body);
            assertThat(response.statusCode()).as(body).isEqualTo(400);
            assertThat(JSON.readTree(response.body()).path("error").asString()).as(body).isEqualTo("invalid_request");
        }
        assertThat(JSON.readTree(admin("GET", "/admin/v1/virtual-servers", ALICE_SUB, "alice", ALICE_GROUPS, null).body()).size())
                .isZero();
    }

    @Test
    void resourceDefaultsAreDormant() throws Exception {
        String base = "\"slug\":\"narrowed\",\"displayName\":\"x\",\"tools\":[\"jira__get_issue\"]";
        HttpResponse<String> unsupported = admin("POST", "/admin/v1/virtual-servers", ALICE_SUB, "alice", ALICE_GROUPS,
                "{" + base + ",\"resourceDefaults\":{\"Jira::Project\":[\"ABC\"]}}");
        assertThat(unsupported.statusCode()).isEqualTo(400);
        assertThat(JSON.readTree(unsupported.body()).path("error").asString()).isEqualTo("resource_defaults_unsupported");

        // README 2.2.1: a non-empty object is refused before its content is looked at.
        HttpResponse<String> contentNotChecked = admin("POST", "/admin/v1/virtual-servers", ALICE_SUB, "alice", ALICE_GROUPS,
                "{" + base + ",\"resourceDefaults\":{\"Jira::Project\":\"not-an-array\",\"Unknown::Type\":[1]}}");
        assertThat(JSON.readTree(contentNotChecked.body()).path("error").asString()).isEqualTo("resource_defaults_unsupported");

        HttpResponse<String> beforeEverythingElse = admin("POST", "/admin/v1/virtual-servers", ALICE_SUB, "alice", ALICE_GROUPS,
                "{\"slug\":\"Bad Slug\",\"resourceDefaults\":{\"Jira::Project\":[\"ABC\"]}}");
        assertThat(JSON.readTree(beforeEverythingElse.body()).path("error").asString())
                .isEqualTo("resource_defaults_unsupported");

        for (String notAnObject : List.of("[]", "null", "\"x\"", "7", "[\"ABC\"]")) {
            HttpResponse<String> response = admin("POST", "/admin/v1/virtual-servers", ALICE_SUB, "alice", ALICE_GROUPS,
                    "{" + base + ",\"resourceDefaults\":" + notAnObject + "}");
            assertThat(JSON.readTree(response.body()).path("error").asString()).as(notAnObject).isEqualTo("invalid_request");
        }
        assertThat(JSON.readTree(admin("GET", "/admin/v1/virtual-servers", ALICE_SUB, "alice", ALICE_GROUPS, null).body()).size())
                .isZero();

        HttpResponse<String> empty = admin("POST", "/admin/v1/virtual-servers", ALICE_SUB, "alice", ALICE_GROUPS,
                "{" + base + ",\"resourceDefaults\":{}}");
        assertThat(empty.statusCode()).isEqualTo(201);
        JsonNode list = JSON.readTree(admin("GET", "/admin/v1/virtual-servers", ALICE_SUB, "alice", ALICE_GROUPS, null).body());
        assertThat(list.get(0).has("resourceDefaults")).as("responses never carry it").isFalse();
    }

    @Test
    void adminRequestIdIsEchoedWhenItIsAUuidV7AndReplacedOtherwise() throws Exception {
        String token = env.idp.token(ALICE_SUB, "alice", ALICE_GROUPS, "mcp-gateway-admin", "mcp-portal-bff");
        String offered = pl.aiwcorpo.mcp.gateway.jwt.UuidV7.next();
        HttpClient client = HttpClient.newBuilder().sslContext(env.bffTls).build();
        HttpResponse<String> echoed = client.send(HttpRequest.newBuilder(
                URI.create("https://localhost:" + env.internalPort + "/admin/v1/virtual-servers"))
                .header("Authorization", "Bearer " + token).header("X-Request-Id", offered).build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(echoed.headers().firstValue("X-Request-Id")).hasValue(offered);
        HttpResponse<String> replaced = client.send(HttpRequest.newBuilder(
                URI.create("https://localhost:" + env.internalPort + "/admin/v1/virtual-servers"))
                .header("Authorization", "Bearer " + token).header("X-Request-Id", "not\"a-uuid").build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(replaced.headers().firstValue("X-Request-Id").orElse("")).isNotEqualTo("not\"a-uuid").matches("^[0-9a-f-]{36}$");
    }

    private static JsonNode server(JsonNode catalog, String serverId) {
        for (JsonNode server : catalog.path("servers")) {
            if (serverId.equals(server.path("serverId").asString())) {
                return server;
            }
        }
        throw new AssertionError("no server " + serverId + " in " + catalog);
    }

    private static JsonNode tool(JsonNode server, String name) {
        for (JsonNode tool : server.path("tools")) {
            if (name.equals(tool.path("name").asString())) {
                return tool;
            }
        }
        throw new AssertionError("no tool " + name + " in " + server);
    }
}
