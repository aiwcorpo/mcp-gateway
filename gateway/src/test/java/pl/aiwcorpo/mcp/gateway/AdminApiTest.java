package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.system.CapturedOutput;

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

        assertThat(admin(env.foreignCaTls, "GET", "/admin/v1/catalog", token, null).statusCode())
                .as("a certificate of a foreign CA").isEqualTo(401);
        assertThat(admin(env.serverIdentityTls, "GET", "/admin/v1/catalog", token, null).statusCode())
                .as("a valid certificate that is not for client authentication").isEqualTo(401);

        assertThat(admin(env.bffTls, "GET", "/admin/v1/catalog", null, null).statusCode()).isEqualTo(401);
        String clientToken = env.idp.token(ALICE_SUB, "alice", ALICE_GROUPS, "mcp-gateway", "claude-code");
        HttpResponse<String> wrongAudience = admin(env.bffTls, "GET", "/admin/v1/catalog", clientToken, null);
        assertThat(wrongAudience.statusCode()).as("a token for MCP clients is not an admin token").isEqualTo(401);
        String brokerToken = env.idp.token(ALICE_SUB, "alice", ALICE_GROUPS, "mcp-credential-broker", "mcp-portal-bff");
        assertThat(admin(env.bffTls, "GET", "/admin/v1/catalog", brokerToken, null).statusCode()).isEqualTo(401);
    }

    @Test
    void theAdminTokenMustBeIssuedToTheBffAndNamesOnlyTheAdminAudience() throws Exception {
        assertThat(admin(env.bffTls, "GET", "/admin/v1/catalog",
                env.idp.token(ALICE_SUB, "alice", ALICE_GROUPS, "mcp-gateway-admin", "claude-code"), null).statusCode())
                .as("another client asked for the admin audience").isEqualTo(401);
        assertThat(admin(env.bffTls, "GET", "/admin/v1/catalog", env.idp.token(ALICE_SUB, "alice", ALICE_GROUPS,
                List.of("mcp-gateway-admin", "mcp-gateway"), "mcp-portal-bff"), null).statusCode())
                .as("a token that is also an MCP token").isEqualTo(401);
        assertThat(admin(env.bffTls, "GET", "/admin/v1/catalog", env.idp.token(ALICE_SUB, "alice", ALICE_GROUPS,
                List.of("mcp-gateway-admin", "mcp-credential-broker"), "mcp-portal-bff"), null).statusCode())
                .as("other audiences next to the admin one are not a problem").isEqualTo(200);

        assertThat(send(env.idp.token(ALICE_SUB, "alice", ALICE_GROUPS, List.of("mcp-gateway", "mcp-gateway-admin"),
                "claude-code"), "/s/mcp-jira/mcp", initializeBody(), Map.of()).statusCode())
                .as("an admin token does not open the MCP endpoints").isEqualTo(401);
    }

    @Test
    void certificateNamesAreCheckedPerOperation() throws Exception {
        String token = env.idp.token(ALICE_SUB, "alice", ALICE_GROUPS, "mcp-gateway-admin", "mcp-portal-bff");
        assertThat(admin(env.otherComponentTls, "GET", "/admin/v1/virtual-servers", token, null).statusCode())
                .as("registry CI may not list links").isEqualTo(403);
        assertThat(admin(env.otherComponentTls, "POST", "/admin/v1/virtual-servers", token,
                "{\"slug\":\"ci-link\",\"displayName\":\"x\",\"tools\":[\"jira__get_issue\"]}").statusCode()).isEqualTo(403);
        assertThat(JSON.readTree(admin("GET", "/admin/v1/virtual-servers", ALICE_SUB, "alice", ALICE_GROUPS, null).body()).size())
                .as("and created nothing").isZero();

        assertThat(admin(env.bffTls, "PUT", "/admin/v1/registry/servers/mcp-jira", token, "{}").statusCode())
                .as("the BFF may not write manifests").isEqualTo(403);
        assertThat(admin(env.otherComponentTls, "PUT", "/admin/v1/registry/servers/mcp-jira", token, "{}").statusCode())
                .as("registry CI passes the certificate check; the operation itself is not served yet").isNotEqualTo(403);

        for (String path : List.of("/admin/v1/nothing", "/admin/v1", "/admin/v1/catalog/", "/admin/v1/virtual-servers/x/y")) {
            assertThat(admin(env.bffTls, "GET", path, token, null).statusCode()).as(path).isEqualTo(403);
        }
        assertThat(admin(env.bffTls, "PATCH", "/admin/v1/catalog", token, "{}").statusCode()).as("a method the contract lacks")
                .isEqualTo(403);
    }

    @Test
    void serversThatSendTheirOwnCertificateStillFetchTheJwks() throws Exception {
        for (var tls : List.of(env.serverIdentityTls, env.bffTls, env.foreignCaTls, env.noClientCertificateTls)) {
            HttpResponse<String> jwks = admin(tls, "GET", "/.well-known/jwks.json", null, null);
            assertThat(jwks.statusCode()).isEqualTo(200);
            assertThat(JSON.readTree(jwks.body()).path("keys").size()).isEqualTo(2);
        }
    }

    @Test
    void adminApiIsNotOnThePublicPort() throws Exception {
        String token = env.idp.token(ALICE_SUB, "alice", ALICE_GROUPS, "mcp-gateway-admin", "mcp-portal-bff");
        for (String path : List.of("/admin/v1/catalog", "/admin/v1/virtual-servers", "/admin/v1", "/s/../admin/v1/catalog",
                "/s/%2e%2e/admin/v1/catalog", "/v/x/mcp/../../../admin/v1/catalog", "//admin/v1/catalog", "/%61dmin/v1/catalog",
                "/admin//v1/catalog", "/./admin/v1/catalog", "/admin/v1/catalog/", "/admin/v1/virtual-servers;x=1",
                "/ADMIN/v1/catalog")) {
            HttpResponse<String> response = http.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + path))
                    .header("Authorization", "Bearer " + token).build(), HttpResponse.BodyHandlers.ofString());
            assertThat(response.statusCode()).as(path).isIn(400, 401, 404);
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
        assertThat(delete.path("disabled").asBoolean(true)).as("Alice lacks the group; the tool itself is on").isFalse();
        assertThat(delete.path("requiresConfirmation").asBoolean()).isTrue();
        assertThat(delete.path("requiredEntitlements").toString()).isEqualTo("[\"mcp-jira-destructive\"]");

        assertThat(tool(server(catalog, "mcp-gitlab"), "gitlab__get_issue").path("access").asString()).isEqualTo("denied");
        assertThat(tool(server(catalog, "mcp-gitlab"), "gitlab__get_issue").path("disabled").asBoolean(true))
                .as("denied for lack of a group is not disabled: the portal offers to ask for access").isFalse();
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

    @Test
    void aUserOwnsAtMostFiftyLinks() throws Exception {
        List<String> tools = List.of("jira__get_issue");
        for (int i = 0; i < 50; i++) {
            assertThat(createLink(BOB_SUB, "bob", BOB_GROUPS, "link-" + i, "Link " + i, tools).statusCode()).as("link " + i).isEqualTo(201);
        }
        HttpResponse<String> over = createLink(BOB_SUB, "bob", BOB_GROUPS, "link-50", "One too many", tools);
        assertThat(over.statusCode()).isEqualTo(409);
        assertThat(JSON.readTree(over.body()).path("error").asString()).isEqualTo("virtual_server_limit_reached");
        assertThat(JSON.readTree(admin("GET", "/admin/v1/virtual-servers", BOB_SUB, "bob", BOB_GROUPS, null).body()).size())
                .isEqualTo(50);
        assertThat(createLink(ALICE_SUB, "alice", ALICE_GROUPS, "alice-link", "Alice", tools).statusCode())
                .as("the limit is per user").isEqualTo(201);

        assertThat(admin("DELETE", "/admin/v1/virtual-servers/link-7", BOB_SUB, "bob", BOB_GROUPS, null).statusCode()).isEqualTo(204);
        assertThat(createLink(BOB_SUB, "bob", BOB_GROUPS, "link-50", "Fits again", tools).statusCode()).isEqualTo(201);
    }

    @Test
    void concurrentCreatesCannotOvershootTheLimit() throws Exception {
        List<String> tools = List.of("jira__get_issue");
        for (int i = 0; i < 45; i++) {
            assertThat(createLink(BOB_SUB, "bob", BOB_GROUPS, "pre-" + i, "Pre " + i, tools).statusCode()).isEqualTo(201);
        }
        try (var pool = java.util.concurrent.Executors.newFixedThreadPool(16)) {
            List<java.util.concurrent.Future<Integer>> results = new ArrayList<>();
            for (int i = 0; i < 16; i++) {
                String slug = "race-" + i;
                results.add(pool.submit(() -> createLink(BOB_SUB, "bob", BOB_GROUPS, slug, slug, tools).statusCode()));
            }
            int created = 0;
            int refused = 0;
            for (var result : results) {
                int status = result.get();
                created += status == 201 ? 1 : 0;
                refused += status == 409 ? 1 : 0;
            }
            assertThat(created).isEqualTo(5);
            assertThat(refused).as("every loser gets 409 virtual_server_limit_reached, none a 5xx").isEqualTo(11);
        }
        assertThat(JSON.readTree(admin("GET", "/admin/v1/virtual-servers", BOB_SUB, "bob", BOB_GROUPS, null).body()).size())
                .isEqualTo(50);
    }

    @Test
    void everyAdminChangeIsAuditedWithItsOutcome(CapturedOutput output) throws Exception {
        String token = env.idp.token(ALICE_SUB, "alice", ALICE_GROUPS, "mcp-gateway-admin", "mcp-portal-bff");
        String good = "{\"slug\":\"audited\",\"displayName\":\"x\",\"tools\":[\"jira__get_issue\"]}";

        JsonNode created = onlyEvent(output, change("POST", "/admin/v1/virtual-servers", token, good), 201);
        assertThat(created.path("virtualServer").asString()).isEqualTo("audited");
        assertThat(created.path("decision").asString()).isEqualTo("allow");
        assertThat(created.path("reason").asString()).isEqualTo("vs_created");
        assertThat(created.path("outcome").asString()).isEqualTo("ok");
        assertThat(created.path("sub").asString()).isEqualTo(ALICE_SUB);

        JsonNode taken = onlyEvent(output, change("POST", "/admin/v1/virtual-servers", token, good), 409);
        assertThat(taken.path("decision").asString()).isEqualTo("deny");
        assertThat(taken.path("reason").asString()).isEqualTo("slug_taken");
        assertThat(taken.path("outcome").asString()).isEqualTo("denied");

        JsonNode refused = onlyEvent(output, change("POST", "/admin/v1/virtual-servers", token,
                "{\"slug\":\"refused\",\"displayName\":\"x\",\"tools\":[\"jira__delete_issue\"]}"), 403);
        assertThat(refused.path("reason").asString()).isEqualTo("not_granted");
        assertThat(refused.path("errorCode").asString()).isEqualTo("access_denied");
        assertThat(refused.path("virtualServer").asString()).isEqualTo("refused");

        for (int i = 0; i < 49; i++) {
            assertThat(createLink(ALICE_SUB, "alice", ALICE_GROUPS, "fill-" + i, "Fill", List.of("jira__get_issue")).statusCode())
                    .isEqualTo(201);
        }
        JsonNode limited = onlyEvent(output, change("POST", "/admin/v1/virtual-servers", token,
                "{\"slug\":\"one-too-many\",\"displayName\":\"x\",\"tools\":[\"jira__get_issue\"]}"), 409);
        assertThat(limited.path("reason").asString()).isEqualTo("virtual_server_limit");
        assertThat(limited.path("decision").asString()).isEqualTo("deny");
        assertThat(limited.path("outcome").asString()).isEqualTo("denied");

        JsonNode malformed = onlyEvent(output, change("POST", "/admin/v1/virtual-servers", token, "{\"slug\":\"Bad Slug\"}"), 400);
        assertThat(malformed.path("reason").asString()).isEqualTo("invalid_request");
        assertThat(malformed.path("errorCode").asString()).isEqualTo("invalid_argument");
        assertThat(malformed.has("virtualServer")).as("an invalid slug is not copied into the log").isFalse();

        JsonNode unknown = onlyEvent(output, change("DELETE", "/admin/v1/virtual-servers/nobody-has-this", token, null), 404);
        assertThat(unknown.path("reason").asString()).isEqualTo("not_found_or_denied");
        assertThat(unknown.path("decision").asString()).isEqualTo("deny");

        String bobToken = env.idp.token(BOB_SUB, "bob", BOB_GROUPS, "mcp-gateway-admin", "mcp-portal-bff");
        JsonNode foreign = onlyEvent(output, change("DELETE", "/admin/v1/virtual-servers/audited", bobToken, null), 404);
        assertThat(foreign.path("sub").asString()).isEqualTo(BOB_SUB);
        assertThat(foreign.path("reason").asString()).isEqualTo("not_found_or_denied");

        JsonNode deleted = onlyEvent(output, change("DELETE", "/admin/v1/virtual-servers/audited", token, null), 204);
        assertThat(deleted.path("reason").asString()).isEqualTo("vs_deleted");
        assertThat(deleted.path("decision").asString()).isEqualTo("allow");
    }

    private record Change(String requestId, HttpResponse<String> response) {
    }

    private Change change(String method, String path, String token, String body) throws Exception {
        String requestId = pl.aiwcorpo.mcp.gateway.jwt.UuidV7.next();
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create("https://localhost:" + env.internalPort + path))
                .header("Authorization", "Bearer " + token).header("Content-Type", "application/json").header("X-Request-Id", requestId)
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        return new Change(requestId, HttpClient.newBuilder().sslContext(env.bffTls).build()
                .send(builder.build(), HttpResponse.BodyHandlers.ofString()));
    }

    private static JsonNode onlyEvent(CapturedOutput output, Change change, int status) {
        assertThat(change.response().statusCode()).isEqualTo(status);
        List<JsonNode> events = auditEvents(output, change.requestId());
        assertThat(events).hasSize(1);
        JsonNode event = events.get(0);
        assertThat(event.path("event").asString()).isEqualTo("virtual_server_change");
        assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", event)).isEmpty();
        return event;
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
