package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import pl.aiwcorpo.mcp.gateway.support.Contracts;
import tools.jackson.databind.JsonNode;

/** C5 admin API on the internal TLS port: who may call it and the catalog. */
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
        assertThat(admin(env.otherComponentTls, "GET", "/admin/v1/registry/servers", token, null).statusCode())
                .as("another component may not list the registry").isEqualTo(403);

        assertThat(admin(env.bffTls, "PUT", "/admin/v1/registry/servers/mcp-jira", token, "{}").statusCode())
                .as("nothing is registered by a PUT any more: the gateway pulls manifests itself").isEqualTo(403);
        assertThat(admin(env.offboardingTls, "PUT", "/admin/v1/registry/servers/mcp-jira", token, "{}").statusCode())
                .as("the offboarding process writes no manifests").isEqualTo(403);
        assertThat(admin(env.otherComponentTls, "POST", "/admin/v1/users/someone/purge", null, null).statusCode())
                .as("another component does not offboard").isEqualTo(403);
        assertThat(admin(env.bffTls, "POST", "/admin/v1/users/someone/purge", token, null).statusCode())
                .as("the BFF does not offboard").isEqualTo(403);

        for (String path : List.of("/admin/v1/nothing", "/admin/v1", "/admin/v1/catalog/", "/admin/v1/registry/x/y")) {
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
        assertThat(getIssue.path("title").asString()).isEqualTo("Get issue");
        assertThat(getIssue.path("description").asString()).isEqualTo("Returns the key and summary of one Jira issue.");
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
        assertThat(tool(server(catalog, "mcp-confluence"), "confluence__search_issues").path("title").asString()).isEqualTo("search_issues");
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

    // --- the API of saved links is gone (CC-175) -------------------------------------------------------------

    @Test
    void theApiOfSavedLinksIsGone() throws Exception {
        String token = env.idp.token(ALICE_SUB, "alice", ALICE_GROUPS, "mcp-gateway-admin", "mcp-portal-bff");
        for (String method : List.of("GET", "POST")) {
            assertThat(admin(env.bffTls, method, "/admin/v1/virtual-servers", token, method.equals("POST") ? "{}" : null).statusCode())
                    .as(method).isEqualTo(403);
        }
        assertThat(admin(env.bffTls, "DELETE", "/admin/v1/virtual-servers/team-a-dev", token, null).statusCode()).isEqualTo(403);
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

    @Test
    void theCatalogIsA503WhenTheSwitchesCannotBeRead() throws Exception {
        pl.aiwcorpo.mcp.gateway.admin.AdminController controller = new pl.aiwcorpo.mcp.gateway.admin.AdminController(
                org.mockito.Mockito.mock(pl.aiwcorpo.mcp.gateway.server.ServerRegistry.class),
                org.mockito.Mockito.mock(pl.aiwcorpo.mcp.gateway.authz.ToolAuthorizer.class), JSON, "mcp-gateway",
                org.mockito.Mockito.mock(pl.aiwcorpo.mcp.gateway.registry.DefinitionGuard.class),
                org.mockito.Mockito.mock(pl.aiwcorpo.mcp.gateway.killswitch.KillSwitches.class));
        org.springframework.security.oauth2.jwt.Jwt token = org.springframework.security.oauth2.jwt.Jwt.withTokenValue("t").header("alg", "none")
                .subject("s").claim("groups", List.of()).issuedAt(java.time.Instant.now()).expiresAt(java.time.Instant.now().plusSeconds(60)).build();

        var answer = controller.catalog(token, new org.springframework.mock.web.MockHttpServletRequest());

        assertThat(answer.getStatusCode().value()).isEqualTo(503);
        assertThat(answer.getHeaders().getFirst("Retry-After")).isEqualTo("10");
        assertThat(JSON.readTree(answer.getBody()).path("error").asString()).isEqualTo("upstream_unavailable");
    }
}
