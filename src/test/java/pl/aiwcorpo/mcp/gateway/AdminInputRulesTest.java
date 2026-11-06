package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import pl.aiwcorpo.mcp.gateway.support.Contracts;
import tools.jackson.databind.JsonNode;

/**
 * One rule for what the admin API is given (CC-243): a malformed If-Match or If-None-Match and a path identifier that does not fit its pattern
 * are {@code 400 invalid_request}, never {@code 404}; a well-formed identifier without a resource is {@code 404}; a stale If-Match is
 * {@code 412}. Also: replacing an override needs a fresh MFA (creating one does not), the approved policies of a server can be read, and an
 * override cannot target a platform component.
 */
class AdminInputRulesTest extends GatewayTestBase {

    private static final String OVERRIDE = "{\"target\":\"gateway\",\"text\":\"forbid (principal, action == Action::\\\"call\\\", resource is Tool);\"}";

    @AfterEach
    void clean() throws Exception {
        adminCall("DELETE", "/admin/v1/servers/mcp-reader", null);
        jdbc.sql("DELETE FROM policy_overrides").update();
    }

    private JsonNode json(HttpResponse<String> response) {
        return JSON.readTree(response.body());
    }

    private void assertInvalid(String method, String path, String body, Map<String, String> headers) throws Exception {
        HttpResponse<String> response = adminCall(method, path, body, headers);
        assertThat(response.statusCode()).as(method + " " + path + " " + headers + " " + response.body()).isEqualTo(400);
        assertThat(json(response).path("error").asString()).isEqualTo("invalid_request");
    }

    @Test
    void anIdentifierThatDoesNotFitItsPatternIsAnInvalidRequestEverywhere() throws Exception {
        for (String method : List.of("GET", "PATCH", "DELETE")) {
            assertInvalid(method, "/admin/v1/servers/NOT-A-SERVER", method.equals("PATCH") ? "{\"enabled\":false}" : null, Map.of());
        }
        assertInvalid("GET", "/admin/v1/registry/servers/NOT-A-SERVER/policies", null, Map.of());
        assertInvalid("GET", "/admin/v1/registry/servers/NOT-A-SERVER/policies/pending", null, Map.of());
        assertInvalid("POST", "/admin/v1/registry/servers/NOT-A-SERVER/policies/approve", "{\"policiesHash\":\"sha256:" + "0".repeat(64) + "\"}", Map.of());
        assertInvalid("GET", "/admin/v1/registry/servers/mcp-jira/tools/NOT-A-TOOL/pending", null, Map.of());
        assertInvalid("POST", "/admin/v1/registry/servers/mcp-jira/tools/NOT-A-TOOL/approve", "{\"definitionHash\":\"sha256:" + "0".repeat(64) + "\"}", Map.of());
        assertInvalid("PUT", "/admin/v1/registry/servers/mcp-jira/tools/NOT-A-TOOL/kill-switch", "{\"reason\":\"x\"}", Map.of());
        assertInvalid("DELETE", "/admin/v1/registry/servers/mcp-jira/tools/NOT-A-TOOL/kill-switch", null, Map.of());
        assertInvalid("PUT", "/admin/v1/registry/servers/NOT-A-SERVER/kill-switch", "{\"reason\":\"x\"}", Map.of());
        assertInvalid("GET", "/admin/v1/policy/overrides/not-an-override", null, Map.of());
        assertInvalid("DELETE", "/admin/v1/policy/overrides/override-UPPER", null, Map.of("If-Match", "\"stale-version-0000\""));
        assertInvalid("GET", "/admin/v1/confirmations/short", null, Map.of());
    }

    @Test
    void aMalformedPreconditionIsAnInvalidRequestAndAStaleOneIs412() throws Exception {
        assertInvalid("PATCH", "/admin/v1/servers/mcp-jira", "{\"enabled\":false}", Map.of("If-Match", "not an etag"));
        assertInvalid("PUT", "/admin/v1/policy/scope-mapping", "{\"scopeMapping\":[]}", Map.of("If-Match", "W/\"x\""));
        assertInvalid("PUT", "/admin/v1/policy/overrides/override-x", OVERRIDE, Map.of("If-None-Match", "\"abc\""));
        assertInvalid("PUT", "/admin/v1/policy/overrides/override-x", OVERRIDE, Map.of("If-Match", "nope"));
        assertInvalid("DELETE", "/admin/v1/policy/overrides/override-x", null, Map.of("If-Match", "nope"));

        assertThat(adminCall("PATCH", "/admin/v1/servers/mcp-jira", "{\"enabled\":true}", Map.of("If-Match", "\"stale-version-0000\"")).statusCode())
                .isEqualTo(412);
        assertThat(adminCall("PUT", "/admin/v1/policy/scope-mapping", "{\"scopeMapping\":[]}", Map.of("If-Match", "\"stale-version-0000\"")).statusCode())
                .isEqualTo(412);
    }

    @Test
    void aWellFormedIdentifierWithoutAResourceIs404() throws Exception {
        for (String[] call : new String[][] {{"GET", "/admin/v1/servers/mcp-nothere"}, {"DELETE", "/admin/v1/servers/mcp-nothere"},
                {"GET", "/admin/v1/registry/servers/mcp-nothere/policies"}, {"GET", "/admin/v1/registry/servers/mcp-nothere/policies/pending"},
                {"GET", "/admin/v1/policy/overrides/override-nothere"}, {"GET", "/admin/v1/registry/servers/mcp-jira/tools/nothere/pending"}}) {
            assertThat(adminCall(call[0], call[1], null).statusCode()).as(call[0] + " " + call[1]).isEqualTo(404);
        }
        assertThat(adminCall("PATCH", "/admin/v1/servers/mcp-nothere", "{\"enabled\":false}", Map.of("If-Match", "\"stale-version-0000\"")).statusCode())
                .isEqualTo(404);
        assertThat(adminCall("DELETE", "/admin/v1/policy/overrides/override-nothere", null, Map.of("If-Match", "\"stale-version-0000\"")).statusCode())
                .isEqualTo(404);
    }

    @Test
    void theApprovedPoliciesOfAServerCanBeReadAndAreNullUntilThereAreSome() throws Exception {
        HttpResponse<String> jira = adminCall("GET", "/admin/v1/registry/servers/mcp-jira/policies", null);
        assertThat(jira.statusCode()).isEqualTo(200);
        JsonNode body = json(jira);
        assertThat(Contracts.gatewayAdminErrors("ApprovedPolicies", body)).isEmpty();
        assertThat(body.path("approvedHash").asString()).isEqualTo(env.jira.manifest().path("policiesHash").asString());
        assertThat(body.path("approvedPolicies").path("namespace").asString()).isEqualTo("Jira");
        assertThat(body.path("approvedResourceTypes").findValuesAsString("type")).contains("Jira::Project", "Jira::Issue");

        assertThat(adminCall("POST", "/admin/v1/servers", "{\"serverId\":\"mcp-reader\",\"system\":\"reader\",\"internalUrl\":\"https://127.0.0.1:8443/mcp\","
                + "\"credential\":{\"required\":true,\"acceptedTypes\":[\"user-secret\"],\"type\":\"user-secret\"}}").statusCode()).isEqualTo(201);
        HttpResponse<String> nothing = adminCall("GET", "/admin/v1/registry/servers/mcp-reader/policies", null);
        assertThat(nothing.statusCode()).as("nothing approved is not a 404").isEqualTo(200);
        assertThat(json(nothing).path("approvedHash").isNull()).isTrue();
        assertThat(json(nothing).path("approvedPolicies").isNull()).isTrue();
        assertThat(json(nothing).path("approvedResourceTypes").isNull()).isTrue();
        assertThat(Contracts.gatewayAdminErrors("ApprovedPolicies", json(nothing))).isEmpty();
    }

    @Test
    void replacingAnOverrideNeedsAFreshMfaAndCreatingOneDoesNot() throws Exception {
        String stale = env.idp.adminToken(ADMIN_SUB, "a.admin", List.of("mcp-platform-admin"), 4000L, List.of("pwd"), null);
        String fresh = env.idp.adminToken(ADMIN_SUB, "a.admin", List.of("mcp-platform-admin"), 10L, List.of("pwd", "otp"), null);

        HttpResponse<String> created = admin(env.bffTls, "PUT", "/admin/v1/policy/overrides/override-mfa-input", stale, OVERRIDE,
                Map.of("If-None-Match", "*"));
        assertThat(created.statusCode()).as("creating only narrows access: " + created.body()).isEqualTo(200);

        HttpResponse<String> refused = admin(env.bffTls, "PUT", "/admin/v1/policy/overrides/override-mfa-input", stale, OVERRIDE,
                Map.of("If-Match", etag(created)));
        assertThat(refused.statusCode()).isEqualTo(401);
        assertThat(json(refused).path("error").asString()).isEqualTo("step_up_required");

        assertThat(admin(env.bffTls, "PUT", "/admin/v1/policy/overrides/override-mfa-input", fresh, OVERRIDE, Map.of("If-Match", etag(created)))
                .statusCode()).isEqualTo(200);
    }

    @Test
    void anOverrideCannotTargetAPlatformComponent() throws Exception {
        String text = "forbid (principal, action, resource);";
        for (String reserved : List.of("mcp-gateway", "mcp-broker", "mcp-portal", "mcp-offboarding", "mcp-registry", "mcp-ci")) {
            HttpResponse<String> response = adminCall("PUT", "/admin/v1/policy/overrides/override-reserved",
                    JSON.writeValueAsString(JSON.createObjectNode().put("target", reserved).put("text", text)), Map.of("If-None-Match", "*"));
            assertThat(response.statusCode()).as(reserved + " " + response.body()).isEqualTo(400);
            assertThat(json(response).path("error").asString()).isEqualTo("invalid_request");
        }
        assertThat(adminCall("GET", "/admin/v1/policy/overrides/override-reserved", null).statusCode()).as("nothing was stored").isEqualTo(404);
    }
}
