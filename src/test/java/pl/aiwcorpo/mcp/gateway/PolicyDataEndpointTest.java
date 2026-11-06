package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.net.ssl.SSLContext;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import pl.aiwcorpo.mcp.gateway.policy.PolicyService;
import pl.aiwcorpo.mcp.gateway.support.Contracts;
import tools.jackson.databind.JsonNode;

/**
 * {@code GET /internal/v1/policy-data} (C5 getPolicyData) on the internal TLS port: which certificates are served, what a server gets (only the
 * scopes of its own namespace, the overrides for it and for all servers, the hash approved for it) and how it learns that something changed
 * (ETag and If-None-Match, the revision in {@code prv}).
 */
class PolicyDataEndpointTest extends GatewayTestBase {

    @Autowired
    PolicyService policies;

    @AfterEach
    void clean() {
        jdbc.sql("UPDATE policy_state SET scope_mapping = '[]'::jsonb WHERE id = 1").update();
        jdbc.sql("DELETE FROM policy_overrides").update();
        policies.reload();
    }

    private HttpResponse<String> fetch(SSLContext tls, Map<String, String> headers) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create("https://localhost:" + env.internalPort + "/internal/v1/policy-data"));
        headers.forEach(request::header);
        return HttpClient.newBuilder().sslContext(tls).build().send(request.GET().build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> fetch(SSLContext tls) throws Exception {
        return fetch(tls, Map.of());
    }

    private void putMapping(String entries) throws Exception {
        HttpResponse<String> current = adminCall("GET", "/admin/v1/policy/scope-mapping", null);
        HttpResponse<String> put = adminCall("PUT", "/admin/v1/policy/scope-mapping", "{\"scopeMapping\":" + entries + "}",
                Map.of("If-Match", etag(current)));
        assertThat(put.statusCode()).as(put.body()).isEqualTo(200);
    }

    private void putOverride(String id, String target, String text) throws Exception {
        String body = JSON.writeValueAsString(JSON.createObjectNode().put("target", target).put("text", text));
        HttpResponse<String> put = adminCall("PUT", "/admin/v1/policy/overrides/" + id, body, Map.of("If-None-Match", "*"));
        assertThat(put.statusCode()).as(put.body()).isEqualTo(200);
    }

    @Test
    void aServerOfTheRegistryGetsItsDataAndOnlyTheNamespaceOfItsOwn() throws Exception {
        putMapping("[{\"group\":\"mcp-jira-proj-ABC\",\"scopes\":[\"Jira::Project/ABC\"]},"
                + "{\"group\":\"mcp-gitlab-grp-x\",\"scopes\":[\"Gitlab::Project/XYZ\"]},"
                + "{\"group\":\"mcp-team\",\"scopes\":[\"Jira::Project/DEF\",\"Gitlab::Project/UVW\"]}]");

        HttpResponse<String> jira = fetch(env.policyClientJiraTls);
        assertThat(jira.statusCode()).as(jira.body()).isEqualTo(200);
        JsonNode body = JSON.readTree(jira.body());
        assertThat(Contracts.gatewayAdminErrors("PolicyData", body)).isEmpty();
        assertThat(body.path("revision").asLong()).isPositive();
        assertThat(jira.headers().firstValue("ETag")).contains("\"" + body.path("revision").asLong() + "\"");
        List<String> clients = new ArrayList<>();
        body.path("allowedClients").forEach(c -> clients.add(c.asString()));
        assertThat(clients).containsExactly("claude-ai", "claude-code");
        assertThat(body.path("approvedPoliciesHash").asString()).isEqualTo(env.jira.manifest().path("policiesHash").asString());
        assertThat(body.path("scopeMapping").toString()).contains("Jira::Project/ABC", "Jira::Project/DEF").doesNotContain("Gitlab::");
        assertThat(body.path("scopeMapping").size()).as("the group that has only a scope of another system is left out").isEqualTo(2);

        JsonNode gitlab = JSON.readTree(fetch(env.policyClientGitlabTls).body());
        assertThat(gitlab.path("scopeMapping").toString()).contains("Gitlab::Project/XYZ", "Gitlab::Project/UVW").doesNotContain("Jira::");
        assertThat(gitlab.path("approvedPoliciesHash").asString()).isEqualTo(env.gitlab.manifest().path("policiesHash").asString());
        assertThat(gitlab.path("approvedPoliciesHash").asString()).as("the hash is the one of the asking server").isNotEqualTo(body.path("approvedPoliciesHash").asString());
    }

    @Test
    void theCertificateMustBeOfTheInternalCaAndNameARegisteredServer() throws Exception {
        assertThat(fetch(env.policyClientUnknownTls).statusCode()).as("a certificate of the CA whose CN is no serverId of the registry").isEqualTo(403);
        assertThat(fetch(env.otherComponentTls).statusCode()).as("mcp-registry-ci is no server").isEqualTo(403);
        assertThat(fetch(env.bffTls).statusCode()).as("the portal is no server").isEqualTo(403);
        assertThat(fetch(env.noClientCertificateTls).statusCode()).as("no certificate").isEqualTo(401);
        assertThat(fetch(env.foreignCaTls).statusCode()).as("another CA").isIn(401, 403);
        assertThat(fetch(env.policyClientServerOnlyTls).statusCode()).as("a certificate that is for servers to listen with, not to call with").isEqualTo(401);

        HttpResponse<String> publicPort = http.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/internal/v1/policy-data")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(publicPort.statusCode()).as("the public port knows no such path").isEqualTo(404);
    }

    @Test
    void aServerLearnsOfAChangeFromTheETagAndTheRevisionOfTheTokens() throws Exception {
        HttpResponse<String> first = fetch(env.policyClientJiraTls);
        String etag = etag(first);

        HttpResponse<String> unchanged = fetch(env.policyClientJiraTls, Map.of("If-None-Match", etag));
        assertThat(unchanged.statusCode()).isEqualTo(304);
        assertThat(unchanged.body()).isEmpty();

        putMapping("[{\"group\":\"mcp-jira-proj-ABC\",\"scopes\":[\"Jira::Project/ABC\"]}]");

        HttpResponse<String> changed = fetch(env.policyClientJiraTls, Map.of("If-None-Match", etag));
        assertThat(changed.statusCode()).isEqualTo(200);
        long before = JSON.readTree(first.body()).path("revision").asLong();
        long after = JSON.readTree(changed.body()).path("revision").asLong();
        assertThat(after).as("a counter that only rises").isGreaterThan(before);
        assertThat(etag(changed)).isEqualTo("\"" + after + "\"");

        String token = issuer.forService("mcp-jira", pl.aiwcorpo.mcp.gateway.jwt.UuidV7.next());
        assertThat(claims("Bearer " + token).path("prv").asLong()).as("the internal token carries the revision").isEqualTo(after);
        assertThat(claims("Bearer " + token).path("prv").isIntegralNumber()).isTrue();
    }

    @Test
    void anOverrideReachesTheServerItTargetsAndEveryServerButNeverTheGatewayOnes() throws Exception {
        putOverride("override-jira-no-delete", "mcp-jira", "forbid (principal, action == Jira::Action::\"delete\", resource);");
        putOverride("override-all-no-claude-ai", "all-servers", "forbid (principal, action, resource) when { context.client == \"claude-ai\" };");
        putOverride("override-gitlab-only", "mcp-gitlab", "forbid (principal, action == Gitlab::Action::\"update\", resource);");
        putOverride("override-gateway-no-get-issue", "gateway",
                "forbid (principal, action == Action::\"call\", resource is Tool) when { resource.name == \"drop_everything\" };");

        JsonNode jira = JSON.readTree(fetch(env.policyClientJiraTls).body());
        List<String> ids = new ArrayList<>();
        jira.path("overrides").forEach(o -> ids.add(o.path("id").asString()));
        assertThat(ids).containsExactly("override-all-no-claude-ai", "override-jira-no-delete");
        assertThat(jira.path("overrides").get(1).path("text").asString()).contains("Jira::Action");

        List<String> gitlab = new ArrayList<>();
        JSON.readTree(fetch(env.policyClientGitlabTls).body()).path("overrides").forEach(o -> gitlab.add(o.path("id").asString()));
        assertThat(gitlab).containsExactly("override-all-no-claude-ai", "override-gitlab-only");
    }
}
