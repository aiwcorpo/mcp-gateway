package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import pl.aiwcorpo.mcp.gateway.policy.PolicyService;
import pl.aiwcorpo.mcp.gateway.support.Contracts;
import pl.aiwcorpo.mcp.testserver.TestMcpServer;
import tools.jackson.databind.JsonNode;

/**
 * The policy data of a server (C14, CC-249): the gateway pushes it to every server after each change of the revision, only the scopes of
 * the namespace of that server go with it, and a tool call that meets a server which holds none (or older data) is answered by a push and
 * one repetition with a new token. {@code /internal/v1/policy-data}, which servers used to fetch, is gone.
 */
class PolicyDataPushTest extends GatewayTestBase {

    @Autowired
    PolicyService policies;

    @AfterEach
    void clean() {
        env.jira.failPolicyPush(false);
        jdbc.sql("UPDATE policy_state SET scope_mapping = '[]'::jsonb WHERE id = 1").update();
        jdbc.sql("DELETE FROM policy_overrides").update();
        policies.reload();
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

    /** The newest push that reached the server, after the test changed something (the revision it carries is at least {@code revision}). */
    private JsonNode pushedSince(TestMcpServer server, long revision) {
        List<JsonNode> found = new ArrayList<>();
        await().atMost(Duration.ofSeconds(10)).untilAsserted(() -> {
            found.clear();
            server.policyPushes().stream().filter(push -> push.status() == 200).map(push -> JSON.readTree(push.body()))
                    .filter(body -> body.path("revision").asLong() >= revision).forEach(found::add);
            assertThat(found).isNotEmpty();
        });
        return found.getLast();
    }

    private long revision() {
        return policies.snapshot().revision();
    }

    @Test
    void aServerGetsItsDataAndOnlyTheNamespaceOfItsOwn() throws Exception {
        putMapping("[{\"group\":\"mcp-jira-proj-ABC\",\"scopes\":[\"Jira::Project/ABC\"]},"
                + "{\"group\":\"mcp-gitlab-grp-x\",\"scopes\":[\"Gitlab::Project/XYZ\"]},"
                + "{\"group\":\"mcp-team\",\"scopes\":[\"Jira::Project/DEF\",\"Gitlab::Project/UVW\"]}]");
        long revision = revision();

        JsonNode jira = pushedSince(env.jira, revision);
        assertThat(Contracts.serverInterfaceErrors("PolicyData", jira)).isEmpty();
        assertThat(jira.path("revision").asLong()).isEqualTo(revision);
        List<String> clients = new ArrayList<>();
        jira.path("allowedClients").forEach(c -> clients.add(c.asString()));
        assertThat(clients).containsExactly("claude-ai", "claude-code");
        assertThat(jira.path("approvedPoliciesHash").asString()).isEqualTo(env.jira.manifest().path("policiesHash").asString());
        assertThat(jira.path("scopeMapping").toString()).contains("Jira::Project/ABC", "Jira::Project/DEF").doesNotContain("Gitlab::");
        assertThat(jira.path("scopeMapping").size()).as("the group that has only a scope of another system is left out").isEqualTo(2);

        JsonNode gitlab = pushedSince(env.gitlab, revision);
        assertThat(gitlab.path("scopeMapping").toString()).contains("Gitlab::Project/XYZ", "Gitlab::Project/UVW").doesNotContain("Jira::");
        assertThat(gitlab.path("approvedPoliciesHash").asString()).isEqualTo(env.gitlab.manifest().path("policiesHash").asString());
        assertThat(gitlab.path("approvedPoliciesHash").asString()).as("the hash is the one of the receiving server")
                .isNotEqualTo(jira.path("approvedPoliciesHash").asString());
    }

    @Test
    void theTokenOfAPushIsOfTheRightPurposeAndCarriesTheRevisionOfTheBody() throws Exception {
        putMapping("[{\"group\":\"mcp-jira-proj-ABC\",\"scopes\":[\"Jira::Project/ABC\"]}]");
        long revision = revision();
        pushedSince(env.jira, revision);

        TestMcpServer.RecordedRequest push = env.jira.policyPushes().stream().filter(p -> p.status() == 200
                && JSON.readTree(p.body()).path("revision").asLong() == revision).findFirst().orElseThrow();
        JsonNode claims = claims(push.header("authorization"));
        assertThat(claims.path("use").asString()).isEqualTo("policy-data");
        assertThat(claims.path("prv").asLong()).as("the revision of the body").isEqualTo(revision);
        assertThat(claims.path("aud").asString()).isEqualTo("mcp-jira");
        assertThat(claims.path("sub").asString()).isEqualTo("system:mcp-gateway");
        assertThat(claims.has("tool")).isFalse();
        assertThat(push.header("x-request-id")).isEqualTo(claims.path("rid").asString());
    }

    @Test
    void aPushFollowsEveryChangeOfTheRevision() throws Exception {
        long before = revision();
        putMapping("[{\"group\":\"mcp-jira-proj-ABC\",\"scopes\":[\"Jira::Project/ABC\"]}]");
        long first = revision();
        assertThat(first).isGreaterThan(before);
        pushedSince(env.jira, first);

        putOverride("override-jira-no-delete", "mcp-jira", "forbid (principal, action == Jira::Action::\"delete\", resource);");
        long second = revision();
        assertThat(second).as("a counter that only rises").isGreaterThan(first);

        JsonNode pushed = pushedSince(env.jira, second);
        assertThat(pushed.path("revision").asLong()).isEqualTo(second);
        assertThat(env.jira.heldRevision()).isGreaterThanOrEqualTo(second);
    }

    @Test
    void anOverrideReachesTheServerItTargetsAndEveryServerButNeverTheGatewayOnes() throws Exception {
        putOverride("override-jira-no-delete", "mcp-jira", "forbid (principal, action == Jira::Action::\"delete\", resource);");
        putOverride("override-all-no-claude-ai", "all-servers", "forbid (principal, action, resource) when { context.client == \"claude-ai\" };");
        putOverride("override-gitlab-only", "mcp-gitlab", "forbid (principal, action == Gitlab::Action::\"update\", resource);");
        putOverride("override-gateway-no-get-issue", "gateway",
                "forbid (principal, action == Action::\"call\", resource is Tool) when { resource.name == \"drop_everything\" };");
        long revision = revision();

        List<String> jira = new ArrayList<>();
        pushedSince(env.jira, revision).path("overrides").forEach(o -> jira.add(o.path("id").asString()));
        assertThat(jira).containsExactly("override-all-no-claude-ai", "override-jira-no-delete");

        List<String> gitlab = new ArrayList<>();
        pushedSince(env.gitlab, revision).path("overrides").forEach(o -> gitlab.add(o.path("id").asString()));
        assertThat(gitlab).containsExactly("override-all-no-claude-ai", "override-gitlab-only");
    }

    @Test
    void aServerThatLostItsDataIsPushedToAndTheCallRepeatedOnceWithANewToken() throws Exception {
        assertThat(toolError(callGetIssue(aliceToken())).path("error").asString()).isEmpty();
        env.jira.forgetPolicyData();
        env.jira.clearRequests();

        HttpResponse<String> call = callGetIssue(aliceToken());

        assertThat(toolError(call).path("error").asString()).as("the client sees a call that worked: " + call.body()).isEmpty();
        List<TestMcpServer.RecordedRequest> calls = env.jira.requests().stream().filter(r -> "tools/call".equals(r.rpcMethod())).toList();
        assertThat(calls).extracting(TestMcpServer.RecordedRequest::status).as("refused as stale, then served").containsExactly(409, 200);
        assertThat(claims(calls.get(0).header("authorization")).path("jti").asString())
                .as("the first token is spent: the repetition has a new one")
                .isNotEqualTo(claims(calls.get(1).header("authorization")).path("jti").asString());
        assertThat(calls.get(0).rejectReason()).isEqualTo("policy_data_stale");
        assertThat(env.jira.policyPushes()).as("the gateway pushed in between").anyMatch(push -> push.status() == 200);
        assertThat(env.jira.heldRevision()).isGreaterThanOrEqualTo(revision());
    }

    @Test
    void whenThePushDoesNotReachTheServerTheClientGetsUpstreamUnavailableAfterTheOneRepetition() throws Exception {
        assertThat(toolError(callGetIssue(aliceToken())).path("error").asString()).isEmpty();
        env.jira.forgetPolicyData();
        env.jira.failPolicyPush(true);
        env.jira.clearRequests();

        JsonNode error = toolError(callGetIssue(aliceToken()));

        assertThat(error.path("error").asString()).isEqualTo("upstream_unavailable");
        assertThat(env.jira.requests().stream().filter(r -> "tools/call".equals(r.rpcMethod())).map(TestMcpServer.RecordedRequest::status))
                .as("refused, a push that did not arrive, refused again: no third attempt").containsExactly(409, 409);

        env.jira.failPolicyPush(false);
        await().atMost(Duration.ofSeconds(15)).untilAsserted(() ->
                assertThat(toolError(callGetIssue(aliceToken())).path("error").asString()).as("the next call pushes again").isEmpty());
    }

    @Test
    void aServerThatIsStillStaleAfterThePushIsNotAskedAThirdTime() throws Exception {
        assertThat(toolError(callGetIssue(aliceToken())).path("error").asString()).isEmpty();
        env.jira.forgetPolicyData();
        // Data that is current for the push but ignored by the server: it holds an older revision than the token asks for.
        env.jira.holdPolicyDataBehind();
        env.jira.clearRequests();
        try {
            JsonNode error = toolError(callGetIssue(aliceToken()));

            assertThat(error.path("error").asString()).isEqualTo("upstream_unavailable");
            assertThat(env.jira.requests().stream().filter(r -> "tools/call".equals(r.rpcMethod())).map(TestMcpServer.RecordedRequest::status))
                    .as("a second 409 ends it").containsExactly(409, 409);
        } finally {
            env.jira.holdPolicyDataBehind(false);
        }
    }

    @Test
    void thePolicyDataOfServersIsNoLongerServedByTheGateway() throws Exception {
        for (String base : List.of("http://localhost:" + port, "https://localhost:" + env.internalPort)) {
            HttpResponse<String> response = java.net.http.HttpClient.newBuilder().sslContext(env.serverIdentityTls).build().send(
                    HttpRequest.newBuilder(URI.create(base + "/internal/v1/policy-data")).GET().build(), HttpResponse.BodyHandlers.ofString());
            assertThat(response.statusCode()).as(base).isIn(401, 403, 404);
            assertThat(response.body()).doesNotContain("scopeMapping");
        }
    }
}
