package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.system.CapturedOutput;

import pl.aiwcorpo.mcp.gateway.support.BrokerStub;
import pl.aiwcorpo.mcp.gateway.support.Contracts;
import pl.aiwcorpo.mcp.gateway.support.GatewayTestEnvironment;
import pl.aiwcorpo.mcp.testserver.TestMcpServer;
import tools.jackson.databind.JsonNode;

/** MCP clients on {@code /v/<slug>/mcp}: a link filters, owns, and never grants (invariant 5). */
class VirtualServerMcpTest extends GatewayTestBase {

    private static final String CALL_GET_ISSUE = "{\"name\":\"jira__get_issue\",\"arguments\":{\"issueKey\":\"ABC-1\"}}";
    private static final List<String> WITH_GITLAB = List.of("mcp-jira-read", "mcp-jira-write", "mcp-gitlab-read");
    private static final List<String> BOB_ALL = List.of("mcp-jira-read", "mcp-jira-write", "mcp-gitlab-read");

    @Test
    void linkListsOnlyItsToolsAcrossServers() throws Exception {
        link("mixed", WITH_GITLAB, List.of("jira__get_issue", "gitlab__get_issue"));
        HttpResponse<String> list = sendVirtual(aliceTokenWith("mcp-jira-read", "mcp-gitlab-read"), "mixed", "tools/list", null, "{}");
        assertThat(list.statusCode()).isEqualTo(200);
        assertThat(names(list)).containsExactlyInAnyOrder("jira__get_issue", "gitlab__get_issue");

        assertThat(names(sendVirtual(aliceToken(), "mixed", "tools/list", null, "{}")))
                .as("gitlab is not in Alice's groups").containsExactly("jira__get_issue");
    }

    @Test
    void callThroughTheLinkCarriesVsAndAnEmptyVscToTheServer(CapturedOutput output) throws Exception {
        link("team-a-dev", List.of("jira__get_issue", "jira__search_issues"));
        HttpResponse<String> call = sendVirtual(aliceToken(), "team-a-dev", "tools/call", "jira__get_issue", CALL_GET_ISSUE);
        assertThat(JSON.readTree(call.body()).path("result").path("isError").asBoolean()).isFalse();
        String rid = call.headers().firstValue("X-Request-Id").orElseThrow();

        TestMcpServer.RecordedRequest atServer = env.jira.requests().stream()
                .filter(r -> "tools/call".equals(r.rpcMethod())).reduce((a, b) -> b).orElseThrow();
        assertThat(atServer.status()).isEqualTo(200);
        JsonNode claims = claims(atServer.header("authorization"));
        assertThat(claims.path("vs").asString()).isEqualTo("team-a-dev");
        assertThat(claims.path("vsc").isObject()).isTrue();
        assertThat(claims.path("vsc").isEmpty()).as("resource narrowing is dormant").isTrue();
        assertThat(claims.path("tool").asString()).isEqualTo("get_issue");
        assertThat(Contracts.schemaErrors("schemas/internal-jwt.schema.json", claims)).isEmpty();
        for (TestMcpServer.RecordedRequest request : env.jira.requests()) {
            assertThat(claims(request.header("authorization")).path("vs").asString()).as(request.rpcMethod())
                    .isEqualTo("team-a-dev");
        }

        List<JsonNode> events = auditEvents(output, rid);
        assertThat(events).hasSize(2).allSatisfy(e -> {
            assertThat(e.path("virtualServer").asString()).isEqualTo("team-a-dev");
            assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", e)).isEmpty();
        });

        sendModern(aliceToken(), "tools/call", "jira__get_issue", CALL_GET_ISSUE);
        TestMcpServer.RecordedRequest direct = lastToolCall(env.jira);
        assertThat(claims(direct.header("authorization")).has("vs")).as("a full server call has no vs").isFalse();
        assertThat(claims(direct.header("authorization")).has("vsc")).isFalse();
    }

    @Test
    void toolOutsideTheLinkIsNotAvailableEvenThoughTheUserMayCallIt() throws Exception {
        link("narrow", List.of("jira__get_issue"));
        HttpResponse<String> call = sendVirtual(aliceToken(), "narrow", "tools/call", "jira__search_issues",
                "{\"name\":\"jira__search_issues\",\"arguments\":{\"project\":\"ABC\"}}");
        assertThat(toolError(call).path("error").asString()).isEqualTo("tool_disabled");
        assertThat(env.jira.requests()).noneMatch(r -> "tools/call".equals(r.rpcMethod()));
        assertThat(resolveCount()).isZero();
        assertThat(toolError(sendVirtual(aliceToken(), "narrow", "tools/call", "gitlab__get_issue",
                "{\"name\":\"gitlab__get_issue\",\"arguments\":{\"issueKey\":\"ABC-1\"}}")).path("error").asString())
                .isEqualTo("tool_disabled");
        assertThat(toolError(sendVirtual(aliceToken(), "narrow", "tools/call", "jira__nope", "{\"name\":\"jira__nope\",\"arguments\":{}}"))
                .path("error").asString()).isEqualTo("tool_disabled");
        assertThat(env.jira.requests()).noneMatch(r -> "tools/call".equals(r.rpcMethod()));
    }

    @Test
    void linkNeverKeepsAPermissionTheUserLost(CapturedOutput output) throws Exception {
        link("lost-right", WITH_GITLAB, List.of("jira__get_issue", "gitlab__get_issue"));
        String gitlabBody = "{\"name\":\"gitlab__get_issue\",\"arguments\":{\"issueKey\":\"ABC-1\"}}";
        String stillAllowed = aliceTokenWith("mcp-jira-read", "mcp-gitlab-read");
        String readOnlyJira = aliceTokenWith("mcp-jira-read");

        assertThat(names(sendVirtual(stillAllowed, "lost-right", "tools/list", null, "{}")))
                .containsExactlyInAnyOrder("jira__get_issue", "gitlab__get_issue");
        assertThat(names(sendVirtual(readOnlyJira, "lost-right", "tools/list", null, "{}"))).containsExactly("jira__get_issue");

        env.broker.clear();
        env.gitlab.clearRequests();
        HttpResponse<String> call = sendVirtual(readOnlyJira, "lost-right", "tools/call", "gitlab__get_issue", gitlabBody);
        JsonNode error = toolError(call);
        assertThat(error.path("error").asString()).isEqualTo("access_denied");
        assertThat(error.path("requiredEntitlements").toString()).isEqualTo("[\"mcp-gitlab-read\"]");
        assertThat(resolveCount()).isZero();
        assertThat(env.gitlab.requests()).noneMatch(r -> "tools/call".equals(r.rpcMethod()));
        assertThat(auditEvents(output, call.headers().firstValue("X-Request-Id").orElseThrow())).anySatisfy(e -> {
            assertThat(e.path("event").asString()).isEqualTo("tool_call");
            assertThat(e.path("decision").asString()).isEqualTo("deny");
            assertThat(e.path("virtualServer").asString()).isEqualTo("lost-right");
        });

        String noGroups = env.idp.token(ALICE_SUB, "alice", List.of());
        assertThat(names(sendVirtual(noGroups, "lost-right", "tools/list", null, "{}"))).isEmpty();
        assertThat(toolError(sendVirtual(noGroups, "lost-right", "tools/call", "jira__get_issue", CALL_GET_ISSUE)).path("error")
                .asString()).isEqualTo("access_denied");
    }

    @Test
    void linkCannotBeCreatedWithAToolTheUserMayNotCallAndTheServerOwnsNoShortcut() throws Exception {
        HttpResponse<String> created = createLink(ALICE_SUB, "alice", ALICE_GROUPS, "escalate", "x",
                List.of("jira__get_issue", "gitlab__get_issue"));
        assertThat(created.statusCode()).isEqualTo(403);
        assertThat(sendVirtual(aliceTokenWith("mcp-gitlab-read"), "escalate", "tools/list", null, "{}").statusCode()).isEqualTo(404);
    }

    @Test
    void someoneElsesSlugIsNotFoundForEveryMethodAndEra() throws Exception {
        link("alice-only", List.of("jira__get_issue"));
        String bob = env.idp.token(BOB_SUB, "bob", BOB_ALL);

        for (String missing : List.of("alice-only", "no-such-link")) {
            assertThat(sendVirtual(bob, missing, "tools/list", null, "{}").statusCode()).as(missing).isEqualTo(404);
            assertThat(sendVirtual(bob, missing, "tools/call", "jira__get_issue", CALL_GET_ISSUE).statusCode()).isEqualTo(404);
            assertThat(send(bob, "/v/" + missing + "/mcp", initializeBody("2025-11-25"), Map.of()).statusCode()).isEqualTo(404);
            HttpResponse<String> delete = http.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/v/" + missing + "/mcp"))
                    .header("Authorization", "Bearer " + bob).header("Mcp-Session-Id", "x".repeat(32)).DELETE().build(),
                    HttpResponse.BodyHandlers.ofString());
            assertThat(delete.statusCode()).isEqualTo(404);
        }
        assertThat(sendVirtual(bob, "alice-only", "tools/list", null, "{}").body())
                .as("the same body as for a slug that does not exist")
                .isEqualTo(sendVirtual(bob, "no-such-link", "tools/list", null, "{}").body());
        assertThat(env.jira.requests()).isEmpty();
        assertThat(resolveCount()).isZero();
    }

    @Test
    void slugsOutsideThePatternAreNotFoundWithoutTouchingTheStore() throws Exception {
        link("fine", List.of("jira__get_issue"));
        List<String> slugs = List.of("Fine", "FINE", "fine_x", "-fine", "fine-", "%2e%2e", "..", "fine%0Ax",
                "fine%20", "a'%20OR%20'1'='1", "fine;x", "x".repeat(64), "%C5%82", "fine%00");
        for (String slug : slugs) {
            HttpResponse<String> response = send(aliceToken(), "/v/" + slug + "/mcp", initializeBody(), Map.of());
            assertThat(response.statusCode()).as(slug).isIn(400, 404);
            assertThat(response.body()).as(slug).doesNotContain("result");
        }
        assertThat(env.jira.requests()).isEmpty();
    }

    @Test
    void deletedLinkStopsWorkingAtOnceAndLegacySessionsWorkOnTheLink() throws Exception {
        link("session-link", List.of("jira__get_issue"));
        String token = aliceToken();
        HttpResponse<String> init = send(token, "/v/session-link/mcp", initializeBody("2025-11-25"), Map.of());
        assertThat(init.statusCode()).isEqualTo(200);
        assertThat(JSON.readTree(init.body()).path("result").path("serverInfo").path("name").asString())
                .isEqualTo("mcp-gateway/vs/session-link");
        String session = init.headers().firstValue("Mcp-Session-Id").orElseThrow();
        Map<String, String> headers = Map.of("Mcp-Session-Id", session, "MCP-Protocol-Version", "2025-11-25");
        assertThat(send(token, "/v/session-link/mcp", "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}", headers)
                .statusCode()).isEqualTo(202);
        HttpResponse<String> list = send(token, "/v/session-link/mcp", "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}", headers);
        assertThat(names(list)).containsExactly("jira__get_issue");

        assertThat(admin("DELETE", "/admin/v1/virtual-servers/session-link", ALICE_SUB, "alice", ALICE_GROUPS, null).statusCode())
                .isEqualTo(204);
        assertThat(send(token, "/v/session-link/mcp", "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/list\"}", headers)
                .statusCode()).isEqualTo(404);
    }

    @Test
    void oneFailingServerOfALinkDoesNotHideTheOthersButAllFailingIsAnError() throws Exception {
        link("jira-and-confluence", List.of("jira__get_issue", "confluence__search_issues"));
        link("confluence-only", List.of("confluence__search_issues"));
        String token = aliceToken();

        HttpResponse<String> partial = sendVirtual(token, "jira-and-confluence", "tools/list", null, "{}");
        assertThat(partial.statusCode()).isEqualTo(200);
        assertThat(names(partial)).containsExactly("jira__get_issue");

        HttpResponse<String> allFailing = sendVirtual(token, "confluence-only", "tools/list", null, "{}");
        assertThat(JSON.readTree(allFailing.body()).path("error").path("code").asInt()).isEqualTo(-32603);
    }

    @Test
    void credentialRequiredThroughALinkPointsToThePortalOnThePublicOrigin() throws Exception {
        link("needs-pat", List.of("jira__get_issue"));
        env.broker.mode(BrokerStub.Mode.REQUIRED);
        HttpResponse<String> call = sendVirtual(aliceToken(), "needs-pat", "tools/call", "jira__get_issue", CALL_GET_ISSUE);
        JsonNode error = toolError(call);
        assertThat(error.path("error").asString()).isEqualTo("credential_required");
        assertThat(error.path("connectUrl").asString()).isEqualTo(GatewayTestEnvironment.PUBLIC_URL + "/connections?system=jira");
        assertThat(Contracts.schemaErrors("schemas/tool-error.schema.json", error)).isEmpty();
        assertThat(env.jira.requests()).noneMatch(r -> "tools/call".equals(r.rpcMethod()));
    }

    @Test
    void connectUrlIgnoresTheBrokersUrl() throws Exception {
        env.broker.mode(BrokerStub.Mode.REQUIRED);
        HttpResponse<String> call = sendModern(aliceToken(), "/s/mcp-jira/mcp", "tools/call", "jira__get_issue", CALL_GET_ISSUE);
        assertThat(toolError(call).path("connectUrl").asString()).isEqualTo(GatewayTestEnvironment.PUBLIC_URL + "/connections?system=jira");
        assertThat(call.body()).doesNotContain("localhost:18090");
    }

    private void link(String slug, List<String> tools) throws Exception {
        link(slug, ALICE_GROUPS, tools);
    }

    private void link(String slug, List<String> creatorGroups, List<String> tools) throws Exception {
        HttpResponse<String> created = createLink(ALICE_SUB, "alice", creatorGroups, slug, "Link " + slug, tools);
        assertThat(created.statusCode()).as(created.body()).isEqualTo(201);
    }

    private String aliceTokenWith(String... groups) {
        return env.idp.token(ALICE_SUB, "alice", List.of(groups));
    }

    private static List<String> names(HttpResponse<String> response) {
        List<String> names = new ArrayList<>();
        JSON.readTree(response.body()).path("result").path("tools").forEach(t -> names.add(t.path("name").asString()));
        return names;
    }
}
