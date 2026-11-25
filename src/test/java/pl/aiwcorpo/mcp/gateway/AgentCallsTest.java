package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.system.CapturedOutput;

import com.nimbusds.jwt.JWTClaimsSet;

import pl.aiwcorpo.mcp.gateway.agent.AgentClient;
import pl.aiwcorpo.mcp.gateway.agent.AgentRegistry;
import pl.aiwcorpo.mcp.gateway.agent.AgentStore;
import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.authz.AgentCeilingAuthorizer;
import pl.aiwcorpo.mcp.gateway.registry.DefinitionGuard;
import pl.aiwcorpo.mcp.gateway.server.CredentialPolicy;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.server.ToolDefinition;
import pl.aiwcorpo.mcp.gateway.server.Risk;
import pl.aiwcorpo.mcp.gateway.support.Contracts;
import tools.jackson.databind.JsonNode;

/**
 * An autonomous agent through the real gateway (CC-266, CC-261, CC-263): recognised from the registry, its groups cut to the ceiling, the
 * ceiling of risk in the list and at the call, the refusal of a suspended agent and of a call that needs a confirmation or a credential
 * (until the principal type is emitted). Nothing about an agent is sent to a server or to the broker yet.
 */
class AgentCallsTest extends GatewayTestBase {

    private static final String CLIENT = "agent-reports";
    private static final String SERVICE_ACCOUNT = "7d0f3c1e-2b64-4a8e-9a0b-5c1f6e2d8a47";
    private static final String OWNER = "4c7d1e90-5a2b-4e63-8f14-b2a9d0c6e358";
    private static final List<String> CEILING = List.of("mcp-jira-read", "mcp-jira-write");
    private static final List<String> TOKEN_GROUPS = List.of("mcp-jira-read", "mcp-jira-write", "mcp-jira-destructive", "mcp-jira-proj-ABC");

    @Autowired
    AgentStore store;

    @Autowired
    AgentRegistry registry;

    @Autowired
    DefinitionGuard definitions;

    @BeforeEach
    void serveTheUpdateTool() {
        env.jira.updateTool(true);
        definitions.forget("mcp-jira");
        register(Risk.READ_ONLY, null);
    }

    @AfterEach
    void removeTheAgents() {
        env.jira.updateTool(false);
        definitions.forget("mcp-jira");
        jdbc.sql("DELETE FROM agent_clients").update();
        registry.refresh();
    }

    private void register(Risk maxRisk, AgentClient.Suspension suspension) {
        jdbc.sql("DELETE FROM agent_clients").update();
        store.insert(new AgentClient(CLIENT, SERVICE_ACCOUNT, OWNER, maxRisk, CEILING, false, ADMIN_SUB, Instant.now(), null, null));
        if (suspension != null) {
            store.suspend(CLIENT, suspension.by(), suspension.at(), suspension.reason());
        }
        registry.refresh();
    }

    private String agentToken(String azp, String sub, boolean marker, long lifetimeSeconds) {
        Instant now = Instant.now();
        JWTClaimsSet.Builder claims = env.idp.validClaims(sub, "service-account-" + azp).claim("azp", azp).claim("groups", TOKEN_GROUPS)
                .issueTime(Date.from(now)).expirationTime(Date.from(now.plusSeconds(lifetimeSeconds)));
        if (marker) {
            claims.claim("principal_type", "agent");
        }
        return env.idp.sign(claims.build());
    }

    private String agentToken() {
        return agentToken(CLIENT, SERVICE_ACCOUNT, true, 300);
    }

    private List<String> listed(String token) throws Exception {
        HttpResponse<String> response = sendModern(token, "/mcp", "tools/list", null, "{}");
        assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
        return JSON.readTree(response.body()).path("result").path("tools").valueStream().map(t -> t.path("name").asString()).toList();
    }

    private JsonNode call(String token, String tool, String arguments) throws Exception {
        HttpResponse<String> response = sendModern(token, "/mcp", "tools/call", tool, "{\"name\":\"" + tool + "\",\"arguments\":" + arguments + "}");
        assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
        return JSON.readTree(response.body());
    }

    private static List<JsonNode> events(CapturedOutput output, String reason) {
        return output.getOut().lines().filter(l -> l.startsWith("{") && l.contains("\"reason\":\"" + reason + "\"")).map(l -> JSON.readTree(l)).toList();
    }

    @Test
    void anActiveAgentListsWhatItsCeilingOfRiskAndOfGroupsLeaves() throws Exception {
        assertThat(listed(agentToken())).as("READ_ONLY only: the group of DESTRUCTIVE is cut, the UPDATE tool is above maxRisk")
                .contains("jira__get_issue", "jira__search_issues").doesNotContain("jira__add_comment", "jira__delete_issue");

        register(Risk.UPDATE, null);

        assertThat(listed(agentToken())).as("the next request sees the new ceiling").contains("jira__get_issue", "jira__add_comment")
                .doesNotContain("jira__delete_issue");
        assertThat(listed(aliceToken())).as("a human of the same groups is not limited").contains("jira__get_issue", "jira__search_issues");
    }

    @Test
    void aToolAboveMaxRiskIsNotFoundOrDeniedAndNeverReachesTheBrokerOrTheServer(CapturedOutput output) throws Exception {
        env.broker.clear();
        env.jira.clearRequests();

        JsonNode answer = toolError(sendModern(agentToken(), "/mcp", "tools/call", "jira__add_comment",
                "{\"name\":\"jira__add_comment\",\"arguments\":{\"issueKey\":\"ABC-1\",\"comment\":\"x\"}}"));

        assertThat(answer.path("error").asString()).isEqualTo("not_found_or_denied");
        assertThat(env.broker.received()).isEmpty();
        assertThat(env.jira.requests()).noneMatch(r -> "tools/call".equals(r.rpcMethod()));
        JsonNode event = events(output, "agent_max_risk").stream().filter(e -> "tool_call".equals(e.path("event").asString())).findFirst().orElseThrow();
        assertThat(event.path("principalType").asString()).isEqualTo("agent");
        assertThat(event.path("agentOwner").asString()).isEqualTo(OWNER);
        assertThat(event.path("client").asString()).isEqualTo(CLIENT);
        assertThat(event.path("errorCode").asString()).isEqualTo("not_found_or_denied");
        assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", event)).isEmpty();
        assertThat(toolError(sendModern(agentToken(), "/mcp", "tools/call", "jira__no_such_tool", "{\"name\":\"jira__no_such_tool\",\"arguments\":{}}"))
                .path("message").asString()).as("the same text for a tool that does not exist").isEqualTo(answer.path("message").asString());
    }

    @Test
    void anUpdateToolOfAnAgentThatMayCallItEndsAsAccessDeniedBeforeTheBroker(CapturedOutput output) throws Exception {
        register(Risk.UPDATE, null);
        env.broker.clear();
        env.jira.clearRequests();

        JsonNode answer = toolError(sendModern(agentToken(), "/mcp", "tools/call", "jira__add_comment",
                "{\"name\":\"jira__add_comment\",\"arguments\":{\"issueKey\":\"ABC-1\",\"comment\":\"x\"}}"));

        assertThat(answer.path("error").asString()).isEqualTo("access_denied");
        assertThat(Contracts.schemaErrors("schemas/tool-error.schema.json", answer)).isEmpty();
        assertThat(env.broker.received()).as("no credential, no authenticator, no confirmation").isEmpty();
        assertThat(env.jira.requests()).noneMatch(r -> "tools/call".equals(r.rpcMethod()));
        List<JsonNode> refusals = events(output, "principal_not_eligible");
        assertThat(refusals).extracting(e -> e.path("event").asString()).contains("policy_decision", "tool_call");
        assertThat(refusals).allSatisfy(e -> assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", e)).isEmpty());
    }

    @Test
    void aToolThatNeedsACredentialIsRefusedToAnAgentBeforeTheBrokerUntilThePrincipalTypeIsEmitted(CapturedOutput output) throws Exception {
        env.broker.clear();
        env.jira.clearRequests();

        JsonNode answer = toolError(sendModern(agentToken(), "/mcp", "tools/call", "jira__get_issue",
                "{\"name\":\"jira__get_issue\",\"arguments\":{\"issueKey\":\"ABC-1\"}}"));

        assertThat(answer.path("error").asString()).isEqualTo("access_denied");
        assertThat(env.broker.received()).as("the broker would take the agent for a person: no pty is sent yet").isEmpty();
        assertThat(env.jira.requests()).noneMatch(r -> "tools/call".equals(r.rpcMethod()));
        List<JsonNode> refusals = events(output, "principal_not_eligible");
        assertThat(refusals).isNotEmpty().allSatisfy(e -> {
            assertThat(e.path("principalType").asString()).isEqualTo("agent");
            assertThat(e.path("agentOwner").asString()).isEqualTo(OWNER);
            assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", e)).isEmpty();
        });
    }

    @Test
    void aToolWithoutACredentialIsStillOpenToAnAgentAndAPersonIsNeverAffected() {
        McpServer open = new McpServer("mcp-open", "open", java.net.URI.create("https://mcp-open.internal:8443/mcp"), "1.0.0", true,
                new CredentialPolicy(false, Set.of(), List.of(), false, null), Map.of());
        McpServer needs = new McpServer("mcp-needs", "needs", java.net.URI.create("https://mcp-needs.internal:8443/mcp"), "1.0.0", true,
                new CredentialPolicy(true, Set.of("user-secret"), List.of(), false, "user-secret"), Map.of());
        ToolDefinition read = new ToolDefinition("get_thing", Risk.READ_ONLY, "read", null, "x", false, List.of());
        ToolDefinition update = new ToolDefinition("set_thing", Risk.UPDATE, "update", null, "x", false, List.of());
        GatewayUser agent = new GatewayUser("sa", "svc", CLIENT, List.of(), "t", new GatewayUser.Agent(CLIENT, OWNER));
        GatewayUser person = new GatewayUser("p", "alice", "claude-code", List.of(), "t");

        assertThat(AgentCeilingAuthorizer.eligible(agent, open, read)).isTrue();
        assertThat(AgentCeilingAuthorizer.eligible(agent, needs, read)).isFalse();
        assertThat(AgentCeilingAuthorizer.eligible(agent, open, update)).as("no authenticator to confirm with").isFalse();
        assertThat(AgentCeilingAuthorizer.eligible(person, needs, update)).isTrue();
    }

    @Test
    void aSuspendedAgentIsRefusedWhateverItAsksForAndTheAnswerDoesNotTellWhichToolsExist(CapturedOutput output) throws Exception {
        register(Risk.UPDATE, new AgentClient.Suspension(OWNER, Instant.now(), "Unexpected volume of calls"));
        env.broker.clear();
        env.jira.clearRequests();
        String token = agentToken();

        assertThat(listed(token)).isEmpty();
        JsonNode existing = toolError(sendModern(token, "/mcp", "tools/call", "jira__get_issue",
                "{\"name\":\"jira__get_issue\",\"arguments\":{\"issueKey\":\"ABC-1\"}}"));
        JsonNode missing = toolError(sendModern(token, "/mcp", "tools/call", "jira__no_such_tool", "{\"name\":\"jira__no_such_tool\",\"arguments\":{}}"));

        assertThat(existing.path("error").asString()).isEqualTo("access_denied");
        assertThat(missing).isEqualTo(existing);
        assertThat(env.broker.received()).isEmpty();
        assertThat(env.jira.requests()).noneMatch(r -> "tools/call".equals(r.rpcMethod()));
        List<JsonNode> refusals = events(output, "agent_suspended");
        assertThat(refusals).isNotEmpty().allSatisfy(e -> {
            assertThat(e.path("principalType").asString()).isEqualTo("agent");
            assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", e)).isEmpty();
        });
        assertThat(output.getOut()).doesNotContain("Unexpected volume of calls");

        register(Risk.READ_ONLY, null);
        assertThat(listed(token)).as("lifted: the same token works again").contains("jira__get_issue");
    }

    @Test
    void aTokenThatHalfFitsAnAgentIs401AndAuditedAsAnAuthenticationEvent(CapturedOutput output) throws Exception {
        String unknown = agentToken("agent-unknown", SERVICE_ACCOUNT, true, 300);
        String withoutMarker = agentToken(CLIENT, SERVICE_ACCOUNT, false, 300);
        String otherSub = agentToken(CLIENT, UUID.randomUUID().toString(), true, 300);
        String tooLong = agentToken(CLIENT, SERVICE_ACCOUNT, true, 301);
        String humanWithMarker = agentToken("claude-code", SERVICE_ACCOUNT, true, 300);

        for (String[] refused : new String[][] {{unknown, "agent_not_registered"}, {withoutMarker, "agent_not_registered"},
                {otherSub, "agent_not_registered"}, {tooLong, "agent_token_lifetime"}, {humanWithMarker, "agent_not_registered"}}) {
            HttpResponse<String> response = sendModern(refused[0], "/mcp", "tools/list", null, "{}");
            assertThat(response.statusCode()).as(refused[1]).isEqualTo(401);
            assertThat(response.headers().firstValue("WWW-Authenticate")).isPresent();
            String requestId = response.headers().firstValue("X-Request-Id").orElseThrow();
            List<JsonNode> logged = auditEvents(output, requestId);
            assertThat(logged).hasSize(1);
            assertThat(logged.getFirst().path("event").asString()).isEqualTo("authentication");
            assertThat(logged.getFirst().path("reason").asString()).isEqualTo(refused[1]);
            assertThat(logged.getFirst().has("principalType")).as("the token is not trusted yet").isFalse();
            assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", logged.getFirst())).isEmpty();
        }
    }

    @Test
    void anAgentThatWasRemovedIsRefusedAtTheNextRequestAndHumansDoNotNeedTheRegistry() throws Exception {
        String token = agentToken();
        assertThat(listed(token)).isNotEmpty();

        jdbc.sql("DELETE FROM agent_clients").update();
        registry.refresh();

        assertThat(sendModern(token, "/mcp", "tools/list", null, "{}").statusCode()).isEqualTo(401);
        assertThat(listed(aliceToken())).isNotEmpty();
    }
}
