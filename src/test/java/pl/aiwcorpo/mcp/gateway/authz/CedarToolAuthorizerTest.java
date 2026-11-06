package pl.aiwcorpo.mcp.gateway.authz;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import pl.aiwcorpo.mcp.cedar.entities.ResourceRef;
import pl.aiwcorpo.mcp.cedar.entities.ResourceTypes;
import pl.aiwcorpo.mcp.cedar.entities.ScopeMapping;
import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.policy.PolicyService;
import pl.aiwcorpo.mcp.gateway.server.CredentialPolicy;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.server.Risk;
import pl.aiwcorpo.mcp.gateway.server.ToolDefinition;
import pl.aiwcorpo.mcp.gateway.support.Fragments;
import pl.aiwcorpo.mcp.gateway.support.Snapshots;
import tools.jackson.databind.json.JsonMapper;

/** The decision on call: clients before Cedar, the cap on identifiers, data that cannot be used, the requirement of scopes for a write. */
class CedarToolAuthorizerTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final ResourceTypes TYPES = ResourceTypes.fromJson(Fragments.resourceTypes("jira").toString());
    private static final McpServer SERVER = new McpServer("mcp-jira", "jira", URI.create("https://mcp-jira.internal:8443/mcp"), "1.0.0", true,
            new CredentialPolicy(true, Set.of("user-secret"), List.of(), false, "user-secret"), Map.of());

    private static ToolDefinition tool(String name, Risk risk, String action, String type) {
        return new ToolDefinition(name, risk, action, null, "x", false, List.of(new ResourceRef("key", type)));
    }

    private static GatewayUser user(String client, String... groups) {
        return new GatewayUser("6f1c2a9e-4d4b-4c51-9a53-1e0f0c7d2b11", "alice", client, List.of(groups), "unused");
    }

    private static CedarToolAuthorizer authorizer(PolicyService.Snapshot snapshot) {
        return new CedarToolAuthorizer(Snapshots.source(snapshot), JSON);
    }

    private static PolicyService.Snapshot data(Map<String, List<String>> mapping, List<String> clients) {
        return Snapshots.of(5, TYPES, ScopeMapping.of(TYPES, mapping), Map.of(), clients);
    }

    private static tools.jackson.databind.JsonNode arguments(String key) {
        return JSON.createObjectNode().put("key", key);
    }

    @Test
    void onlyTheConfiguredClientsMayCallAndTheCheckComesBeforeCedar() {
        CedarToolAuthorizer authorizer = authorizer(data(Map.of(), List.of("claude-code")));
        ToolDefinition read = tool("get_issue", Risk.READ_ONLY, "read", "Jira::Issue");

        assertThat(authorizer.decide(user("claude-code", "mcp-jira-read"), SERVER, read, arguments("ABC-1")).allowed()).isTrue();
        ToolDecision other = authorizer.decide(user("claude-ai", "mcp-jira-read"), SERVER, read, arguments("ABC-1"));
        assertThat(other.allowed()).isFalse();
        assertThat(other.reason()).isEqualTo("not_granted");
        assertThat(authorizer.toolLevel(user("claude-ai", "mcp-jira-read"), SERVER, read).allowed()).as("nothing is listed for such a client").isFalse();
        assertThat(authorizer.forCatalog(user("mcp-portal-bff", "mcp-jira-read"), SERVER, read).allowed())
                .as("the portal's client name is not an AI client, the catalog asks as one that is allowed").isTrue();
    }

    @Test
    void aWriteNeedsTheScopesOfTheProjectItNamesAndTheGroupOfItsRisk() {
        CedarToolAuthorizer authorizer = authorizer(data(Map.of("mcp-jira-proj-ABC", List.of("Jira::Project/ABC")), List.of("claude-code")));
        ToolDefinition create = tool("create_issue", Risk.UPDATE, "update", "Jira::Project");

        assertThat(authorizer.decide(user("claude-code", "mcp-jira-write", "mcp-jira-proj-ABC"), SERVER, create, arguments("ABC")).allowed()).isTrue();
        ToolDecision outside = authorizer.decide(user("claude-code", "mcp-jira-write", "mcp-jira-proj-ABC"), SERVER, create, arguments("DEF"));
        assertThat(outside.allowed()).isFalse();
        assertThat(outside.reason()).isEqualTo("policy_forbid");
        assertThat(authorizer.decide(user("claude-code", "mcp-jira-proj-ABC"), SERVER, create, arguments("ABC")).reason())
                .as("the scope without the group of the risk grants nothing").isEqualTo("not_granted");
        assertThat(authorizer.decide(user("claude-code", "mcp-jira-write", "mcp-jira-proj-ABC"), SERVER, create, arguments("abc")).reason())
                .as("an identifier that is none of the declared type").isEqualTo("invalid_argument");
    }

    @Test
    void anIdentifierLongerThanTheCapIsRefusedBeforeAnyPatternSeesIt() {
        CedarToolAuthorizer authorizer = authorizer(data(Map.of(), List.of("claude-code")));
        ToolDefinition read = tool("get_issue", Risk.READ_ONLY, "read", "Jira::Issue");

        ToolDecision decision = authorizer.decide(user("claude-code", "mcp-jira-read"), SERVER, read, arguments("A".repeat(ResourceTypes.MAX_ID_LENGTH + 1)));

        assertThat(decision.allowed()).isFalse();
        assertThat(decision.reason()).isEqualTo("invalid_argument");
    }

    @Test
    void aToolWhoseServerHasNoApprovedTypesIsDecidedByTheGroupAtTheLevelOfTheTool() {
        CedarToolAuthorizer authorizer = new CedarToolAuthorizer(Snapshots.source(
                Snapshots.of(5, ResourceTypes.empty(), ScopeMapping.empty(), Map.of(), List.of("claude-code"))), JSON);
        ToolDefinition waiting = tool("get_issue", Risk.READ_ONLY, "read", "Jira::Issue");

        assertThat(authorizer.toolLevel(user("claude-code", "mcp-jira-read"), SERVER, waiting).allowed()).isTrue();
        assertThat(authorizer.toolLevel(user("claude-code"), SERVER, waiting).reason()).isEqualTo("not_granted");
        assertThat(authorizer.decide(user("claude-code", "mcp-jira-read"), SERVER, waiting, arguments("ABC-1")).reason())
                .as("with arguments the type has to be declared").isEqualTo("policy_error");
    }

    @Test
    void dataThatCannotBeUsedIsADenyAndDataThatWasNeverLoadedIsUnavailable() {
        PolicyService.Snapshot broken = new PolicyService.Snapshot(9, ResourceTypes.empty(), ScopeMapping.empty(), null, List.of("claude-code"),
                Map.of(), Map.of(), List.of(), "two servers declare Jira");
        ToolDefinition read = tool("get_issue", Risk.READ_ONLY, "read", "Jira::Issue");

        ToolDecision decision = authorizer(broken).toolLevel(user("claude-code", "mcp-jira-read"), SERVER, read);
        assertThat(decision.allowed()).isFalse();
        assertThat(decision.reason()).as("undecided, not denied for the user").isEqualTo("policy_error");

        PolicyService.Snapshot notLoaded = new PolicyService.Snapshot(0, ResourceTypes.empty(), ScopeMapping.empty(), null, List.of(), Map.of(),
                Map.of(), List.of(), "not loaded");
        assertThat(authorizer(notLoaded).toolLevel(user("claude-code", "mcp-jira-read"), SERVER, read).reason()).isEqualTo("policy_unavailable");
        assertThat(authorizer(notLoaded).policyRevision()).isZero();
        assertThat(authorizer(data(Map.of(), List.of("claude-code"))).policyRevision()).isEqualTo(5);
    }

    @Test
    void theGroupOfARiskIsDerivedInOnePlace() {
        CedarToolAuthorizer authorizer = authorizer(data(Map.of(), List.of("claude-code")));

        assertThat(authorizer.requiredEntitlements(SERVER, tool("a", Risk.READ_ONLY, "read", "Jira::Issue"))).containsExactly("mcp-jira-read");
        assertThat(authorizer.requiredEntitlements(SERVER, tool("a", Risk.UPDATE, "update", "Jira::Issue"))).containsExactly("mcp-jira-write");
        assertThat(authorizer.requiredEntitlements(SERVER, tool("a", Risk.DESTRUCTIVE, "delete", "Jira::Issue"))).containsExactly("mcp-jira-destructive");
    }
}
