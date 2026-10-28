package pl.aiwcorpo.mcp.gateway.authz;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.server.CredentialPolicy;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.server.Risk;
import pl.aiwcorpo.mcp.gateway.server.ToolDefinition;

class GroupToolAuthorizerTest {

    private final GroupToolAuthorizer authorizer = new GroupToolAuthorizer();
    private final McpServer jira = server(true);
    private final GatewayUser all = user("mcp-jira-read", "mcp-jira-write", "mcp-jira-destructive");

    @Test
    void readOnlyNeedsRead() {
        assertThat(authorizer.decide(user("mcp-jira-read"), jira, tool(Risk.READ_ONLY)).allowed()).isTrue();
        assertThat(authorizer.decide(user("mcp-jira-write"), jira, tool(Risk.READ_ONLY)).allowed()).isFalse();
        assertThat(authorizer.decide(user("mcp-confluence-read"), jira, tool(Risk.READ_ONLY)).allowed()).isFalse();
    }

    @Test
    void updateNeedsWriteNotRead() {
        ToolDecision decision = authorizer.decide(user("mcp-jira-read"), jira, tool(Risk.UPDATE));
        assertThat(decision.allowed()).isFalse();
        assertThat(decision.reason()).isEqualTo("not_granted");
        assertThat(decision.requiredEntitlements()).containsExactly("mcp-jira-write");
        assertThat(authorizer.decide(user("mcp-jira-write"), jira, tool(Risk.UPDATE)).allowed()).isTrue();
    }

    @Test
    void destructiveIsAlwaysDeniedBeforeConfirmationsExist() {
        ToolDecision decision = authorizer.decide(all, jira, tool(Risk.DESTRUCTIVE));
        assertThat(decision.allowed()).isFalse();
        assertThat(decision.reason()).isEqualTo("tool_disabled");
    }

    @Test
    void disabledServerOrToolIsDeniedFirstWhateverTheGroups() {
        McpServer disabledServer = server(false);
        ToolDecision server = authorizer.decide(all, disabledServer, tool(Risk.READ_ONLY));
        assertThat(server.allowed()).isFalse();
        assertThat(server.reason()).isEqualTo("tool_disabled");
        ToolDefinition off = new ToolDefinition("some_tool", Risk.READ_ONLY, "read", null, "A tool.", true);
        assertThat(authorizer.decide(all, jira, off).reason()).isEqualTo("tool_disabled");
    }

    @Test
    void entitlementsFollowTheRisk() {
        assertThat(authorizer.requiredEntitlements(jira, tool(Risk.READ_ONLY))).containsExactly("mcp-jira-read");
        assertThat(authorizer.requiredEntitlements(jira, tool(Risk.UPDATE))).containsExactly("mcp-jira-write");
        assertThat(authorizer.requiredEntitlements(jira, tool(Risk.DESTRUCTIVE))).containsExactly("mcp-jira-destructive");
    }

    private static McpServer server(boolean enabled) {
        return new McpServer("mcp-jira", "jira", URI.create("https://mcp-jira.internal:8443/mcp"), "1.0.0", enabled,
                new CredentialPolicy(true, Set.of("user-secret"), List.of(), false), Map.of());
    }

    private static ToolDefinition tool(Risk risk) {
        return new ToolDefinition("some_tool", risk, "read", null, "A tool.", false);
    }

    private static GatewayUser user(String... groups) {
        return new GatewayUser("sub", "user", "claude-code", List.of(groups), "token");
    }
}
