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
    private final McpServer jira = new McpServer("mcp-jira", "jira", URI.create("https://mcp-jira.internal:8443/mcp"),
            new CredentialPolicy(true, Set.of("user-secret"), List.of(), false), Map.of());
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

    private static ToolDefinition tool(Risk risk) {
        return new ToolDefinition("some_tool", risk);
    }

    private static GatewayUser user(String... groups) {
        return new GatewayUser("sub", "user", "claude-code", List.of(groups), "token");
    }
}
