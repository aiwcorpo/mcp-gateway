package pl.aiwcorpo.mcp.gateway.authz;

import java.util.List;

import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.server.ToolDefinition;

/**
 * M1 stand-in for the Cedar evaluation: the C9 group {@code mcp-<system>-read|write} by risk. DESTRUCTIVE tools
 * are always denied, because confirmations (C11) do not exist before M3. Deny is the default (invariant 6).
 */
public final class GroupToolAuthorizer implements ToolAuthorizer {

    @Override
    public ToolDecision decide(GatewayUser user, McpServer server, ToolDefinition tool) {
        String required = switch (tool.risk()) {
            case READ_ONLY -> "mcp-" + server.system() + "-read";
            case UPDATE -> "mcp-" + server.system() + "-write";
            case DESTRUCTIVE -> null;
        };
        if (required == null) {
            return ToolDecision.deny("tool_disabled", List.of());
        }
        return user.hasGroup(required) ? ToolDecision.allow() : ToolDecision.deny("not_granted", List.of(required));
    }

    @Override
    public String policyRevision() {
        return null;
    }
}
