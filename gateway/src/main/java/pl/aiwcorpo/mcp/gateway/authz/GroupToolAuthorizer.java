package pl.aiwcorpo.mcp.gateway.authz;

import java.util.List;

import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.server.ToolDefinition;

/**
 * Stand-in for the Cedar evaluation: the C9 group {@code mcp-<system>-read|write} by risk. DESTRUCTIVE tools
 * are always denied, because confirmations (C11) do not exist before M3. A disabled server or tool is denied
 * first. Deny is the default (invariant 6).
 */
public final class GroupToolAuthorizer implements ToolAuthorizer {

    @Override
    public ToolDecision decide(GatewayUser user, McpServer server, ToolDefinition tool) {
        if (!server.enabled() || tool.disabled()) {
            return ToolDecision.deny("tool_disabled", List.of());
        }
        return switch (tool.risk()) {
            case DESTRUCTIVE -> ToolDecision.deny("tool_disabled", List.of());
            case READ_ONLY, UPDATE -> {
                String required = requiredEntitlements(server, tool).getFirst();
                yield user.hasGroup(required) ? ToolDecision.allow() : ToolDecision.deny("not_granted", List.of(required));
            }
        };
    }

    @Override
    public List<String> requiredEntitlements(McpServer server, ToolDefinition tool) {
        return List.of("mcp-" + server.system() + "-" + switch (tool.risk()) {
            case READ_ONLY -> "read";
            case UPDATE -> "write";
            case DESTRUCTIVE -> "destructive";
        });
    }

    @Override
    public String policyRevision() {
        return null;
    }
}
