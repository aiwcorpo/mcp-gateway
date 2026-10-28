package pl.aiwcorpo.mcp.gateway.support;

import java.util.List;

import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.authz.ToolAuthorizer;
import pl.aiwcorpo.mcp.gateway.authz.ToolDecision;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.server.ToolDefinition;
import tools.jackson.databind.JsonNode;

/** The group rule of the example policies as a plain function, for unit tests that need an authorizer but not Cedar. */
public final class GroupRulesAuthorizer implements ToolAuthorizer {

    @Override
    public ToolDecision decide(GatewayUser user, McpServer server, ToolDefinition tool, JsonNode arguments, String virtualSlug) {
        if (!server.enabled() || tool.disabled()) {
            return ToolDecision.deny("tool_disabled", List.of());
        }
        String required = requiredEntitlements(server, tool).getFirst();
        return user.hasGroup(required) ? ToolDecision.allow() : ToolDecision.deny("not_granted", List.of(required));
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
