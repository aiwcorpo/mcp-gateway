package pl.aiwcorpo.mcp.gateway.authz;

import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.server.ToolDefinition;

/**
 * Tool-level authorization before a call and for the tools/list filter. M2 replaces the implementation with
 * the Cedar {@code call} evaluation from the policy bundle (PolicyStore of mcp-policy-bundle); callers stay.
 */
public interface ToolAuthorizer {

    ToolDecision decide(GatewayUser user, McpServer server, ToolDefinition tool);

    /** Revision of the policies used, for {@code prv} (C2) and {@code policyRevision} (C8); null without a bundle. */
    String policyRevision();
}
