package pl.aiwcorpo.mcp.gateway.authz;

import java.util.List;

import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.server.ToolDefinition;

/**
 * Tool-level authorization before a call, for the tools/list filter, the catalog and the creation of virtual
 * servers. A later Cedar {@code call} evaluation from the policy bundle replaces the implementation; callers stay.
 */
public interface ToolAuthorizer {

    ToolDecision decide(GatewayUser user, McpServer server, ToolDefinition tool);

    /** Groups (C9) that grant the tool according to the policy; shown in the catalog and in access_denied. */
    List<String> requiredEntitlements(McpServer server, ToolDefinition tool);

    /** Revision of the policies used, for {@code prv} (C2) and {@code policyRevision} (C8); null without a bundle. */
    String policyRevision();
}
