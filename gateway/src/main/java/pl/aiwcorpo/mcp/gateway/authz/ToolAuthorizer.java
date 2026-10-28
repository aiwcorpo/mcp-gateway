package pl.aiwcorpo.mcp.gateway.authz;

import java.util.List;

import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.server.ToolDefinition;
import tools.jackson.databind.JsonNode;

/**
 * Tool-level authorization (C7): the Cedar {@code call} evaluation from the policy bundle. Used for the tools/list filter, the
 * catalog and the creation of virtual servers (no arguments, so no resource references), and before every call (with the
 * arguments and the link). Deny is the default, and any failure to decide is a deny (invariant 6).
 */
public interface ToolAuthorizer {

    /** Without arguments and without a link: whether the caller may call this tool at all. */
    default ToolDecision decide(GatewayUser user, McpServer server, ToolDefinition tool) {
        return decide(user, server, tool, null, null);
    }

    /**
     * Before a call. {@code arguments} give the resources named by the tool's {@code resourceRefs}; {@code virtualSlug} is the
     * link the call came through, or null.
     */
    ToolDecision decide(GatewayUser user, McpServer server, ToolDefinition tool, JsonNode arguments, String virtualSlug);

    /** Groups (C9) that usually grant the tool; shown in the catalog and in access_denied. Informational: the policy decides. */
    List<String> requiredEntitlements(McpServer server, ToolDefinition tool);

    /** Revision of the main policy bundle in force, for {@code prv} (C2) and {@code policyRevision} (C8); null before the first. */
    String policyRevision();
}
