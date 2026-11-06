package pl.aiwcorpo.mcp.gateway.authz;

import java.util.List;

import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.server.ToolDefinition;
import tools.jackson.databind.JsonNode;

/**
 * Tool-level authorization (C7): the Cedar {@code call} evaluation with the platform policies and the overrides. Used for the tools/list filter and the
 * catalog (no arguments, so no resource references), and before every call (with the arguments). Deny is the default, and any
 * failure to decide is a deny (invariant 6).
 */
public interface ToolAuthorizer {

    /** Without arguments: whether the caller may call this tool at all, and the tool is not switched off. */
    default ToolDecision decide(GatewayUser user, McpServer server, ToolDefinition tool) {
        return decide(user, server, tool, null);
    }

    /** Before a call. {@code arguments} give the resources named by the tool's {@code resourceRefs}. */
    ToolDecision decide(GatewayUser user, McpServer server, ToolDefinition tool, JsonNode arguments);

    /**
     * {@code mayCall} of CC-178: the decision at the level of the tool (no arguments), the same one that qualifies a tool for
     * {@code tools/list}, but whatever the switches say: a disabled server or tool, the availability of the server and the state of
     * the account do not change it.
     */
    default boolean mayCall(GatewayUser user, McpServer server, ToolDefinition tool) {
        return toolLevel(user, server, tool).allowed();
    }

    /**
     * The decision behind {@link #mayCall}: allowed, denied for a reason that is the user's (no grant, a forbid) or undecided because
     * the policy could not answer ({@code policy_unavailable}, {@code policy_error}); an undecided call is not a denied one, and the
     * caller must not tell the client that the tool does not exist.
     */
    ToolDecision toolLevel(GatewayUser user, McpServer server, ToolDefinition tool);

    /**
     * What the catalog of the portal shows: whether the user may call the tool as the user of an AI client. The caller of the catalog is the
     * portal, whose own client name says nothing of the AI clients the user works with, so the clients that may call are not asked.
     */
    default ToolDecision forCatalog(GatewayUser user, McpServer server, ToolDefinition tool) {
        return decide(user, server, tool);
    }

    /** Groups (C9) that usually grant the tool; shown in the catalog and in access_denied. Informational: the policy decides. */
    List<String> requiredEntitlements(McpServer server, ToolDefinition tool);

    /** Revision of the policy data in force, for {@code prv} (C2) and {@code policyRevision} (C8); 0 before the first load. */
    long policyRevision();
}
