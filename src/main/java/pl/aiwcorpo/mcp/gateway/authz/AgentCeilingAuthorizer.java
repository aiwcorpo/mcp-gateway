package pl.aiwcorpo.mcp.gateway.authz;

import java.util.List;

import pl.aiwcorpo.mcp.gateway.agent.AgentRegistry;
import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.server.ToolDefinition;
import tools.jackson.databind.JsonNode;

/**
 * What the registry says about an agent before Cedar is asked (CC-266): the entry as it is now, so that a suspension, a lower
 * {@code maxRisk} or a narrower ceiling of groups holds for the next decision and for the streams that were opened earlier. A tool above
 * {@code maxRisk} is {@code agent_max_risk}, which the call answers as {@code not_found_or_denied} (the agent does not learn that the tool
 * exists) and the list leaves out. The groups reach Cedar cut to the ceiling. A caller that is not an agent is passed through untouched.
 */
public final class AgentCeilingAuthorizer implements ToolAuthorizer {

    public static final String MAX_RISK = "agent_max_risk";
    public static final String SUSPENDED = "agent_suspended";
    public static final String NOT_REGISTERED = "agent_not_registered";

    private final ToolAuthorizer delegate;
    private final AgentRegistry agents;

    public AgentCeilingAuthorizer(ToolAuthorizer delegate, AgentRegistry agents) {
        this.delegate = delegate;
        this.agents = agents;
    }

    @Override
    public ToolDecision decide(GatewayUser user, McpServer server, ToolDefinition tool, JsonNode arguments) {
        if (!user.isAgent()) {
            return delegate.decide(user, server, tool, arguments);
        }
        ToolDecision refusal = refusal(user, tool);
        return refusal != null ? refusal : delegate.decide(narrowed(user), server, tool, arguments);
    }

    @Override
    public ToolDecision toolLevel(GatewayUser user, McpServer server, ToolDefinition tool) {
        if (!user.isAgent()) {
            return delegate.toolLevel(user, server, tool);
        }
        ToolDecision refusal = refusal(user, tool);
        return refusal != null ? refusal : delegate.toolLevel(narrowed(user), server, tool);
    }

    @Override
    public ToolDecision forCatalog(GatewayUser user, McpServer server, ToolDefinition tool) {
        return delegate.forCatalog(user, server, tool);
    }

    @Override
    public List<String> requiredEntitlements(McpServer server, ToolDefinition tool) {
        return delegate.requiredEntitlements(server, tool);
    }

    @Override
    public long policyRevision() {
        return delegate.policyRevision();
    }

    /**
     * Whether an agent may make this call at all before the principal type is emitted. Until the emission slice (CC-260 step 5) the broker
     * is asked for a credential as for a person, without {@code pty}, so its rule for agents (CC-261: only a service account of a system
     * with {@code agentsAllowed}) cannot apply; an agent therefore gets no tool that needs a credential, and none that needs a confirmation
     * (it has no authenticator). Lift the credential half when the gateway sends {@code pty} to the broker. Not an agent: always eligible.
     */
    public static boolean eligible(GatewayUser user, McpServer server, ToolDefinition tool) {
        return !user.isAgent() || !(tool.requiresConfirmation() || server.credential().required());
    }

    /** The refusal the registry gives for this agent and tool, or null when Cedar decides. */
    private ToolDecision refusal(GatewayUser user, ToolDefinition tool) {
        return switch (agents.find(user.agent().clientId())) {
            case AgentRegistry.Lookup.Unreadable unreadable -> ToolDecision.deny("policy_unavailable", List.of());
            case AgentRegistry.Lookup.Absent absent -> ToolDecision.deny(NOT_REGISTERED, List.of());
            case AgentRegistry.Lookup.Found found -> found.agent().suspended() ? ToolDecision.deny(SUSPENDED, List.of())
                    : tool.risk().compareTo(found.agent().maxRisk()) > 0 ? ToolDecision.deny(MAX_RISK, List.of()) : null;
        };
    }

    /** The registry entry cuts the groups once more, so that a change of the ceiling does not wait for the token of the agent to expire. */
    private GatewayUser narrowed(GatewayUser user) {
        return agents.find(user.agent().clientId()) instanceof AgentRegistry.Lookup.Found found
                ? user.withGroups(found.agent().narrow(user.groups())) : user;
    }
}
