package pl.aiwcorpo.mcp.gateway.agent;

import java.time.Instant;
import java.util.List;
import java.util.regex.Pattern;

import pl.aiwcorpo.mcp.gateway.server.Risk;

/**
 * An agent of the registry (C5 {@code AgentClient}, CC-266): a client of the identity provider with its own service account.
 * {@code serviceAccountSub} is the {@code sub} of that account, not its {@code preferred_username}.
 */
public record AgentClient(String clientId, String serviceAccountSub, String ownerSub, Risk maxRisk, List<String> allowedGroups,
                          boolean delegationAllowed, String createdBy, Instant createdAt, Instant keyRotatedAt, Suspension suspension) {

    /** The suspension of an agent, the emergency switch of CC-266: who put it, when and why. */
    public record Suspension(String by, Instant at, String reason) {
    }

    public static final Pattern CLIENT_ID = Pattern.compile("^agent-[a-z][a-z0-9]*(-[a-z0-9]+)*$");
    public static final String ADMIN_GROUP = "mcp-platform-admin";
    public static final String DESTRUCTIVE_SUFFIX = "-destructive";

    public AgentClient {
        allowedGroups = List.copyOf(allowedGroups);
    }

    public boolean suspended() {
        return suspension != null;
    }

    /** A group that an agent can never hold, however an administrator asks for it (CC-266). */
    public static boolean groupNotAllowed(String group) {
        return group.endsWith(DESTRUCTIVE_SUFFIX) || ADMIN_GROUP.equals(group);
    }

    /** The groups of the token that the ceiling lets through, in the order of the token. */
    public List<String> narrow(List<String> tokenGroups) {
        return tokenGroups.stream().filter(allowedGroups::contains).filter(group -> !groupNotAllowed(group)).toList();
    }
}
