package pl.aiwcorpo.mcp.gateway.auth;

import java.util.List;
import java.util.regex.Pattern;

import org.springframework.security.oauth2.jwt.Jwt;

/**
 * The caller from the IdP token (C1). {@code accessToken} is kept only for the token exchange of
 * token-exchange systems; it never leaves the gateway in any other form.
 */
public record GatewayUser(String sub, String username, String client, List<String> groups, String accessToken, Agent agent) {

    /** The registry entry behind an autonomous agent (CC-266), as the request found it; null on a user is a human. */
    public record Agent(String clientId, String ownerSub) {
    }

    public GatewayUser(String sub, String username, String client, List<String> groups, String accessToken) {
        this(sub, username, client, groups, accessToken, null);
    }

    private static final Pattern MCP_GROUP = Pattern.compile("^mcp-[A-Za-z0-9][A-Za-z0-9._-]*$");

    public static GatewayUser from(Jwt jwt) {
        List<String> groups = jwt.getClaimAsStringList("groups");
        return new GatewayUser(jwt.getSubject(), jwt.getClaimAsString("preferred_username"), jwt.getClaimAsString("azp"),
                groups == null ? List.of() : List.copyOf(groups), jwt.getTokenValue(), agentOf(jwt));
    }

    /**
     * The claims only {@link AgentClassifyingDecoder} sets; a token that arrives with one of them is refused as {@code invalid_claims}, so
     * nothing in a token can say that its bearer is an agent.
     */
    public static final String AGENT_CLIENT_CLAIM = "gw_agent_client";
    public static final String AGENT_OWNER_CLAIM = "gw_agent_owner";

    private static Agent agentOf(Jwt jwt) {
        String clientId = jwt.getClaimAsString(AGENT_CLIENT_CLAIM);
        return clientId == null ? null : new Agent(clientId, jwt.getClaimAsString(AGENT_OWNER_CLAIM));
    }

    public boolean isAgent() {
        return agent != null;
    }

    /** The value of C2 {@code pty} and of the Cedar context {@code principalType}: a token without a marker is a human. */
    public String principalType() {
        return agent == null ? "user" : "agent";
    }

    /** The same caller with other groups, as the ceiling of an agent leaves them. */
    public GatewayUser withGroups(List<String> narrowed) {
        return new GatewayUser(sub, username, client, narrowed, accessToken, agent);
    }

    /** Groups forwarded in {@code grp} (C2): only C9 names with the mcp- prefix. */
    public List<String> mcpGroups() {
        return groups.stream().filter(g -> g.length() <= 255 && MCP_GROUP.matcher(g).matches()).distinct().toList();
    }

    public boolean hasGroup(String group) {
        return groups.contains(group);
    }

    @Override
    public String toString() {
        return "GatewayUser[sub=" + sub + ", username=" + username + ", client=" + client + "]";
    }
}
