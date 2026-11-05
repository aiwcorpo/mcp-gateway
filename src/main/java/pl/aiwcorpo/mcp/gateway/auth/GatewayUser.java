package pl.aiwcorpo.mcp.gateway.auth;

import java.util.List;
import java.util.regex.Pattern;

import org.springframework.security.oauth2.jwt.Jwt;

/**
 * The caller from the IdP token (C1). {@code accessToken} is kept only for the token exchange of
 * token-exchange systems; it never leaves the gateway in any other form.
 */
public record GatewayUser(String sub, String username, String client, List<String> groups, String accessToken) {

    private static final Pattern MCP_GROUP = Pattern.compile("^mcp-[A-Za-z0-9][A-Za-z0-9._-]*$");

    public static GatewayUser from(Jwt jwt) {
        List<String> groups = jwt.getClaimAsStringList("groups");
        return new GatewayUser(jwt.getSubject(), jwt.getClaimAsString("preferred_username"), jwt.getClaimAsString("azp"),
                groups == null ? List.of() : List.copyOf(groups), jwt.getTokenValue());
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
