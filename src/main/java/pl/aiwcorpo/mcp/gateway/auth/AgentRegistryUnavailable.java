package pl.aiwcorpo.mcp.gateway.auth;

import org.springframework.security.oauth2.jwt.JwtException;

/**
 * The agent registry could not be read, so a token that looks like an agent's could be neither accepted nor rejected (CC-266): the
 * answer is 503 with {@code Retry-After}, the event reason {@code upstream_unavailable} and errorCode upstream_unavailable.
 */
public final class AgentRegistryUnavailable extends JwtException {

    public static final String REASON = "upstream_unavailable";
    public static final int RETRY_AFTER_SECONDS = 10;

    public AgentRegistryUnavailable() {
        super(REASON);
    }
}
