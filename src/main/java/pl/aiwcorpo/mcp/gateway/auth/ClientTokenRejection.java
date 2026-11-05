package pl.aiwcorpo.mcp.gateway.auth;

import org.springframework.security.oauth2.jwt.BadJwtException;

/**
 * A C1 token the gateway rejected, with the C8 {@code reason} of the authentication event. The message is the
 * reason only: nothing of the token ends up in it, so it is safe to log.
 */
public final class ClientTokenRejection extends BadJwtException {

    private final String reason;

    public ClientTokenRejection(String reason) {
        super(reason);
        this.reason = reason;
    }

    public String reason() {
        return reason;
    }
}
