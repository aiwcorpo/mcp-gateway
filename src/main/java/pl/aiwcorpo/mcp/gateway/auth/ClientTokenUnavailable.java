package pl.aiwcorpo.mcp.gateway.auth;

import org.springframework.security.oauth2.jwt.JwtException;

/**
 * The IdP keys could not be had, so the token could be neither accepted nor rejected (CC-124): the answer is 503 with
 * {@code Retry-After}, the event reason {@code jwks_unavailable} and errorCode upstream_unavailable.
 */
public final class ClientTokenUnavailable extends JwtException {

    public static final String REASON = "jwks_unavailable";

    private final int retryAfterSeconds;

    public ClientTokenUnavailable(int retryAfterSeconds) {
        super(REASON);
        this.retryAfterSeconds = retryAfterSeconds;
    }

    public int retryAfterSeconds() {
        return retryAfterSeconds;
    }
}
