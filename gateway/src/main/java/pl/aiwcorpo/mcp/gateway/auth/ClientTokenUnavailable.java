package pl.aiwcorpo.mcp.gateway.auth;

import org.springframework.security.oauth2.jwt.JwtException;

/** The IdP keys could not be fetched, so the token could be neither accepted nor rejected (errorCode upstream_unavailable). */
public final class ClientTokenUnavailable extends JwtException {

    public static final String REASON = "jwks_unavailable";

    public ClientTokenUnavailable() {
        super(REASON);
    }
}
