package pl.aiwcorpo.mcp.gateway.broker;

import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;

/** What the confirmations need from the broker's authenticator (C4): registration state, a code check and the burn of codes. */
public interface AuthenticatorPort {

    /** State of the user's authenticator registration. */
    enum State { NONE, ACTIVE, DISABLED, UNAVAILABLE }

    /** The broker's judgement of a code; {@code retryAfterSeconds} only for {@code locked}; "unavailable" for any failure. */
    record Verdict(String result, int retryAfterSeconds) {
    }

    State state(GatewayUser user, String tool, String requestId);

    Verdict verify(GatewayUser user, String tool, String code, String requestId);

    /** True only when the broker confirmed the burn; the caller treats anything else as a failure. */
    boolean invalidateCodes(GatewayUser user, String tool, String requestId);
}
