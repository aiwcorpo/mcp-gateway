package pl.aiwcorpo.mcp.gateway.mcp;

import java.util.Optional;

/**
 * Checks 3 to 5 of a request that carries {@code Mcp-Session-Id} (CC-184); the token (1) and the syntax of the query (2) come
 * before and need no session. A session of another user and an unknown one give the same answer and no audit reason, so a request
 * cannot learn whether a session exists; a session used on another route or with another filter is refused with
 * {@code filter_mismatch}. The binding orders the audit; it is not a security boundary (Cedar decides every call).
 */
public final class SessionCheck {

    public enum Result {
        /** The session is the caller's, on its route, with its filter. */
        CONTINUE,
        /** 404 as for an unknown session; no audit reason. */
        UNKNOWN,
        /** 404 as for an unknown session; audit {@code filter_mismatch}. */
        MISMATCH
    }

    private SessionCheck() {
    }

    public static Result check(String callerSub, String route, String requestFilter, Optional<ClientSession> session) {
        if (session.isEmpty() || !session.get().sub().equals(callerSub)) {
            return Result.UNKNOWN;
        }
        if (!session.get().route().equals(route) || !session.get().filter().equals(requestFilter)) {
            return Result.MISMATCH;
        }
        return Result.CONTINUE;
    }
}
