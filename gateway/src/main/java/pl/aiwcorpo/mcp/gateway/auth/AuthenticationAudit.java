package pl.aiwcorpo.mcp.gateway.auth;

import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;

import pl.aiwcorpo.mcp.gateway.audit.AuditEvent;
import pl.aiwcorpo.mcp.gateway.audit.AuditLog;

/**
 * The {@code authentication} event (C8, CC-120, CC-125) of the gateway for a rejected token of the AI client, a
 * rejected BFF token and a rejected client certificate on the admin port. The event carries the reason and nothing
 * from the credential: the schema has no field for it.
 */
public final class AuthenticationAudit {

    private final AuditLog audit;
    private final String componentId;
    private final AuthenticationEventLimiter limiter;

    public AuthenticationAudit(AuditLog audit, String componentId, AuthenticationEventLimiter limiter) {
        this.audit = audit;
        this.componentId = componentId;
        this.limiter = limiter;
    }

    /** {@code source} is the peer address, used only to sample certificate rejections; never written to the event. */
    public void rejected(String requestId, String clientRequestId, String reason, String errorCode, String source) {
        if (!limiter.permit(reason, source)) {
            return;
        }
        audit.emit(AuditEvent.of("authentication", requestId, componentId)
                .clientRequestId(clientRequestId)
                .decision("deny", reason)
                .outcome("denied", errorCode));
    }

    /** The C8 reason of a failed bearer authentication. */
    public static String reasonOf(AuthenticationException failure) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (cause instanceof ClientTokenRejection rejection) {
                return rejection.reason();
            }
            if (cause instanceof ClientTokenUnavailable) {
                return ClientTokenUnavailable.REASON;
            }
        }
        if (failure instanceof AuthenticationCredentialsNotFoundException || failure instanceof InsufficientAuthenticationException) {
            return "missing_token";
        }
        return "malformed";
    }

    /** Seconds from a {@link ClientTokenUnavailable} anywhere in the cause chain, or -1 when there is none. */
    public static int retryAfterOf(Throwable failure) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (cause instanceof ClientTokenUnavailable unavailable) {
                return unavailable.retryAfterSeconds();
            }
        }
        return -1;
    }

    public static String errorCodeOf(String reason) {
        return ClientTokenUnavailable.REASON.equals(reason) ? "upstream_unavailable" : "unauthenticated";
    }
}
