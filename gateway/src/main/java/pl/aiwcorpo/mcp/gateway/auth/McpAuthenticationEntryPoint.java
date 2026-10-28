package pl.aiwcorpo.mcp.gateway.auth;

import java.io.IOException;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.web.AuthenticationEntryPoint;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import pl.aiwcorpo.mcp.gateway.audit.AuditEvent;
import pl.aiwcorpo.mcp.gateway.audit.AuditLog;
import pl.aiwcorpo.mcp.gateway.jwt.UuidV7;

/**
 * 401 with {@code WWW-Authenticate: Bearer resource_metadata="..."} (C1, RFC 9728, MCP authorization). Every
 * rejection is also an {@code authentication} event (C8, CC-120) with the reason and nothing from the token.
 */
public final class McpAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ResourceMetadata metadata;
    private final AuditLog audit;
    private final String componentId;

    public McpAuthenticationEntryPoint(ResourceMetadata metadata, AuditLog audit, String componentId) {
        this.metadata = metadata;
        this.audit = audit;
        this.componentId = componentId;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
            throws IOException {
        String requestId = UuidV7.next();
        emit(request, requestId, authException);
        StringBuilder challenge = new StringBuilder("Bearer");
        if (authException instanceof InvalidBearerTokenException) {
            challenge.append(" error=\"invalid_token\",");
        }
        challenge.append(" resource_metadata=\"").append(metadata.metadataUrl(request.getRequestURI())).append('"');
        response.setHeader(HttpHeaders.WWW_AUTHENTICATE, challenge.toString());
        response.setHeader("X-Request-Id", requestId);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write("{\"error\":\"unauthenticated\",\"message\":\"A valid bearer token is required.\"}");
    }

    private void emit(HttpServletRequest request, String requestId, AuthenticationException failure) {
        String reason = reason(failure);
        boolean infrastructure = ClientTokenUnavailable.REASON.equals(reason);
        audit.emit(AuditEvent.of("authentication", requestId, componentId)
                .clientRequestId(request.getHeader("X-Request-Id"))
                .decision("deny", reason)
                .outcome("denied", infrastructure ? "upstream_unavailable" : "unauthenticated"));
    }

    private static String reason(AuthenticationException failure) {
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
}
