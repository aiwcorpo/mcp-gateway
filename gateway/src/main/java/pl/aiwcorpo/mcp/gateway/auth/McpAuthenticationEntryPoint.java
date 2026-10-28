package pl.aiwcorpo.mcp.gateway.auth;

import java.io.IOException;
import java.util.Set;

import org.springframework.http.HttpHeaders;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import pl.aiwcorpo.mcp.gateway.jwt.UuidV7;

/**
 * Answer to a client that is not authenticated (C1, RFC 9728, MCP authorization, CC-124). A token that was checked and
 * rejected is 401 with {@code WWW-Authenticate: Bearer resource_metadata="..."} and no reason (the reason goes to the
 * audit event). When the gateway cannot check the token because the IdP keys are unavailable the answer is 503
 * {@code upstream_unavailable} with {@code Retry-After} and without any challenge: a client that restarted its login
 * would not be helped. Every rejection is an {@code authentication} event.
 */
public final class McpAuthenticationEntryPoint implements AuthenticationEntryPoint {

    static final String UNAUTHENTICATED_BODY = "{\"error\":\"unauthenticated\",\"message\":\"Authentication required.\"}";
    static final String UNAVAILABLE_BODY = "{\"error\":\"upstream_unavailable\",\"message\":\"The identity provider keys are "
            + "temporarily unavailable. Try again in a few seconds.\"}";

    /**
     * Known noise that is not audited. Everything else is, because the security chain matches paths after
     * normalization (encoding, ;params, double slashes, case) and a raw-path allowlist would let those variants
     * of an MCP endpoint skip the audit of a rejected token.
     */
    private static final Set<String> NOISE_PATHS = Set.of("/", "/favicon.ico", "/robots.txt");

    private final ResourceMetadata metadata;
    private final AuthenticationAudit audit;

    public McpAuthenticationEntryPoint(ResourceMetadata metadata, AuthenticationAudit audit) {
        this.metadata = metadata;
        this.audit = audit;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
            throws IOException {
        String requestId = UuidV7.next();
        String reason = AuthenticationAudit.reasonOf(authException);
        if (!"OPTIONS".equals(request.getMethod()) && !NOISE_PATHS.contains(request.getRequestURI())) {
            audit.rejected(requestId, request.getHeader("X-Request-Id"), reason, AuthenticationAudit.errorCodeOf(reason), null);
        }
        response.setHeader("X-Request-Id", requestId);
        response.setContentType("application/json; charset=utf-8");
        if (ClientTokenUnavailable.REASON.equals(reason)) {
            response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
            response.setHeader(HttpHeaders.RETRY_AFTER, Integer.toString(AuthenticationAudit.retryAfterOf(authException)));
            response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
            response.getWriter().write(UNAVAILABLE_BODY);
            return;
        }
        response.setHeader(HttpHeaders.WWW_AUTHENTICATE,
                "Bearer resource_metadata=\"" + metadata.metadataUrl(request.getRequestURI()) + "\"");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getWriter().write(UNAUTHENTICATED_BODY);
    }
}
