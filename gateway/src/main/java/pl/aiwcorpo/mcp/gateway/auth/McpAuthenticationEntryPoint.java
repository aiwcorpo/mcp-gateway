package pl.aiwcorpo.mcp.gateway.auth;

import java.io.IOException;

import org.springframework.http.HttpHeaders;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.web.AuthenticationEntryPoint;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/** 401 with {@code WWW-Authenticate: Bearer resource_metadata="..."} (C1, RFC 9728, MCP authorization). */
public final class McpAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ResourceMetadata metadata;

    public McpAuthenticationEntryPoint(ResourceMetadata metadata) {
        this.metadata = metadata;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
            throws IOException {
        StringBuilder challenge = new StringBuilder("Bearer");
        if (authException instanceof InvalidBearerTokenException) {
            challenge.append(" error=\"invalid_token\",");
        }
        challenge.append(" resource_metadata=\"").append(metadata.metadataUrl(request.getRequestURI())).append('"');
        response.setHeader(HttpHeaders.WWW_AUTHENTICATE, challenge.toString());
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write("{\"error\":\"unauthenticated\",\"message\":\"A valid bearer token is required.\"}");
    }
}
