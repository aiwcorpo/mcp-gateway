package pl.aiwcorpo.mcp.gateway.edge;

import java.io.IOException;

import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import pl.aiwcorpo.mcp.gateway.jwt.UuidV7;

/**
 * {@code /v/<slug>/mcp}, the route of saved links, no longer exists (CC-177): every method answers the 404 of
 * {@code not_found_or_denied} whatever the token says and leaves no audit event, so the route reveals neither an old link nor the
 * validity of a token. It runs before the security chain, which would reject a bad token on the way.
 */
public final class RemovedRouteFilter extends OncePerRequestFilter {

    public static final String BODY = "{\"error\":\"not_found_or_denied\",\"message\":\"The resource does not exist or you do not have access to it.\"}";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String path = request.getServletPath();
        if ("/v".equals(path) || path.startsWith("/v/")) {
            notFound(response);
            return;
        }
        chain.doFilter(request, response);
    }

    static void notFound(HttpServletResponse response) throws IOException {
        response.setStatus(HttpServletResponse.SC_NOT_FOUND);
        response.setHeader("X-Request-Id", UuidV7.next());
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(BODY);
    }
}
