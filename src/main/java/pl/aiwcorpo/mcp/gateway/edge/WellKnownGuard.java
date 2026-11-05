package pl.aiwcorpo.mcp.gateway.edge;

import java.io.IOException;

import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import pl.aiwcorpo.mcp.gateway.auth.ResourceMetadata;

/**
 * RFC 9728 documents are anonymous, so they exist only for paths that are MCP endpoints by shape. Everything
 * else under {@code /.well-known/oauth-protected-resource} (the route of saved links and the unknown ones alike) is the 404 of
 * {@code not_found_or_denied} and never reaches the metadata filter.
 */
public final class WellKnownGuard extends OncePerRequestFilter {

    private final ResourceMetadata metadata;

    public WellKnownGuard(ResourceMetadata metadata) {
        this.metadata = metadata;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String path = request.getServletPath();
        if (path.startsWith(ResourceMetadata.WELL_KNOWN) && !metadata.isMetadataPath(path)) {
            RemovedRouteFilter.notFound(response);
            return;
        }
        chain.doFilter(request, response);
    }
}
