package pl.aiwcorpo.mcp.gateway.jwt;

import java.io.IOException;

import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Separates the two connectors: the internal TLS port serves only the JWKS, the actuator (health, Prometheus)
 * and the C5 admin API, the public port everything else. Servers and the broker fetch keys over the internal CA,
 * and clients never reach internal endpoints.
 */
public final class InternalPortFilter extends OncePerRequestFilter {

    private final int internalPort;

    public InternalPortFilter(int internalPort) {
        this.internalPort = internalPort;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        boolean internal = request.getLocalPort() == internalPort;
        // The decoded and normalised path (what routing and security see), not the raw URI: "//admin/v1/x" and
        // "/%61dmin/v1/x" must not slip past a prefix test on the public port.
        String path = request.getServletPath();
        boolean internalPath = path.equals("/admin/v1") || path.startsWith("/admin/v1/") || "GET".equals(request.getMethod())
                && (JwksController.PATH.equals(path) || "/actuator/health".equals(path) || "/actuator/prometheus".equals(path));
        if (internal != internalPath) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND);
            return;
        }
        chain.doFilter(request, response);
    }
}
