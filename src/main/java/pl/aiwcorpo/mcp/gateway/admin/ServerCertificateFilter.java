package pl.aiwcorpo.mcp.gateway.admin;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Optional;

import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import pl.aiwcorpo.mcp.gateway.auth.AuthenticationAudit;
import pl.aiwcorpo.mcp.gateway.jwt.UuidV7;

/**
 * The certificate half of {@code GET /internal/v1/policy-data}: the chain must lead to the internal CA and carry the clientAuth purpose,
 * and it must have one CN, which becomes the request attribute {@link #CALLER}. Whether that CN is a registered {@code serverId} is
 * decided by the controller against the registry of servers, which changes at runtime. No usable certificate is 401; nothing of the
 * certificate goes to the audit event (CC-125).
 */
public final class ServerCertificateFilter extends OncePerRequestFilter {

    /** The request attribute that carries the CN of the verified certificate. */
    public static final String CALLER = ServerCertificateFilter.class.getName() + ".cn";
    private static final String CERTIFICATES = "jakarta.servlet.request.X509Certificate";

    private final ClientCertificateVerifier verifier;
    private final AuthenticationAudit audit;

    public ServerCertificateFilter(ClientCertificateVerifier verifier, AuthenticationAudit audit) {
        this.verifier = verifier;
        this.audit = audit;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Object attribute = request.getAttribute(CERTIFICATES);
        Optional<X509Certificate> client = attribute instanceof X509Certificate[] certificates
                ? verifier.verified(certificates, Instant.now()) : Optional.empty();
        String name = client.map(AdminClientCertificateFilter::commonName).orElse(null);
        if (name == null) {
            String requestId = UuidV7.next();
            audit.rejected(requestId, request.getHeader("X-Request-Id"), "client_certificate_rejected", "unauthenticated",
                    request.getRemoteAddr());
            response.setHeader("X-Request-Id", requestId);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json;charset=UTF-8");
            response.getOutputStream().write("{\"error\":\"unauthenticated\"}".getBytes(StandardCharsets.UTF_8));
            return;
        }
        request.setAttribute(CALLER, name);
        chain.doFilter(request, response);
    }
}
