package pl.aiwcorpo.mcp.gateway.admin;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * mTLS half of C5 authentication: the TLS handshake verified the certificate against the internal CA (client
 * certificates are optional on the connector, because servers fetching the JWKS present none), so here only the
 * name is checked. No certificate is 401, a certificate of another component 403 (README of C5).
 */
public final class AdminClientCertificateFilter extends OncePerRequestFilter {

    private static final String CERTIFICATES = "jakarta.servlet.request.X509Certificate";

    private final Set<String> allowedNames;

    public AdminClientCertificateFilter(List<String> allowedNames) {
        this.allowedNames = Set.copyOf(allowedNames);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Object attribute = request.getAttribute(CERTIFICATES);
        if (!(attribute instanceof X509Certificate[] chainOfCertificates) || chainOfCertificates.length == 0) {
            reject(response, HttpServletResponse.SC_UNAUTHORIZED, "unauthenticated");
            return;
        }
        String name = commonName(chainOfCertificates[0]);
        if (name == null || !allowedNames.contains(name)) {
            reject(response, HttpServletResponse.SC_FORBIDDEN, "access_denied");
            return;
        }
        chain.doFilter(request, response);
    }

    static String commonName(X509Certificate certificate) {
        try {
            for (Rdn rdn : new LdapName(certificate.getSubjectX500Principal().getName()).getRdns()) {
                if ("CN".equals(rdn.getType().toUpperCase(Locale.ROOT))) {
                    return rdn.getValue().toString();
                }
            }
        } catch (InvalidNameException e) {
            return null;
        }
        return null;
    }

    private static void reject(HttpServletResponse response, int status, String code) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.getOutputStream().write(("{\"error\":\"" + code + "\"}").getBytes(StandardCharsets.UTF_8));
    }
}
