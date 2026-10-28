package pl.aiwcorpo.mcp.gateway.admin;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
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
 * mTLS half of C5 authentication. Client certificates are optional on the internal port (servers fetching the
 * JWKS present none or a serverAuth-only one), so the chain is verified here against the internal CA and then the
 * name is checked. No usable certificate is 401, a valid certificate of another component 403 (README of C5).
 */
public final class AdminClientCertificateFilter extends OncePerRequestFilter {

    private static final String CERTIFICATES = "jakarta.servlet.request.X509Certificate";

    private final Set<String> allowedNames;
    private final ClientCertificateVerifier verifier;

    public AdminClientCertificateFilter(List<String> allowedNames, ClientCertificateVerifier verifier) {
        this.allowedNames = Set.copyOf(allowedNames);
        this.verifier = verifier;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Object attribute = request.getAttribute(CERTIFICATES);
        Optional<X509Certificate> client = attribute instanceof X509Certificate[] chainOfCertificates
                ? verifier.verified(chainOfCertificates, Instant.now()) : Optional.empty();
        if (client.isEmpty()) {
            reject(response, HttpServletResponse.SC_UNAUTHORIZED, "unauthenticated");
            return;
        }
        String name = commonName(client.get());
        if (name == null || !allowedNames.contains(name)) {
            reject(response, HttpServletResponse.SC_FORBIDDEN, "access_denied");
            return;
        }
        chain.doFilter(request, response);
    }

    /**
     * The one CN of the subject, or null (fail-closed) when there is none, more than one, or a multi-valued RDN.
     * When the certificate carries DNS names, one of them must be the CN or {@code <CN>.internal} (CC-035), so a
     * subject and a SAN that name different components are refused.
     */
    static String commonName(X509Certificate certificate) {
        try {
            String found = null;
            for (Rdn rdn : new LdapName(certificate.getSubjectX500Principal().getName()).getRdns()) {
                if (rdn.size() > 1) {
                    return null;
                }
                if ("CN".equals(rdn.getType().toUpperCase(Locale.ROOT))) {
                    if (found != null) {
                        return null;
                    }
                    found = rdn.getValue().toString();
                }
            }
            if (found == null || !sanAgrees(certificate, found)) {
                return null;
            }
            return found;
        } catch (InvalidNameException | CertificateParsingException e) {
            return null;
        }
    }

    private static boolean sanAgrees(X509Certificate certificate, String name) throws CertificateParsingException {
        Collection<List<?>> alternatives = certificate.getSubjectAlternativeNames();
        if (alternatives == null) {
            return true;
        }
        boolean anyDns = false;
        for (List<?> entry : alternatives) {
            if (Integer.valueOf(2).equals(entry.get(0))) {
                anyDns = true;
                String dns = String.valueOf(entry.get(1)).toLowerCase(Locale.ROOT);
                if (dns.equals(name.toLowerCase(Locale.ROOT)) || dns.equals(name.toLowerCase(Locale.ROOT) + ".internal")) {
                    return true;
                }
            }
        }
        return !anyDns;
    }

    private static void reject(HttpServletResponse response, int status, String code) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json;charset=UTF-8");
        response.getOutputStream().write(("{\"error\":\"" + code + "\"}").getBytes(StandardCharsets.UTF_8));
    }
}
