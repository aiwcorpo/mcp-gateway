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

import org.springframework.http.server.PathContainer;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import pl.aiwcorpo.mcp.gateway.auth.AuthenticationAudit;
import pl.aiwcorpo.mcp.gateway.jwt.UuidV7;

/**
 * mTLS half of C5 authentication. Client certificates are optional on the internal port (servers fetching the
 * JWKS present none or a serverAuth-only one), so the chain is verified here against the internal CA and then the
 * name is checked against the operation: each rule is a method and a path pattern with the names the contract
 * allows for it ({@code x-allowed-client-cn}). A request no rule covers is refused for every name. No usable
 * certificate is 401, a valid certificate of another component 403 (README of C5).
 */
public final class AdminClientCertificateFilter extends OncePerRequestFilter {

    /** One operation (or all methods when {@code method} is null) and the certificate names allowed to call it. */
    public record Rule(String method, PathPattern pattern, Set<String> names) {
        private static final PathPatternParser PARSER = new PathPatternParser();

        public static Rule of(String method, String pattern, Collection<String> names) {
            return new Rule(method, PARSER.parse(pattern), Set.copyOf(names));
        }

        boolean covers(String requestMethod, PathContainer path) {
            return (method == null || method.equals(requestMethod)) && pattern.matches(path);
        }
    }

    private static final String CERTIFICATES = "jakarta.servlet.request.X509Certificate";

    private final List<Rule> rules;
    private final boolean refuseUncovered;
    private final ClientCertificateVerifier verifier;
    private final AuthenticationAudit audit;

    /**
     * @param refuseUncovered true for the admin chain (every path in it is an operation); false for a filter that
     *                        guards a few paths of a chain and lets the rest through untouched
     */
    public AdminClientCertificateFilter(List<Rule> rules, boolean refuseUncovered, ClientCertificateVerifier verifier,
                                        AuthenticationAudit audit) {
        this.rules = List.copyOf(rules);
        this.refuseUncovered = refuseUncovered;
        this.verifier = verifier;
        this.audit = audit;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        PathContainer path = PathContainer.parsePath(request.getServletPath());
        Rule rule = rules.stream().filter(candidate -> candidate.covers(request.getMethod(), path)).findFirst().orElse(null);
        if (rule == null && !refuseUncovered) {
            chain.doFilter(request, response);
            return;
        }
        Object attribute = request.getAttribute(CERTIFICATES);
        Optional<X509Certificate> client = attribute instanceof X509Certificate[] chainOfCertificates
                ? verifier.verified(chainOfCertificates, Instant.now()) : Optional.empty();
        if (client.isEmpty()) {
            reject(request, response, HttpServletResponse.SC_UNAUTHORIZED, "unauthenticated");
            return;
        }
        String name = commonName(client.get());
        if (rule == null || name == null || !rule.names().contains(name)) {
            reject(request, response, HttpServletResponse.SC_FORBIDDEN, "access_denied");
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

    /** Nothing of the certificate goes to the event (CC-125): the reason and the status only. */
    private void reject(HttpServletRequest request, HttpServletResponse response, int status, String code) throws IOException {
        String requestId = UuidV7.next();
        audit.rejected(requestId, request.getHeader("X-Request-Id"), "client_certificate_rejected", code, request.getRemoteAddr());
        response.setHeader("X-Request-Id", requestId);
        response.setStatus(status);
        response.setContentType("application/json;charset=UTF-8");
        response.getOutputStream().write(("{\"error\":\"" + code + "\"}").getBytes(StandardCharsets.UTF_8));
    }
}
