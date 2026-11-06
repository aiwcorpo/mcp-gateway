package pl.aiwcorpo.mcp.gateway.tls;

import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Locale;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Server certificate check for internal calls: PKIX against the internal CA, then the certificate must carry
 * {@code expectedName} as a DNS SAN, whatever address the connection went to (C5: SAN == {@code <serverId>.internal};
 * CC-035: the broker name is configuration). Being an {@link X509ExtendedTrustManager}, it replaces JSSE's
 * hostname check instead of adding to it. For an MCP server ({@link #forServer}) the leaf must also have exactly one CN, equal to the
 * {@code serverId}: a certificate that the internal CA issued to another server, or to a component, is not the identity of this one.
 */
public final class PinnedNameTrustManager extends X509ExtendedTrustManager {

    private static final int SAN_DNS = 2;

    private final X509TrustManager pkix;
    private final String expectedName;
    private final String expectedCn;

    public PinnedNameTrustManager(X509TrustManager pkix, String expectedName) {
        this(pkix, expectedName, null);
    }

    private PinnedNameTrustManager(X509TrustManager pkix, String expectedName, String expectedCn) {
        this.pkix = pkix;
        this.expectedName = expectedName.toLowerCase(Locale.ROOT);
        this.expectedCn = expectedCn;
    }

    /** The identity of a server: SAN {@code <serverId>.internal} and CN {@code serverId} (C5, CC-240). */
    public static PinnedNameTrustManager forServer(X509TrustManager pkix, String serverId) {
        return new PinnedNameTrustManager(pkix, serverId + ".internal", serverId);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        pkix.checkServerTrusted(chain, authType);
        checkName(chain[0]);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        checkServerTrusted(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        checkServerTrusted(chain, authType);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        throw new CertificateException("client certificates are not accepted here");
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        checkClientTrusted(chain, authType);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        checkClientTrusted(chain, authType);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return pkix.getAcceptedIssuers();
    }

    private void checkName(X509Certificate leaf) throws CertificateException {
        if (!dnsNames(leaf).contains(expectedName)) {
            throw new CertificateException("server certificate has no DNS SAN " + expectedName);
        }
        if (expectedCn != null && !expectedCn.equals(commonName(leaf))) {
            throw new CertificateException("server certificate has not the CN " + expectedCn);
        }
    }

    /** The one CN of the subject, or null when there is none, more than one, or a multi-valued RDN. */
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
            return found;
        } catch (InvalidNameException e) {
            return null;
        }
    }

    static List<String> dnsNames(X509Certificate certificate) throws CertificateParsingException {
        Collection<List<?>> sans = certificate.getSubjectAlternativeNames();
        if (sans == null) {
            return List.of();
        }
        return sans.stream().filter(san -> san.size() >= 2 && Integer.valueOf(SAN_DNS).equals(san.get(0)))
                .map(san -> ((String) san.get(1)).toLowerCase(Locale.ROOT)).toList();
    }
}
