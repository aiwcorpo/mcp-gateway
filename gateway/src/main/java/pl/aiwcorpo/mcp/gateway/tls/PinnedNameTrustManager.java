package pl.aiwcorpo.mcp.gateway.tls;

import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Locale;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Server certificate check for internal calls: PKIX against the internal CA, then the certificate must carry
 * {@code expectedName} as a DNS SAN, whatever address the connection went to (C5: SAN == {@code <serverId>.internal};
 * CC-035: the broker name is configuration). Being an {@link X509ExtendedTrustManager}, it replaces JSSE's
 * hostname check instead of adding to it.
 */
public final class PinnedNameTrustManager extends X509ExtendedTrustManager {

    private static final int SAN_DNS = 2;

    private final X509TrustManager pkix;
    private final String expectedName;

    public PinnedNameTrustManager(X509TrustManager pkix, String expectedName) {
        this.pkix = pkix;
        this.expectedName = expectedName.toLowerCase(Locale.ROOT);
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
