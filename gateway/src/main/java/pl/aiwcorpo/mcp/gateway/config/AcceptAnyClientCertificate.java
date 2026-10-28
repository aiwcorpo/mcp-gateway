package pl.aiwcorpo.mcp.gateway.config;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509TrustManager;

/**
 * Trust manager of the internal port that lets the handshake pass whatever client certificate is offered and
 * advertises no CA list, so every client that has a certificate sends it. The judgement (chain, dates, purpose,
 * name) is made by {@code AdminClientCertificateFilter} and only for {@code /admin/v1}. Tomcat instantiates the
 * class by name, hence the public constructor.
 */
public final class AcceptAnyClientCertificate implements X509TrustManager {

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) {
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        throw new CertificateException("not a client-side trust manager");
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }
}
