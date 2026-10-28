package pl.aiwcorpo.mcp.gateway.admin;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;

/**
 * Verifies a client certificate chain against the internal CA by hand. The internal port asks for client
 * certificates without letting the TLS stack judge them ({@code optionalNoCA}): servers and the broker fetch the
 * JWKS with an SSL context that carries their own serverAuth-only certificate, and a handshake-time purpose
 * check would break those fetches. The handshake still proves possession of the private key; here the chain, its
 * dates and the clientAuth purpose are checked, and only the admin API cares about the result.
 */
public final class ClientCertificateVerifier {

    private static final String CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";

    private final KeyStore trust;

    public ClientCertificateVerifier(Path truststore, char[] password) {
        try (InputStream in = Files.newInputStream(truststore)) {
            KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(in, password);
            this.trust = store;
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalStateException("Cannot read the truststore " + truststore, e);
        }
    }

    /** The end-entity certificate when {@code chain} leads to the internal CA and is valid for client authentication. */
    public Optional<X509Certificate> verified(X509Certificate[] chain, Instant now) {
        if (chain == null || chain.length == 0) {
            return Optional.empty();
        }
        X509Certificate leaf = chain[0];
        try {
            if (leaf.getBasicConstraints() != -1 || leaf.getExtendedKeyUsage() == null
                    || !leaf.getExtendedKeyUsage().contains(CLIENT_AUTH)) {
                return Optional.empty();
            }
            List<X509Certificate> path = new ArrayList<>();
            for (X509Certificate certificate : chain) {
                if (trust.getCertificateAlias(certificate) == null) {
                    path.add(certificate);
                }
            }
            CertPath certPath = CertificateFactory.getInstance("X.509").generateCertPath(path);
            PKIXParameters parameters = new PKIXParameters(trust);
            parameters.setRevocationEnabled(false);
            parameters.setDate(Date.from(now));
            CertPathValidator.getInstance("PKIX").validate(certPath, parameters);
            return Optional.of(leaf);
        } catch (GeneralSecurityException | RuntimeException e) {
            return Optional.empty();
        }
    }
}
