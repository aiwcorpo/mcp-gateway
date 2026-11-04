package pl.aiwcorpo.mcp.testserver;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/** SSLContext from PKCS12 files as the dev stack produces them (certs/&lt;name&gt;/keystore.p12, certs/ca/truststore.p12). */
public final class Tls {

    private Tls() {
    }

    public static SSLContext fromPkcs12(Path keystore, Path truststore, char[] password) throws Exception {
        KeyStore keys = load(keystore, password);
        KeyStore trust = load(truststore, password);
        return fromKeyStores(keys, password, trust);
    }

    public static SSLContext fromKeyStores(KeyStore keys, char[] keyPassword, KeyStore trust) throws Exception {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keys, keyPassword);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trust);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keys == null ? null : kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return context;
    }

    private static KeyStore load(Path file, char[] password) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(file)) {
            store.load(in, password);
        }
        return store;
    }
}
