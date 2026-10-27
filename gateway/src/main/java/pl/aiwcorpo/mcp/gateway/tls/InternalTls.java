package pl.aiwcorpo.mcp.gateway.tls;

import java.io.InputStream;
import java.net.http.HttpClient;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.time.Duration;
import java.util.Arrays;
import java.util.concurrent.Executors;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * mTLS material of the gateway (certificate CN=mcp-gateway, internal CA) and HTTP clients for internal calls,
 * one per expected server name.
 */
public final class InternalTls {

    private final KeyManagerFactory keyManagers;
    private final X509TrustManager pkix;

    public InternalTls(Path keystore, Path truststore, char[] password) {
        try {
            KeyStore keys = load(keystore, password);
            keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagers.init(keys, password);
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(load(truststore, password));
            pkix = Arrays.stream(tmf.getTrustManagers()).filter(X509TrustManager.class::isInstance)
                    .map(X509TrustManager.class::cast).findFirst()
                    .orElseThrow(() -> new IllegalStateException("no X509 trust manager"));
        } catch (Exception e) {
            throw new IllegalStateException("Cannot load the gateway TLS material", e);
        }
    }

    /** Client that presents the gateway certificate and accepts only a server certificate naming {@code tlsName}. */
    public HttpClient clientFor(String tlsName, Duration connectTimeout) {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(keyManagers.getKeyManagers(), new TrustManager[] {new PinnedNameTrustManager(pkix, tlsName)}, null);
            SSLParameters parameters = context.getDefaultSSLParameters();
            parameters.setProtocols(new String[] {"TLSv1.3", "TLSv1.2"});
            return HttpClient.newBuilder()
                    .sslContext(context)
                    .sslParameters(parameters)
                    .version(HttpClient.Version.HTTP_1_1)
                    .followRedirects(HttpClient.Redirect.NEVER)
                    .connectTimeout(connectTimeout)
                    .executor(Executors.newVirtualThreadPerTaskExecutor())
                    .build();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Cannot build TLS context for " + tlsName, e);
        }
    }

    private static KeyStore load(Path file, char[] password) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(file)) {
            store.load(in, password);
        }
        return store;
    }
}
