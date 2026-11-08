package pl.aiwcorpo.mcp.gateway.tls;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.http.HttpClient;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Executors;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

import pl.aiwcorpo.mcp.gateway.net.AddressPolicy;

/**
 * Outbound TLS towards the MCP servers (C5, CC-249). The gateway presents no client certificate, and what it accepts of the server is
 * chosen per server when an administrator approves the connection:
 *
 * <ul>
 * <li>{@code ca}: the chain leads to a CA of the server trust, which is the default trust store of the JVM and the optional PEM bundle
 *     {@code MCP_SERVER_TRUSTED_CAS}, and the certificate names the host of the address (the standard hostname verification);</li>
 * <li>{@code pinned}: the leaf certificate is exactly the one approved, by the SHA-256 of its DER; no chain and no host name are checked,
 *     because a self-signed certificate has neither a chain nor, necessarily, a name that fits the address;</li>
 * <li>{@code plain}: {@code http}, nothing to check.</li>
 * </ul>
 */
public final class ServerTls {

    public static final String CA = "ca";
    public static final String PINNED = "pinned";
    public static final String PLAIN = "plain";

    /** What a handshake with the address showed: the leaf and whether it is acceptable as {@code ca} for the host. */
    public record Presented(ServerCertificate leaf, boolean validatesAsCa) {
    }

    private static final String[] PROTOCOLS = {"TLSv1.3", "TLSv1.2"};

    private final X509ExtendedTrustManager caTrust;

    /** @param trustedCas a PEM file with CA certificates added to the trust store of the JVM, or null */
    public ServerTls(Path trustedCas) {
        this.caTrust = caTrust(trustedCas);
    }

    private static X509ExtendedTrustManager caTrust(Path bundle) {
        try {
            TrustManagerFactory defaults = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            defaults.init((KeyStore) null);
            KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
            store.load(null, null);
            int index = 0;
            for (TrustManager manager : defaults.getTrustManagers()) {
                if (manager instanceof X509TrustManager x509) {
                    for (X509Certificate issuer : x509.getAcceptedIssuers()) {
                        store.setCertificateEntry("default-" + index++, issuer);
                    }
                }
            }
            if (bundle != null) {
                Collection<? extends Certificate> extra = read(bundle);
                if (extra.isEmpty()) {
                    throw new IllegalStateException(bundle + " (MCP_SERVER_TRUSTED_CAS) holds no certificate");
                }
                for (Certificate certificate : extra) {
                    store.setCertificateEntry("bundle-" + index++, certificate);
                }
            }
            TrustManagerFactory combined = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            combined.init(store);
            return Arrays.stream(combined.getTrustManagers()).filter(X509ExtendedTrustManager.class::isInstance)
                    .map(X509ExtendedTrustManager.class::cast).findFirst()
                    .orElseThrow(() -> new IllegalStateException("no X509 trust manager for the server trust"));
        } catch (GeneralSecurityException | IOException e) {
            throw new IllegalStateException("Cannot build the trust of the MCP servers" + (bundle == null ? ""
                    : " from " + bundle + " (MCP_SERVER_TRUSTED_CAS): a PEM file with CA certificates is expected"), e);
        }
    }

    private static Collection<? extends Certificate> read(Path bundle) throws IOException, CertificateException {
        try (InputStream in = Files.newInputStream(bundle)) {
            return CertificateFactory.getInstance("X.509").generateCertificates(in);
        }
    }

    /** The client for a server under the approved trust; {@code fingerprint} is used by {@code pinned} only. */
    public HttpClient client(String tlsMode, String fingerprint, Duration connectTimeout) {
        HttpClient.Builder builder = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1)
                .followRedirects(HttpClient.Redirect.NEVER).connectTimeout(connectTimeout)
                .executor(Executors.newVirtualThreadPerTaskExecutor());
        if (PLAIN.equals(tlsMode)) {
            return builder.build();
        }
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            TrustManager trust = PINNED.equals(tlsMode) ? new Pinned(fingerprint) : caTrust;
            context.init(null, new TrustManager[] {trust}, null);
            SSLParameters parameters = context.getDefaultSSLParameters();
            parameters.setProtocols(PROTOCOLS);
            if (CA.equals(tlsMode)) {
                parameters.setEndpointIdentificationAlgorithm("HTTPS");
            }
            return builder.sslContext(context).sslParameters(parameters).build();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Cannot build the TLS context for a server", e);
        }
    }

    /**
     * A handshake without a client certificate that accepts any certificate in order to read it. The leaf is returned with the verdict of
     * the {@code ca} trust for {@code host}: the chain, and the name. Nothing is sent over the connection.
     */
    public Presented probe(String host, int port, Duration timeout) throws IOException {
        Capturing capture = new Capturing(caTrust);
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, new TrustManager[] {capture}, null);
            int millis = (int) timeout.toMillis();
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(host, port), millis);
                socket.setSoTimeout(millis);
                try (SSLSocket ssl = (SSLSocket) context.getSocketFactory().createSocket(socket, host, port, true)) {
                    SSLParameters parameters = ssl.getSSLParameters();
                    parameters.setProtocols(PROTOCOLS);
                    parameters.setEndpointIdentificationAlgorithm("HTTPS");
                    if (AddressPolicy.parseLiteral(host).isEmpty()) {
                        parameters.setServerNames(List.of(new SNIHostName(host)));
                    }
                    ssl.setSSLParameters(parameters);
                    ssl.startHandshake();
                }
            }
        } catch (GeneralSecurityException e) {
            throw new IOException("TLS handshake failed", e);
        }
        X509Certificate[] chain = capture.chain;
        if (chain == null || chain.length == 0) {
            throw new IOException("the server presented no certificate");
        }
        return new Presented(ServerCertificate.of(chain[0]), capture.validates);
    }

    /** The leaf certificate of a response, from its TLS session. */
    public static Optional<ServerCertificate> leafOf(Optional<javax.net.ssl.SSLSession> session) {
        try {
            if (session.isPresent() && session.get().getPeerCertificates().length > 0
                    && session.get().getPeerCertificates()[0] instanceof X509Certificate leaf) {
                return Optional.of(ServerCertificate.of(leaf));
            }
        } catch (javax.net.ssl.SSLPeerUnverifiedException e) {
            return Optional.empty();
        }
        return Optional.empty();
    }

    /** Exactly one leaf certificate, by the SHA-256 of its DER encoding. */
    private static final class Pinned extends X509ExtendedTrustManager {
        private final String fingerprint;

        Pinned(String fingerprint) {
            this.fingerprint = fingerprint;
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            if (chain == null || chain.length == 0 || !fingerprint.equals(ServerCertificate.fingerprintOf(chain[0].getEncoded()))) {
                throw new CertificateException("the server certificate is not the pinned one");
            }
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
            return new X509Certificate[0];
        }
    }

    /** Accepts every certificate and notes the chain and whether the {@code ca} trust would have accepted it. */
    private static final class Capturing extends X509ExtendedTrustManager {
        private final X509ExtendedTrustManager ca;
        volatile X509Certificate[] chain;
        volatile boolean validates;

        Capturing(X509ExtendedTrustManager ca) {
            this.ca = ca;
        }

        private void record(X509Certificate[] presented, boolean valid) {
            this.chain = presented;
            this.validates = valid;
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) {
            boolean valid = true;
            try {
                ca.checkServerTrusted(chain, authType, socket);
            } catch (CertificateException e) {
                valid = false;
            }
            record(chain, valid);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {
            boolean valid = true;
            try {
                ca.checkServerTrusted(chain, authType, engine);
            } catch (CertificateException e) {
                valid = false;
            }
            record(chain, valid);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
            boolean valid = true;
            try {
                ca.checkServerTrusted(chain, authType);
            } catch (CertificateException e) {
                valid = false;
            }
            record(chain, valid);
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
            return new X509Certificate[0];
        }
    }
}
