package pl.aiwcorpo.mcp.gateway.config;

import org.apache.catalina.connector.Connector;
import org.apache.coyote.http11.Http11NioProtocol;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.apache.tomcat.util.threads.VirtualThreadExecutor;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;

/**
 * Second Tomcat connector: HTTPS with the gateway certificate (SAN = internal TLS name, CC-035) for the JWKS
 * of the internal JWT, the actuator and the C5 admin API. A client certificate is requested but not judged by the
 * TLS stack (servers fetching the JWKS may send one that is valid only for serverAuth); the BFF presents its own
 * and {@code AdminClientCertificateFilter} verifies it on {@code /admin/v1}.
 * <p>
 * Spring Boot's customizers reach only the primary connector, so this one is given the same virtual threads here: a peer that holds a
 * request open holds no worker that others wait for. It waits at most 10 s for what a peer sends, and a body the gateway did not read
 * (a refused request) is not read to its end: the connection is closed after the answer.
 */
public final class InternalConnector implements WebServerFactoryCustomizer<TomcatServletWebServerFactory> {

    private static final int CONNECTION_TIMEOUT_MILLIS = 10_000;

    private final int port;
    private final String keystore;
    private final String password;

    public InternalConnector(int port, String keystore, String password) {
        this.port = port;
        this.keystore = keystore;
        this.password = password;
    }

    @Override
    public void customize(TomcatServletWebServerFactory factory) {
        Connector connector = new Connector(Http11NioProtocol.class.getName());
        connector.setPort(port);
        connector.setScheme("https");
        connector.setSecure(true);
        Http11NioProtocol protocol = (Http11NioProtocol) connector.getProtocolHandler();
        protocol.setExecutor(new VirtualThreadExecutor("tomcat-internal-"));
        protocol.setConnectionTimeout(CONNECTION_TIMEOUT_MILLIS);
        protocol.setMaxSwallowSize(0);
        protocol.setSSLEnabled(true);
        SSLHostConfig ssl = new SSLHostConfig();
        ssl.setProtocols("TLSv1.2+TLSv1.3");
        ssl.setCertificateVerification("optional");
        ssl.setTrustManagerClassName(AcceptAnyClientCertificate.class.getName());
        SSLHostConfigCertificate certificate = new SSLHostConfigCertificate(ssl, SSLHostConfigCertificate.Type.UNDEFINED);
        certificate.setCertificateKeystoreFile(keystore);
        certificate.setCertificateKeystorePassword(password);
        certificate.setCertificateKeystoreType("PKCS12");
        ssl.addCertificate(certificate);
        protocol.addSslHostConfig(ssl);
        factory.addAdditionalConnectors(connector);
    }
}
