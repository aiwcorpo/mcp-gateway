package pl.aiwcorpo.mcp.gateway.config;

import org.apache.catalina.connector.Connector;
import org.apache.coyote.http11.Http11NioProtocol;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;

/**
 * Second Tomcat connector: HTTPS with the gateway certificate (SAN = internal TLS name, CC-035) for the JWKS
 * of the internal JWT. No client certificate: servers present server-only certificates and the keys are public.
 */
public final class InternalConnector implements WebServerFactoryCustomizer<TomcatServletWebServerFactory> {

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
        protocol.setSSLEnabled(true);
        SSLHostConfig ssl = new SSLHostConfig();
        ssl.setProtocols("TLSv1.2+TLSv1.3");
        SSLHostConfigCertificate certificate = new SSLHostConfigCertificate(ssl, SSLHostConfigCertificate.Type.UNDEFINED);
        certificate.setCertificateKeystoreFile(keystore);
        certificate.setCertificateKeystorePassword(password);
        certificate.setCertificateKeystoreType("PKCS12");
        ssl.addCertificate(certificate);
        protocol.addSslHostConfig(ssl);
        factory.addAdditionalConnectors(connector);
    }
}
