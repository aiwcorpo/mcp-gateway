package pl.aiwcorpo.mcp.gateway.tls;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import pl.aiwcorpo.mcp.gateway.support.GatewayTestEnvironment;
import pl.aiwcorpo.mcp.gateway.support.TestPki;

/**
 * The identity of an MCP server is its serverId: the certificate must have the SAN {@code <serverId>.internal} and exactly one CN equal to the
 * serverId. A certificate that the internal CA issued to another server, or one that has only the name or only the CN right, is refused.
 */
class ServerCertificatePinningTest {

    private static TestPki pki;
    private static X509TrustManager pkix;

    @TempDir
    static Path dir;

    @BeforeAll
    static void ca() throws Exception {
        pki = new TestPki(dir);
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init(load(pki.truststore()));
        pkix = Arrays.stream(factory.getTrustManagers()).filter(X509TrustManager.class::isInstance).map(X509TrustManager.class::cast).findFirst()
                .orElseThrow();
    }

    private static KeyStore load(Path file) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(file)) {
            store.load(in, TestPki.PASSWORD);
        }
        return store;
    }

    private static X509Certificate[] chainOf(Path keystore) throws Exception {
        KeyStore store = load(keystore);
        String alias = store.aliases().nextElement();
        return Arrays.stream(store.getCertificateChain(alias)).map(X509Certificate.class::cast).toArray(X509Certificate[]::new);
    }

    private static void check(String serverId, String cn, List<String> sans) throws Exception {
        Path keystore = pki.issue(cn + "-" + sans.hashCode() + ".p12", cn, sans, true, true);
        PinnedNameTrustManager.forServer(pkix, serverId).checkServerTrusted(chainOf(keystore), "ECDHE_ECDSA");
    }

    @Test
    void theCertificateOfTheServerItselfIsAccepted() throws Exception {
        check("mcp-jira", "mcp-jira", List.of("mcp-jira.internal", "localhost"));
    }

    @Test
    void aCertificateOfAnotherServerOfTheSameCaIsRefused() {
        assertThatThrownBy(() -> check("mcp-jira", "mcp-gitlab", List.of("mcp-gitlab.internal"))).isInstanceOf(CertificateException.class);
    }

    @Test
    void aRightNameWithAnotherCnIsRefused() {
        assertThatThrownBy(() -> check("mcp-jira", "mcp-confluence", List.of("mcp-jira.internal"))).isInstanceOf(CertificateException.class)
                .hasMessageContaining("CN mcp-jira");
    }

    @Test
    void aRightCnWithAnotherNameIsRefused() {
        assertThatThrownBy(() -> check("mcp-jira", "mcp-jira", List.of("mcp-other.internal"))).isInstanceOf(CertificateException.class)
                .hasMessageContaining("SAN mcp-jira.internal");
    }

    @Test
    void aComponentOfThePlatformIsNoServer() {
        assertThatThrownBy(() -> check("mcp-jira", "mcp-gateway", List.of("mcp-gateway.internal"))).isInstanceOf(CertificateException.class);
    }

    @Test
    void theClientOfAServerRefusesTheCertificateOfAnotherOneInTheHandshake() throws Exception {
        GatewayTestEnvironment env = GatewayTestEnvironment.get();
        InternalTls tls = new InternalTls(env.gatewayKeystore, env.pki.truststore(), TestPki.PASSWORD);
        HttpRequest request = HttpRequest.newBuilder(URI.create("https://127.0.0.1:" + env.gitlab.port() + "/mcp-manifest"))
                .timeout(Duration.ofSeconds(5)).GET().build();

        HttpClient asJira = tls.clientForServer("mcp-jira", Duration.ofSeconds(5));
        assertThatThrownBy(() -> asJira.send(request, HttpResponse.BodyHandlers.ofString()))
                .as("the certificate of mcp-gitlab is valid for the internal CA and is not mcp-jira").isInstanceOf(java.io.IOException.class);

        HttpClient asGitlab = tls.clientForServer("mcp-gitlab", Duration.ofSeconds(5));
        assertThat(asGitlab.send(request, HttpResponse.BodyHandlers.ofString()).statusCode()).as("the right server answers (401: no token)")
                .isEqualTo(401);
    }
}
