package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import pl.aiwcorpo.mcp.gateway.support.GatewayProcess;
import pl.aiwcorpo.mcp.gateway.support.GatewayTestEnvironment;
import pl.aiwcorpo.mcp.gateway.support.TestPki;
import pl.aiwcorpo.mcp.testserver.Tls;

/**
 * Optional TLS on the public port: a gateway started as a process of its own with a PEM certificate and key of the test CA. A client
 * that trusts the CA is served, one that trusts another CA is refused in the handshake, plain http gets nothing, TLS 1.2 and 1.3
 * are negotiated, and the internal port (health, JWKS) is unchanged.
 */
class PublicTlsTest {

    private static final String METADATA = "/.well-known/oauth-protected-resource/mcp";

    private static GatewayTestEnvironment env;
    private static GatewayProcess gateway;
    private static SSLContext trusting;
    private static SSLContext foreign;

    @BeforeAll
    static void startGatewayWithPublicTls() throws Exception {
        env = GatewayTestEnvironment.get();
        Path dir = Files.createTempDirectory("mcp-gateway-public-tls");
        List<Path> pem = env.pki.issuePem("public", "mcp-gateway-public", List.of("localhost", "127.0.0.1"), "rw-------");
        trusting = Tls.fromKeyStores(null, TestPki.PASSWORD, load(env.pki.truststore()));
        TestPki other = new TestPki(Files.createDirectory(dir.resolve("other-ca")));
        foreign = Tls.fromKeyStores(null, TestPki.PASSWORD, load(other.truststore()));

        gateway = startWith("public-tls", dir, pem.get(0).toString(), pem.get(1).toString(), null);
    }

    private static GatewayProcess startWith(String name, Path dir, String certificate, String key, String password) throws Exception {
        Map<String, String> properties = new LinkedHashMap<>(env.properties());
        properties.remove("gateway.internal-endpoint.port");
        properties.put("gateway.public-tls.enabled", "true");
        properties.put("gateway.public-tls.certificate", certificate);
        properties.put("gateway.public-tls.private-key", key);
        if (password != null) {
            properties.put("gateway.public-tls.private-key-password", password);
        }
        properties.put("gateway.policy.state-dir", Files.createDirectories(dir.resolve("state-" + name)).toString());
        return GatewayProcess.startWithPublicTls(name, dir, properties, GatewayProcess.freePort(), GatewayProcess.freePort(), trusting);
    }

    @AfterAll
    static void stop() {
        if (gateway != null) {
            gateway.close();
        }
    }

    private static KeyStore load(Path file) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (var in = Files.newInputStream(file)) {
            store.load(in, TestPki.PASSWORD);
        }
        return store;
    }

    private static HttpResponse<String> get(HttpClient client, String url) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(10)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void aClientThatTrustsTheCaIsServedOverTls13() throws Exception {
        HttpResponse<String> response = get(HttpClient.newBuilder().sslContext(trusting).build(),
                "https://localhost:" + gateway.port() + METADATA);
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.sslSession()).isPresent();
        assertThat(response.sslSession().get().getProtocol()).isEqualTo("TLSv1.3");
    }

    @Test
    void tls12IsStillAccepted() throws Exception {
        SSLParameters only12 = new SSLParameters();
        only12.setProtocols(new String[] {"TLSv1.2"});
        HttpResponse<String> response = get(HttpClient.newBuilder().sslContext(trusting).sslParameters(only12).build(),
                "https://localhost:" + gateway.port() + METADATA);
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.sslSession().orElseThrow().getProtocol()).isEqualTo("TLSv1.2");
    }

    @Test
    void aClientThatTrustsAnotherCaIsRefusedInTheHandshake() {
        assertThatThrownBy(() -> get(HttpClient.newBuilder().sslContext(foreign).build(),
                "https://localhost:" + gateway.port() + METADATA)).isInstanceOf(SSLHandshakeException.class);
    }

    @Test
    void plainHttpOnTheTlsPortIsAnswered400() throws Exception {
        HttpResponse<String> response = get(HttpClient.newHttpClient(), "http://localhost:" + gateway.port() + METADATA);
        assertThat(response.statusCode()).isEqualTo(400);
    }

    @Test
    void theInternalPortKeepsItsHealthEndpointAndMetricsGuard() throws Exception {
        HttpClient internal = HttpClient.newBuilder().sslContext(env.gatewayClientTls).build();
        assertThat(get(internal, "https://localhost:" + gateway.internalPort() + "/actuator/health").statusCode()).isEqualTo(200);
        assertThat(get(internal, "https://localhost:" + gateway.internalPort() + "/.well-known/jwks.json").statusCode()).isEqualTo(200);
        assertThat(get(internal, "https://localhost:" + gateway.internalPort() + "/actuator/prometheus").statusCode()).isIn(401, 403, 404);
    }

    @Test
    void theActuatorIsNotServedOnThePublicPortWithTlsEither() throws Exception {
        HttpClient client = HttpClient.newBuilder().sslContext(trusting).build();
        assertThat(get(client, "https://localhost:" + gateway.port() + "/actuator/health").statusCode()).isNotEqualTo(200);
    }

    @Test
    void anEncryptedKeyStartsWithItsPasswordAndTheFilePrefixIsAccepted() throws Exception {
        Path dir = Files.createTempDirectory("mcp-gateway-public-tls-encrypted");
        List<Path> pem = env.pki.issueEncryptedPem("encrypted", "mcp-gateway-public", List.of("localhost"), "key-password-1");
        try (GatewayProcess encrypted = startWith("encrypted", dir, "file:" + pem.get(0), "file:" + pem.get(1), "key-password-1")) {
            HttpResponse<String> response = get(HttpClient.newBuilder().sslContext(trusting).build(),
                    "https://localhost:" + encrypted.port() + METADATA);
            assertThat(response.statusCode()).isEqualTo(200);
        }
    }

    @Test
    void aWrongOrMissingKeyPasswordStopsTheStartWithoutPrintingIt() throws Exception {
        Path dir = Files.createTempDirectory("mcp-gateway-public-tls-wrong");
        List<Path> pem = env.pki.issueEncryptedPem("wrong", "mcp-gateway-public", List.of("localhost"), "key-password-1");
        for (String password : new String[] {"not-the-password-2", null}) {
            assertThatThrownBy(() -> startWith("wrong", dir, pem.get(0).toString(), pem.get(1).toString(), password).close())
                    .isInstanceOf(IllegalStateException.class).hasMessageContaining("exited")
                    .hasMessageNotContaining("not-the-password-2").hasMessageNotContaining("key-password-1");
        }
    }
}
