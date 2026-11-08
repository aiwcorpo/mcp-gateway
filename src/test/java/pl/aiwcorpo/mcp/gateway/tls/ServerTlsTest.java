package pl.aiwcorpo.mcp.gateway.tls;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.time.Duration;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;

import pl.aiwcorpo.mcp.gateway.support.GatewayTestEnvironment;
import pl.aiwcorpo.mcp.testserver.TestMcpServer;

/**
 * How the gateway trusts the certificate of an MCP server (C5, CC-249) on real TLS servers: {@code ca} (the chain leads to the default trust
 * store of the JVM or the bundle {@code MCP_SERVER_TRUSTED_CAS}, and the certificate names the host), {@code pinned} (exactly one
 * certificate by the SHA-256 of its DER, no chain, no name) and {@code plain}; no client certificate in any of them.
 */
class ServerTlsTest {

    private static final GatewayTestEnvironment env = GatewayTestEnvironment.get();
    private static final ServerTls WITH_BUNDLE = new ServerTls(env.serverCas);
    private static final ServerTls DEFAULTS_ONLY = new ServerTls(null);
    private static TestMcpServer selfSigned;
    private static TestMcpServer otherHost;
    private static TestMcpServer plain;

    static {
        try {
            selfSigned = env.startSelfSignedServer("mcp-selfsigned");
            otherHost = env.startServerForAnotherHost("mcp-elsewhere");
            plain = env.startPlainServer("mcp-plain");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @AfterAll
    static void stop() {
        selfSigned.close();
        otherHost.close();
        plain.close();
    }

    private static HttpResponse<String> get(HttpClient client, TestMcpServer server, String scheme) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create(scheme + "://127.0.0.1:" + server.port() + "/.well-known/mcp-manifest"))
                .timeout(Duration.ofSeconds(5)).GET().build(), HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void caAcceptsACertificateOfTheBundleThatNamesTheHost() throws Exception {
        HttpResponse<String> response = get(WITH_BUNDLE.client(ServerTls.CA, null, Duration.ofSeconds(5)), env.jira, "https");

        assertThat(response.statusCode()).as("the server answers (401: no token); the handshake held").isEqualTo(401);
    }

    @Test
    void caWithoutTheBundleKnowsOnlyTheDefaultTrustOfTheJvm() {
        assertThatThrownBy(() -> get(DEFAULTS_ONLY.client(ServerTls.CA, null, Duration.ofSeconds(5)), env.jira, "https"))
                .as("the CA of the tests is in no default store").isInstanceOf(IOException.class);
    }

    @Test
    void caChecksTheNameOfTheHostAsWellAsTheChain() {
        assertThatThrownBy(() -> get(WITH_BUNDLE.client(ServerTls.CA, null, Duration.ofSeconds(5)), otherHost, "https"))
                .as("signed by the CA, but for another host").isInstanceOf(IOException.class);
    }

    @Test
    void caRefusesASelfSignedCertificate() {
        assertThatThrownBy(() -> get(WITH_BUNDLE.client(ServerTls.CA, null, Duration.ofSeconds(5)), selfSigned, "https"))
                .isInstanceOf(IOException.class);
    }

    @Test
    void pinnedAcceptsExactlyTheOneCertificateWithNoChainAndNoName() throws Exception {
        for (TestMcpServer server : new TestMcpServer[] {selfSigned, otherHost}) {
            HttpResponse<String> response = get(DEFAULTS_ONLY.client(ServerTls.PINNED, env.fingerprint(server), Duration.ofSeconds(5)), server, "https");
            assertThat(response.statusCode()).as("self-signed, and a certificate for another host, both pinned").isEqualTo(401);
        }
    }

    @Test
    void pinnedRefusesAnyOtherCertificateEvenOneThatValidatesAsCa() {
        assertThatThrownBy(() -> get(WITH_BUNDLE.client(ServerTls.PINNED, env.fingerprint(selfSigned), Duration.ofSeconds(5)), env.jira, "https"))
                .isInstanceOf(IOException.class);
        assertThatThrownBy(() -> get(WITH_BUNDLE.client(ServerTls.PINNED, env.fingerprint(env.jira), Duration.ofSeconds(5)), selfSigned, "https"))
                .isInstanceOf(IOException.class);
    }

    @Test
    void plainSpeaksHttpToAServerThatDoesNotSpeakTls() throws Exception {
        HttpResponse<String> response = get(WITH_BUNDLE.client(ServerTls.PLAIN, null, Duration.ofSeconds(5)), plain, "http");

        assertThat(response.statusCode()).isEqualTo(401);
    }

    @Test
    void theGatewayPresentsNoClientCertificateInAnyMode() throws Exception {
        HttpClient client = WITH_BUNDLE.client(ServerTls.CA, null, Duration.ofSeconds(5));
        HttpResponse<String> response = get(client, env.jira, "https");

        assertThat(response.sslSession()).isPresent();
        assertThat(response.sslSession().get().getLocalCertificates()).as("nothing was sent to the server").isNull();
    }

    @Test
    void theProbeReadsTheLeafAndSaysWhetherItValidatesAsCaForTheHost() throws Exception {
        ServerTls.Presented signed = WITH_BUNDLE.probe("127.0.0.1", env.jira.port(), Duration.ofSeconds(5));
        assertThat(signed.validatesAsCa()).isTrue();
        assertThat(signed.leaf().fingerprint()).isEqualTo(env.fingerprint(env.jira)).matches("^sha256:[0-9a-f]{64}$");
        assertThat(signed.leaf().subject()).isEqualTo("CN=mcp-jira");
        assertThat(signed.leaf().issuer()).isEqualTo("CN=test-internal-ca");
        assertThat(signed.leaf().sans()).contains("127.0.0.1", "localhost");
        assertThat(signed.leaf().notAfter()).isAfter(java.time.Instant.now());

        ServerTls.Presented own = WITH_BUNDLE.probe("127.0.0.1", selfSigned.port(), Duration.ofSeconds(5));
        assertThat(own.validatesAsCa()).as("self-signed").isFalse();
        assertThat(own.leaf().fingerprint()).isEqualTo(env.fingerprint(selfSigned));

        assertThat(WITH_BUNDLE.probe("127.0.0.1", otherHost.port(), Duration.ofSeconds(5)).validatesAsCa()).as("for another host").isFalse();
        assertThat(DEFAULTS_ONLY.probe("127.0.0.1", env.jira.port(), Duration.ofSeconds(5)).validatesAsCa()).as("without the bundle").isFalse();
    }

    @Test
    void theProbeFailsForAnAddressThatSpeaksNoTls() {
        assertThatThrownBy(() -> WITH_BUNDLE.probe("127.0.0.1", plain.port(), Duration.ofSeconds(5))).isInstanceOf(IOException.class);
    }

    @Test
    void aBundleThatHoldsNoCertificateStopsTheStart(@org.junit.jupiter.api.io.TempDir Path dir) throws Exception {
        Path empty = dir.resolve("empty.pem");
        java.nio.file.Files.writeString(empty, "no certificate here\n");

        assertThatThrownBy(() -> new ServerTls(empty)).isInstanceOf(IllegalStateException.class).hasMessageContaining("MCP_SERVER_TRUSTED_CAS");
        assertThatThrownBy(() -> new ServerTls(dir.resolve("missing.pem"))).isInstanceOf(IllegalStateException.class);
    }
}
