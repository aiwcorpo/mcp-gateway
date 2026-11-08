package pl.aiwcorpo.mcp.gateway.link;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import pl.aiwcorpo.mcp.gateway.jwt.InternalTokenIssuer;
import pl.aiwcorpo.mcp.gateway.net.AddressPolicy;
import pl.aiwcorpo.mcp.gateway.support.TestPki;
import pl.aiwcorpo.mcp.gateway.tls.ServerTls;
import pl.aiwcorpo.mcp.gateway.upstream.StreamableHttpClient;
import pl.aiwcorpo.mcp.gateway.upstream.UpstreamException;
import pl.aiwcorpo.mcp.gateway.upstream.UpstreamRequest;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.IntNode;

/**
 * The address check right before a connection (C5, CC-249, vector address-refusal/refused-address-before-connection): the name of the server
 * is resolved again and one refused address refuses the connection, for the probe, the manifest pull, the policy-data push and tool calls. The
 * name is {@code localhost}, which the JDK client resolves to the listeners below, so a request that the check let through would arrive there.
 * TLS ({@code ca}, {@code pinned}) is what stops a rebinding name from being trusted; the check only refuses the address.
 */
class ServerLinksAddressCheckTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    @TempDir
    Path dir;

    private final AtomicInteger accepted = new AtomicInteger();
    private final AtomicReference<List<String>> answer = new AtomicReference<>(List.of("127.0.0.1"));
    private SSLServerSocket tls;
    private ServerSocket plain;
    private String fingerprint;
    private ServerLinks links;

    @BeforeEach
    void start() throws Exception {
        Path keystore = TestPki.selfSigned(dir, "listener.p12", "localhost", List.of("localhost", "127.0.0.1"));
        fingerprint = TestPki.fingerprint(keystore);
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(keystore)) {
            store.load(in, TestPki.PASSWORD);
        }
        KeyManagerFactory keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keys.init(store, TestPki.PASSWORD);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keys.getKeyManagers(), null, null);
        tls = (SSLServerSocket) context.getServerSocketFactory().createServerSocket(0, 50, InetAddress.getByName("127.0.0.1"));
        plain = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"));
        Thread.ofVirtual().start(() -> serve(tls));
        Thread.ofVirtual().start(() -> serve(plain));

        AddressPolicy policy = new AddressPolicy(true, host -> {
            try {
                java.util.List<InetAddress> resolved = new java.util.ArrayList<>();
                for (String literal : answer.get()) {
                    resolved.add(InetAddress.getByAddress(host, AddressPolicy.parseLiteral(literal).orElseThrow()));
                }
                return resolved;
            } catch (java.net.UnknownHostException e) {
                throw new IllegalStateException(e);
            }
        });
        InternalTokenIssuer tokens = mock(InternalTokenIssuer.class);
        when(tokens.forManifest(anyString(), anyString())).thenReturn("manifest-token");
        when(tokens.forPolicyData(anyString(), anyString(), anyLong())).thenReturn("policy-data-token");
        links = new ServerLinks(policy, new ServerTls(null), tokens, JSON);
    }

    @AfterEach
    void stop() throws IOException {
        tls.close();
        plain.close();
    }

    private void serve(ServerSocket listener) {
        while (!listener.isClosed()) {
            try (java.net.Socket socket = listener.accept()) {
                accepted.incrementAndGet();
                socket.setSoTimeout(1000);
                socket.getInputStream().read();
            } catch (IOException e) {
                // a probe or a refused client closes the connection at once
            }
        }
    }

    private URI tlsUrl() {
        return URI.create("https://localhost:" + tls.getLocalPort() + "/mcp");
    }

    private URI plainUrl() {
        return URI.create("http://localhost:" + plain.getLocalPort() + "/mcp");
    }

    private static UpstreamRequest call() {
        return new UpstreamRequest("call-token", "rid-1", null, "2025-11-25", null, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}");
    }

    @Test
    void anAllowedNameIsConnectedToAndTheListenerSeesIt() throws Exception {
        assertThat(links.checkAddress(tlsUrl())).isEmpty();

        ServerLinks.Pull pull = links.pullManifest(tlsUrl(), "mcp-test", ServerTls.PINNED, fingerprint);

        assertThat(pull.failure()).as("the listener speaks no HTTP, the connection itself is what is shown").isNotEqualTo(ServerLinks.Failure.ADDRESS_REFUSED);
        assertThat(accepted.get()).isPositive();
    }

    @Test
    void oneRefusedAddressAmongTheResolvedOnesMeansNoRequestIsSentForAnyKindOfRequest() throws Exception {
        for (List<String> resolved : List.of(List.of("169.254.169.254"), List.of("127.0.0.1", "169.254.169.254"), List.of("100.100.100.200"),
                List.of("192.0.0.192"), List.of("fd00:ec2::254"), List.of("10.0.0.5", "::ffff:100.100.100.200"))) {
            answer.set(resolved);
            int before = accepted.get();

            assertThat(links.pullManifest(tlsUrl(), "mcp-test", ServerTls.PINNED, fingerprint).failure()).as(resolved.toString())
                    .isEqualTo(ServerLinks.Failure.ADDRESS_REFUSED);
            assertThat(links.pushPolicyData(tlsUrl(), "mcp-test", ServerTls.PINNED, fingerprint, 1, JSON.readTree("{}")).failure())
                    .isEqualTo(ServerLinks.Failure.ADDRESS_REFUSED);
            assertThat(links.pullManifest(plainUrl(), "mcp-test", ServerTls.PLAIN, null).failure()).isEqualTo(ServerLinks.Failure.ADDRESS_REFUSED);
            assertThat(links.pushPolicyData(plainUrl(), "mcp-test", ServerTls.PLAIN, null, 1, JSON.readTree("{}")).failure())
                    .isEqualTo(ServerLinks.Failure.ADDRESS_REFUSED);
            assertThatThrownBy(() -> links.probe(tlsUrl())).isInstanceOf(ServerLinks.AddressRefused.class);
            assertThat(accepted.get()).as("nothing arrived at the listeners").isEqualTo(before);
        }
    }

    @Test
    void aToolCallIsRefusedBeforeAnyConnectionOverTlsAndPlain() throws Exception {
        answer.set(List.of("169.254.169.254"));
        StreamableHttpClient overTls = new StreamableHttpClient(tlsUrl(), links.client(ServerTls.PINNED, fingerprint), JSON, Duration.ofSeconds(3), 1 << 20,
                () -> links.checkAddress(tlsUrl()).map(AddressPolicy.Refusal::message));
        StreamableHttpClient overPlain = new StreamableHttpClient(plainUrl(), links.client(ServerTls.PLAIN, null), JSON, Duration.ofSeconds(3), 1 << 20,
                () -> links.checkAddress(plainUrl()).map(AddressPolicy.Refusal::message));

        for (StreamableHttpClient client : List.of(overTls, overPlain)) {
            assertThatThrownBy(() -> client.post(call(), IntNode.valueOf(1))).isInstanceOfSatisfying(UpstreamException.class, e -> {
                assertThat(e.kind()).isEqualTo(UpstreamException.Kind.UNAVAILABLE);
                assertThat(e.getMessage()).startsWith("address_refused");
            });
        }

        assertThat(accepted.get()).isZero();
    }

    @Test
    void theCheckIsMadeAgainForEveryConnectionSoANameThatTurnsBadIsRefusedFromThenOn() throws Exception {
        assertThat(links.checkAddress(plainUrl())).isEmpty();
        answer.set(List.of("127.0.0.1", "169.254.169.254"));

        assertThat(links.checkAddress(plainUrl())).hasValueSatisfying(refusal -> assertThat(refusal.cls()).isEqualTo("link_local"));
        answer.set(List.of("127.0.0.1"));
        assertThat(links.checkAddress(plainUrl())).isEmpty();
    }
}
