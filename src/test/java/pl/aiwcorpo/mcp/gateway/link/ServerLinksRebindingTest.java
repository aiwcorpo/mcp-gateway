package pl.aiwcorpo.mcp.gateway.link;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
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

import com.sun.net.httpserver.HttpServer;

import pl.aiwcorpo.mcp.gateway.jwt.InternalTokenIssuer;
import pl.aiwcorpo.mcp.gateway.net.AddressPolicy;
import pl.aiwcorpo.mcp.gateway.support.TestPki;
import pl.aiwcorpo.mcp.gateway.tls.ServerTls;
import pl.aiwcorpo.mcp.gateway.upstream.StreamableHttpClient;
import pl.aiwcorpo.mcp.gateway.upstream.UpstreamException;
import pl.aiwcorpo.mcp.gateway.upstream.UpstreamRequest;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.IntNode;

/**
 * DNS rebinding at connect time (CC-249, vector address-refusal/rebinding-at-connect-time): the name of a server resolves to an allowed address
 * when the connection is made and to a refused one afterwards. The name exists only in the resolver of the test, so every connection that
 * succeeds proves that it was made through the address policy, and a refused one must not reach the listener that stands for loopback or
 * for the metadata service: no TCP connection arrives there, for the probe, the manifest pull, the policy-data push and the tool calls.
 */
class ServerLinksRebindingTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final String NAME = "rebind.test";

    @TempDir
    Path dir;

    private final AtomicInteger resolutions = new AtomicInteger();
    private final AtomicInteger accepted = new AtomicInteger();
    private final AtomicInteger plainRequests = new AtomicInteger();
    private final AtomicReference<String> answer = new AtomicReference<>("127.0.0.1");
    private SSLServerSocket tlsServer;
    private HttpServer plainServer;
    private String fingerprint;
    private ServerLinks links;

    @BeforeEach
    void start() throws Exception {
        Path keystore = TestPki.selfSigned(dir, "rebind.p12", NAME, List.of(NAME));
        fingerprint = TestPki.fingerprint(keystore);
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(keystore)) {
            store.load(in, TestPki.PASSWORD);
        }
        KeyManagerFactory keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keys.init(store, TestPki.PASSWORD);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keys.getKeyManagers(), null, null);
        tlsServer = (SSLServerSocket) context.getServerSocketFactory().createServerSocket(0, 50, InetAddress.getLoopbackAddress());
        Thread.ofVirtual().start(this::serveTls);

        plainServer = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        plainServer.createContext("/", exchange -> {
            plainRequests.incrementAndGet();
            exchange.getRequestBody().readAllBytes();
            byte[] body = "{\"ok\":true}".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        plainServer.start();

        AddressPolicy policy = new AddressPolicy(true, host -> {
            resolutions.incrementAndGet();
            try {
                return List.of(InetAddress.getByAddress(host, AddressPolicy.parseLiteral(answer.get()).orElseThrow()));
            } catch (java.net.UnknownHostException e) {
                throw new IllegalStateException(e);
            }
        });
        InternalTokenIssuer tokens = mock(InternalTokenIssuer.class);
        when(tokens.forManifest(anyString(), anyString())).thenReturn("manifest-token");
        when(tokens.forPolicyData(anyString(), anyString(), anyLong())).thenReturn("policy-data-token");
        links = new ServerLinks(policy, new ServerTls(null), tokens, JSON, Duration.ofSeconds(2));
    }

    @AfterEach
    void stop() throws IOException {
        links.close();
        tlsServer.close();
        plainServer.stop(0);
    }

    private void serveTls() {
        while (!tlsServer.isClosed()) {
            try (Socket socket = tlsServer.accept()) {
                accepted.incrementAndGet();
                socket.setSoTimeout(3000);
                InputStream in = socket.getInputStream();
                int state = 0;
                while (state < 4) {
                    int next = in.read();
                    if (next < 0) {
                        break;
                    }
                    state = (next == '\r' && (state == 0 || state == 2)) || (next == '\n' && (state == 1 || state == 3)) ? state + 1 : next == '\r' ? 1 : 0;
                }
                OutputStream out = socket.getOutputStream();
                out.write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}"
                        .getBytes(StandardCharsets.US_ASCII));
                out.flush();
            } catch (IOException e) {
                // a probe closes the connection after its handshake
            }
        }
    }

    private URI tlsUrl() {
        return URI.create("https://" + NAME + ":" + tlsServer.getLocalPort() + "/mcp");
    }

    private URI plainUrl() {
        return URI.create("http://" + NAME + ":" + plainServer.getAddress().getPort() + "/mcp");
    }

    private static UpstreamRequest call() {
        return new UpstreamRequest("call-token", "rid-1", null, "2025-11-25", null,
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}");
    }

    @Test
    void theNameIsConnectedThroughTheAddressPolicyAndOnlyOnceForEveryConnection() throws Exception {
        ServerLinks.Pull pull = links.pullManifest(tlsUrl(), "mcp-test", ServerTls.PINNED, fingerprint);

        assertThat(pull.succeeded()).as(String.valueOf(pull.message())).isTrue();
        assertThat(resolutions.get()).as("the client did not resolve the name on its own").isEqualTo(1);
        assertThat(accepted.get()).isEqualTo(1);
    }

    @Test
    void afterTheAnswerChangedToTheMetadataAddressNoConnectionIsMadeForAnyKindOfRequest() throws Exception {
        assertThat(links.pullManifest(tlsUrl(), "mcp-test", ServerTls.PINNED, fingerprint).succeeded()).isTrue();
        assertThat(links.pushPolicyData(tlsUrl(), "mcp-test", ServerTls.PINNED, fingerprint, 1, JSON.readTree("{}")).delivered()).isTrue();
        assertThat(links.probe(tlsUrl()).leaf().fingerprint()).isEqualTo(fingerprint);
        int before = accepted.get();
        int before80 = plainRequests.get();

        for (String refused : List.of("169.254.169.254", "100.100.100.200", "192.0.0.192", "fd00:ec2::254")) {
            answer.set(refused);

            ServerLinks.Pull pull = links.pullManifest(tlsUrl(), "mcp-test", ServerTls.PINNED, fingerprint);
            assertThat(pull.failure()).as(refused).isEqualTo(ServerLinks.Failure.ADDRESS_REFUSED);
            assertThat(links.pushPolicyData(tlsUrl(), "mcp-test", ServerTls.PINNED, fingerprint, 2, JSON.readTree("{}")).failure())
                    .as(refused).isEqualTo(ServerLinks.Failure.ADDRESS_REFUSED);
            assertThatThrownBy(() -> links.probe(tlsUrl())).as(refused).isInstanceOf(ServerLinks.AddressRefused.class);
            assertThat(links.pullManifest(plainUrl(), "mcp-test", ServerTls.PLAIN, null).failure()).as(refused)
                    .isEqualTo(ServerLinks.Failure.ADDRESS_REFUSED);
            assertThat(links.pushPolicyData(plainUrl(), "mcp-test", ServerTls.PLAIN, null, 2, JSON.readTree("{}")).failure()).as(refused)
                    .isEqualTo(ServerLinks.Failure.ADDRESS_REFUSED);
        }

        assertThat(accepted.get()).as("no TLS connection reached the listener").isEqualTo(before);
        assertThat(plainRequests.get()).as("no plain request reached the server").isEqualTo(before80);
    }

    @Test
    void aToolCallAfterTheAnswerChangedIsRefusedBeforeAnyByteIsSentOverTlsAndPlain() throws Exception {
        HttpClient tls = links.client(ServerTls.PINNED, fingerprint);
        HttpClient plain = links.client(ServerTls.PLAIN, null);
        StreamableHttpClient over = new StreamableHttpClient(tlsUrl(), tls, JSON, Duration.ofSeconds(3), 1 << 20, links::target);
        StreamableHttpClient overPlain = new StreamableHttpClient(plainUrl(), plain, JSON, Duration.ofSeconds(3), 1 << 20, links::target);
        answer.set("169.254.169.254");

        for (StreamableHttpClient client : List.of(over, overPlain)) {
            assertThatThrownBy(() -> client.post(call(), IntNode.valueOf(1))).isInstanceOfSatisfying(UpstreamException.class, e -> {
                assertThat(e.kind()).isEqualTo(UpstreamException.Kind.UNAVAILABLE);
                assertThat(e.getMessage()).startsWith("address_refused");
            });
        }

        assertThat(accepted.get()).isZero();
        assertThat(plainRequests.get()).isZero();
    }

    @Test
    void aToolCallBeforeTheChangeReachesTheServerThroughTheSameClient() throws Exception {
        StreamableHttpClient client = new StreamableHttpClient(plainUrl(), links.client(ServerTls.PLAIN, null), JSON, Duration.ofSeconds(3), 1 << 20,
                links::target);
        JsonNode expectedId = IntNode.valueOf(1);

        assertThatThrownBy(() -> client.post(call(), expectedId)).as("the server answers 200 without a JSON-RPC response").isInstanceOf(UpstreamException.class)
                .satisfies(e -> assertThat(((UpstreamException) e).kind()).isNotEqualTo(UpstreamException.Kind.UNAVAILABLE));
        assertThat(plainRequests.get()).isEqualTo(1);
    }
}
