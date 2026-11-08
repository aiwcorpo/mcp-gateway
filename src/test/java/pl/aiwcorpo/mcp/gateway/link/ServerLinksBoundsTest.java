package pl.aiwcorpo.mcp.gateway.link;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicBoolean;

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
import tools.jackson.databind.json.JsonMapper;

/**
 * What a server can make the gateway hold (review of CC-249): a certificate that changes at every handshake must not leave an HTTP client
 * and its selector thread behind for each, and a server that sends its answer one byte at a time must not hold a pull or a push past the
 * deadline.
 */
class ServerLinksBoundsTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final Duration DEADLINE = Duration.ofSeconds(1);

    @TempDir
    Path dir;

    private SSLServerSocket tls;
    private ServerSocket dripping;
    private final AtomicBoolean running = new AtomicBoolean(true);
    private ServerLinks links;

    @BeforeEach
    void start() throws Exception {
        Path keystore = TestPki.selfSigned(dir, "listener.p12", "localhost", List.of("localhost", "127.0.0.1"));
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(keystore)) {
            store.load(in, TestPki.PASSWORD);
        }
        KeyManagerFactory keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keys.init(store, TestPki.PASSWORD);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keys.getKeyManagers(), null, null);
        tls = (SSLServerSocket) context.getServerSocketFactory().createServerSocket(0, 50, InetAddress.getByName("127.0.0.1"));
        dripping = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"));
        Thread.ofVirtual().start(this::closeAtOnce);
        Thread.ofVirtual().start(this::dripForever);
        InternalTokenIssuer tokens = mock(InternalTokenIssuer.class);
        when(tokens.forPolicyData(anyString(), anyString(), anyLong())).thenReturn("policy-data-token");
        links = new ServerLinks(new AddressPolicy(true), new ServerTls(null), tokens, JSON, DEADLINE);
    }

    @AfterEach
    void stop() throws IOException {
        running.set(false);
        tls.close();
        dripping.close();
    }

    private void closeAtOnce() {
        while (!tls.isClosed()) {
            try (Socket socket = tls.accept()) {
                socket.setSoTimeout(1000);
                socket.getInputStream().read();
            } catch (IOException e) {
                // the client refused the certificate and went away
            }
        }
    }

    private void dripForever() {
        while (!dripping.isClosed()) {
            try {
                Socket socket = dripping.accept();
                Thread.ofVirtual().start(() -> drip(socket));
            } catch (IOException e) {
                return;
            }
        }
    }

    private void drip(Socket socket) {
        try (socket) {
            InputStream in = socket.getInputStream();
            int matched = 0;
            while (matched < 4) {
                int b = in.read();
                if (b < 0) {
                    return;
                }
                matched = (b == '\r' && (matched == 0 || matched == 2)) || (b == '\n' && (matched == 1 || matched == 3)) ? matched + 1 : 0;
            }
            OutputStream out = socket.getOutputStream();
            out.write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100000\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
            out.flush();
            while (running.get()) {
                out.write('{');
                out.flush();
                Thread.sleep(100);
            }
        } catch (IOException | InterruptedException e) {
            // the gateway closed the connection at its deadline
        }
    }

    private static long selectorThreads() {
        return Thread.getAllStackTraces().keySet().stream().filter(t -> t.getName().contains("SelectorManager") && t.isAlive()).count();
    }

    private static String randomFingerprint() {
        byte[] bytes = new byte[32];
        ThreadLocalRandom.current().nextBytes(bytes);
        return "sha256:" + HexFormat.of().formatHex(bytes);
    }

    @Test
    void manyFingerprintsChosenByTheServerBeforeTheApprovalLeaveNoClientAndNoThreadBehind() throws Exception {
        URI url = URI.create("https://localhost:" + tls.getLocalPort() + "/mcp");
        long threadsBefore = selectorThreads();

        for (int i = 0; i < 40; i++) {
            ServerLinks.Pull pull = links.pullManifestBeforeApproval(url, ServerTls.PINNED, randomFingerprint());
            assertThat(pull.succeeded()).isFalse();
        }

        assertThat(links.cachedClients()).as("a pre-approval client is never cached").isZero();
        long settled = settle(threadsBefore + 3);
        assertThat(settled).as("selector threads after 40 one-shot clients").isLessThanOrEqualTo(threadsBefore + 3);
    }

    @Test
    void onlyTheApprovedTrustIsCachedAndAnApprovalThatReplacesAFingerprintEvictsTheOldOne() {
        for (int i = 0; i < 20; i++) {
            links.client(ServerTls.PLAIN, "ignored-" + i);
            links.client(ServerTls.CA, "ignored-" + i);
        }
        assertThat(links.cachedClients()).as("ca and plain are keyed by the mode alone").isEqualTo(2);

        String first = randomFingerprint();
        String second = randomFingerprint();
        links.client(ServerTls.PINNED, first);
        links.client(ServerTls.PINNED, second);
        assertThat(links.cachedClients()).isEqualTo(4);

        links.evict(ServerTls.PINNED, first);
        links.evict(ServerTls.CA, null);
        assertThat(links.cachedClients()).as("only a pinned entry is evicted").isEqualTo(3);
    }

    @Test
    void aPullFromAServerThatDripsItsAnswerFailsAtTheDeadline() {
        URI url = URI.create("http://localhost:" + dripping.getLocalPort() + "/mcp");
        long started = System.nanoTime();

        ServerLinks.Pull pull = links.pullManifest(url, ServerTls.PLAIN, null);

        assertThat(pull.succeeded()).isFalse();
        assertThat(pull.failure()).isEqualTo(ServerLinks.Failure.UNREACHABLE);
        assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(DEADLINE.multipliedBy(4));
    }

    @Test
    void aPushToAServerThatDripsItsAnswerFailsAtTheDeadline() throws Exception {
        URI url = URI.create("http://localhost:" + dripping.getLocalPort() + "/mcp");
        long started = System.nanoTime();

        ServerLinks.Push push = links.pushPolicyData(url, "mcp-drip", ServerTls.PLAIN, null, 1, JSON.readTree("{}"));

        assertThat(push.delivered()).isFalse();
        assertThat(push.failure()).isEqualTo(ServerLinks.Failure.UNREACHABLE);
        assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(DEADLINE.multipliedBy(4));
    }

    private ServerLinks.Push pushAnsweredWith(String ack, long pushed) throws Exception {
        com.sun.net.httpserver.HttpServer server = com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0), 0);
        server.createContext("/.well-known/mcp-policy-data", exchange -> {
            byte[] body = ack.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        try {
            return links.pushPolicyData(URI.create("http://localhost:" + server.getAddress().getPort() + "/mcp"), "mcp-ack", ServerTls.PLAIN, null,
                    pushed, JSON.readTree("{}"));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void anAckThatRefusesTheDataBecauseTheServerHoldsANewerRevisionIsNotADelivery() throws Exception {
        ServerLinks.Push ahead = pushAnsweredWith("{\"revision\":9,\"accepted\":false,\"gate\":\"ok\"}", 7);

        assertThat(ahead.delivered()).isFalse();
        assertThat(ahead.failure()).isEqualTo(ServerLinks.Failure.REJECTED);
        assertThat(pushAnsweredWith("{\"revision\":7,\"accepted\":false,\"gate\":\"ok\"}", 7).delivered())
                .as("the same revision again is the periodic push of unchanged data").isTrue();
        assertThat(pushAnsweredWith("{\"revision\":7,\"accepted\":true,\"gate\":\"ok\"}", 7).delivered()).isTrue();
        assertThat(pushAnsweredWith("{\"revision\":5,\"accepted\":false,\"gate\":\"ok\"}", 7).delivered())
                .as("a server that keeps an older revision than the push is not ahead of the gateway").isTrue();
    }

    private static long settle(long wanted) throws InterruptedException {
        long count = selectorThreads();
        for (int i = 0; i < 50 && count > wanted; i++) {
            Thread.sleep(100);
            System.gc();
            count = selectorThreads();
        }
        return count;
    }
}
