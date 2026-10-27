package pl.aiwcorpo.mcp.gateway.upstream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpServer;

import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.IntNode;

class StreamableHttpClientTest {

    private static final int LIMIT = 64 * 1024;
    private static final JsonMapper JSON = JsonMapper.builder().build();

    private final AtomicReference<String> contentType = new AtomicReference<>();
    private final AtomicReference<byte[]> chunk = new AtomicReference<>();
    private volatile long chunks;
    private HttpServer server;
    private StreamableHttpClient client;

    @BeforeEach
    void start() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/mcp", exchange -> {
            exchange.getRequestBody().readAllBytes();
            exchange.getResponseHeaders().set("Content-Type", contentType.get());
            exchange.sendResponseHeaders(200, 0);
            try (OutputStream out = exchange.getResponseBody()) {
                for (long i = 0; i < chunks; i++) {
                    out.write(chunk.get());
                }
            } catch (java.io.IOException e) {
                // the gateway closes the stream once the limit is hit
            }
        });
        server.start();
        client = new StreamableHttpClient(URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/mcp"),
                HttpClient.newHttpClient(), JSON, Duration.ofSeconds(10), LIMIT);
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    @Test
    void eventStreamLineWithoutNewlineBeyondTheLimitFailsClosed() {
        byte[] noNewline = new byte[16 * 1024];
        Arrays.fill(noNewline, (byte) 'a');
        noNewline[0] = 'd';
        respond("text/event-stream", noNewline, 64 * 1024);

        assertThatThrownBy(() -> client.post(request(), IntNode.valueOf(1)))
                .isInstanceOfSatisfying(UpstreamException.class, e -> {
                    assertThat(e.kind()).isEqualTo(UpstreamException.Kind.PROTOCOL);
                    assertThat(e.getMessage()).isEqualTo("response too large");
                });
    }

    @Test
    void jsonBodyBeyondTheLimitFailsClosed() {
        byte[] block = new byte[8 * 1024];
        Arrays.fill(block, (byte) ' ');
        respond("application/json", block, 1024);
        assertThatThrownBy(() -> client.post(request(), IntNode.valueOf(1)))
                .isInstanceOfSatisfying(UpstreamException.class, e -> assertThat(e.getMessage()).isEqualTo("response too large"));
    }

    @Test
    void eventStreamKeepsOnlyTheResponseWithTheRequestId() throws Exception {
        String stream = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{}}\n\n"
                + "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"other\":true}}\n\n"
                + "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n\n";
        respond("text/event-stream", stream.getBytes(StandardCharsets.UTF_8), 1);
        UpstreamResponse response = client.post(request(), IntNode.valueOf(1));
        assertThat(response.message().path("result").path("ok").asBoolean()).isTrue();
    }

    private void respond(String type, byte[] bytes, long times) {
        contentType.set(type);
        chunk.set(bytes);
        chunks = times;
    }

    private static UpstreamRequest request() {
        return new UpstreamRequest("jwt", "0192d1b2-7c3a-7d4e-8f10-2a3b4c5d6e7f", null, null, null,
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}");
    }
}
