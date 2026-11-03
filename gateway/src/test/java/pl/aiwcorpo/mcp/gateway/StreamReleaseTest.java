package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import pl.aiwcorpo.mcp.gateway.support.GatewayProcess;
import pl.aiwcorpo.mcp.gateway.support.GatewayTestEnvironment;

/**
 * How soon the place of a stream in MCP_MAX_OPEN_STREAMS is free after the client closed its socket without a word (what a balancer does
 * when its own client leaves). The instance allows one stream and a heartbeat of {@value #HEARTBEAT_SECONDS} s; a closed peer is
 * only seen by a write, so the old behaviour freed the place after two heartbeats (the first write to a closed socket is accepted by the kernel).
 * Both kinds of stream are measured: the GET of a session and POST subscriptions/listen.
 */
class StreamReleaseTest {

    private static final int HEARTBEAT_SECONDS = 4;
    private static final HttpClient HTTP = HttpClient.newHttpClient();
    private static GatewayTestEnvironment env;
    private static GatewayProcess gateway;

    @BeforeEach
    void start() throws Exception {
        env = GatewayTestEnvironment.get();
        Path dir = Files.createTempDirectory("mcp-gateway-release");
        Map<String, String> properties = new LinkedHashMap<>(env.properties());
        properties.remove("gateway.internal-endpoint.port");
        properties.put("gateway.mcp.max-open-streams", "1");
        properties.put("gateway.mcp.sse-heartbeat-interval", HEARTBEAT_SECONDS + "s");
        properties.put("gateway.policy.state-dir", Files.createDirectories(dir.resolve("state")).toString());
        gateway = GatewayProcess.start("streams-release", dir, properties, GatewayProcess.freePort(), GatewayProcess.freePort());
    }

    @AfterEach
    void stop() {
        if (gateway != null) {
            gateway.close();
        }
    }

    @Test
    void sessionStreamReleasesItsPlaceSoonAfterTheClientClosed() throws Exception {
        String token = token();
        String session = initialize(token);
        String request = "GET /mcp HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + token + "\r\nMcp-Session-Id: " + session
                + "\r\nAccept: text/event-stream\r\n\r\n";
        assertThat(measureRelease(request)).isLessThan(Duration.ofSeconds(HEARTBEAT_SECONDS + 2));
    }

    @Test
    void listenStreamReleasesItsPlaceSoonAfterTheClientClosed() throws Exception {
        String token = token();
        assertThat(measureRelease(listenRequest(token, 1))).isLessThan(Duration.ofSeconds(HEARTBEAT_SECONDS + 2));
    }

    /** Opens the stream, closes the socket and returns how long it takes until the same request is served again (the one place is free). */
    private static Duration measureRelease(String openRequest) throws Exception {
        Socket socket = new Socket("localhost", gateway.port());
        assertThat(statusLine(socket, openRequest)).as("the stream holds the only place").startsWith("HTTP/1.1 200");
        assertThat(statusLine(new Socket("localhost", gateway.port()), openRequest)).as("a second stream is refused").startsWith("HTTP/1.1 503");

        long closedAt = System.nanoTime();
        socket.close();
        while (System.nanoTime() - closedAt < Duration.ofSeconds(90).toNanos()) {
            Socket probe = new Socket("localhost", gateway.port());
            boolean served = statusLine(probe, openRequest).startsWith("HTTP/1.1 200");
            if (served) {
                Duration waited = Duration.ofNanos(System.nanoTime() - closedAt);
                probe.close();
                System.out.println("stream release after client close: " + waited.toMillis() + " ms (heartbeat " + HEARTBEAT_SECONDS + " s)");
                return waited;
            }
            probe.close();
            Thread.sleep(100);
        }
        return Duration.ofSeconds(90);
    }

    private static String statusLine(Socket socket, String request) throws Exception {
        socket.setSoTimeout(5000);
        socket.getOutputStream().write(request.getBytes(StandardCharsets.UTF_8));
        socket.getOutputStream().flush();
        byte[] buffer = new byte[4096];
        int read = socket.getInputStream().read(buffer);
        return new String(buffer, 0, Math.max(read, 0), StandardCharsets.UTF_8);
    }

    private static String token() throws Exception {
        return env.idp.token(UUID.randomUUID().toString(), "streams", List.of("mcp-jira-read"));
    }

    private static String initialize(String token) throws Exception {
        HttpResponse<String> init = HTTP.send(HttpRequest.newBuilder(URI.create("http://localhost:" + gateway.port() + "/mcp"))
                .header("Authorization", "Bearer " + token).header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream")
                .POST(HttpRequest.BodyPublishers.ofString("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":"
                        + "{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"t\",\"version\":\"1\"}}}")).build(),
                HttpResponse.BodyHandlers.ofString());
        return init.headers().firstValue("Mcp-Session-Id").orElseThrow();
    }

    private static String listenRequest(String token, int id) {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"method\":\"subscriptions/listen\",\"params\":{\"_meta\":{"
                + "\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{}},"
                + "\"notifications\":{\"toolsListChanged\":true}}}";
        return "POST /mcp HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + token + "\r\nContent-Type: application/json\r\n"
                + "Accept: application/json, text/event-stream\r\nMCP-Protocol-Version: 2026-07-28\r\nMcp-Method: subscriptions/listen\r\n"
                + "Content-Length: " + body.getBytes(StandardCharsets.UTF_8).length + "\r\n\r\n" + body;
    }
}
