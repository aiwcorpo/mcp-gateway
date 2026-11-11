package pl.aiwcorpo.mcp.gateway.upstream;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.jwt.InternalTokenIssuer;
import pl.aiwcorpo.mcp.gateway.jwt.SigningKeys;
import pl.aiwcorpo.mcp.gateway.server.CredentialPolicy;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/** How long the sessions towards a server may hold the gateway, run through the real client against a local server. */
class UpstreamSessionsTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final GatewayUser ALICE = new GatewayUser("6f1c2a9e-4d4b-4c51-9a53-1e0f0c7d2b11", "alice", "claude-code",
            List.of("mcp-jira-read"), "raw");
    private static final String CONVERSATION = "l|" + ALICE.sub() + "|c-1|/mcp";

    private HttpServer http;

    @AfterEach
    void stop() {
        if (http != null) {
            http.stop(0);
        }
    }

    @Test
    void closeReturnsWhenTheServerAnswersAlthoughItsBodyStalls() throws Exception {
        start(exchange -> {
            if (!"DELETE".equals(exchange.getRequestMethod())) {
                answer(exchange, "s-1");
                return;
            }
            exchange.getResponseHeaders().set("Content-Type", "text/event-stream");
            exchange.sendResponseHeaders(200, 0);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(": keepalive\n".getBytes(StandardCharsets.UTF_8));
                out.flush();
                Thread.sleep(10_000);
            } catch (IOException | InterruptedException e) {
                // the gateway closed the stream
            }
        });
        UpstreamSessions sessions = sessions(Duration.ofSeconds(1));
        sessions.call(server("mcp-jira"), CONVERSATION, ALICE, "r-1", toolsCall(), "get_issue", null, true);
        long started = System.nanoTime();

        sessions.close("l|" + ALICE.sub() + "|c-1|", ALICE, "r-2");

        assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(3));
        assertThat(sessions.size()).isZero();
    }

    @Test
    void theDeletesOfOneCloseShareTheUpstreamTimeout() throws Exception {
        start(exchange -> {
            if (!"DELETE".equals(exchange.getRequestMethod())) {
                answer(exchange, "s-1");
                return;
            }
            try {
                Thread.sleep(5_000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            exchange.close();
        });
        UpstreamSessions sessions = sessions(Duration.ofMillis(400));
        for (String serverId : List.of("mcp-jira", "mcp-wiki", "mcp-crm")) {
            sessions.call(server(serverId), CONVERSATION, ALICE, "r-1", toolsCall(), "get_issue", null, true);
        }
        long started = System.nanoTime();

        sessions.close("l|" + ALICE.sub() + "|c-1|", ALICE, "r-2");

        assertThat(Duration.ofNanos(System.nanoTime() - started)).as("three servers that never answer, 400 ms in all")
                .isLessThan(Duration.ofMillis(1_000));
        assertThat(sessions.size()).isZero();
    }

    private void start(HttpHandler handler) throws IOException {
        http = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        http.setExecutor(Executors.newCachedThreadPool());
        http.createContext("/mcp", handler);
        http.start();
    }

    /** Opens a session with {@code sessionId}, acknowledges notifications/initialized and answers tools/call; returns the method. */
    private static String answer(HttpExchange exchange, String sessionId) throws IOException {
        JsonNode message = JSON.readTree(exchange.getRequestBody().readAllBytes());
        String method = message.path("method").asString("");
        switch (method) {
            case "initialize" -> send(exchange, 200, sessionId, result(message.get("id"), "{\"protocolVersion\":\"2025-11-25\"}"));
            case "notifications/initialized" -> send(exchange, 202, null, null);
            case "tools/call" -> send(exchange, 200, null, result(message.get("id"), "{\"isError\":false}"));
            default -> send(exchange, 400, null, null);
        }
        return method;
    }

    private static void send(HttpExchange exchange, int status, String sessionId, String body) throws IOException {
        if (sessionId != null) {
            exchange.getResponseHeaders().add("Mcp-Session-Id", sessionId);
        }
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        byte[] bytes = body == null ? new byte[0] : body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
        if (bytes.length > 0) {
            exchange.getResponseBody().write(bytes);
        }
        exchange.close();
    }

    private static String result(JsonNode id, String result) {
        return "{\"jsonrpc\":\"2.0\",\"id\":" + JSON.writeValueAsString(id) + ",\"result\":" + result + "}";
    }

    /** The client is made as in production (ServerTls.client): HTTP/1.1, no redirects, a connect timeout. */
    private static UpstreamSessions sessions(Duration timeout) throws Exception {
        InternalTokenIssuer tokens = new InternalTokenIssuer(SigningKeys.load(null, null, false, false), "https://mcp-gateway.internal",
                Duration.ofSeconds(30), () -> 1L, Clock.systemUTC());
        return new UpstreamSessions(mcp -> new StreamableHttpClient(mcp.internalUrl(), HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1).followRedirects(HttpClient.Redirect.NEVER).connectTimeout(Duration.ofSeconds(1)).build(),
                JSON, timeout, 1 << 20), mcp -> true, tokens, JSON, Duration.ofMinutes(30), Clock.systemUTC(), "mcp-gateway", "test");
    }

    private McpServer server(String serverId) {
        return new McpServer(serverId, serverId.substring(4), URI.create("http://127.0.0.1:" + http.getAddress().getPort() + "/mcp"), "1.0.0",
                true, new CredentialPolicy(false, Set.of(), List.of(), false, null), Map.of());
    }

    private static ObjectNode toolsCall() {
        ObjectNode request = JSON.createObjectNode();
        request.put("jsonrpc", "2.0");
        request.put("id", 7);
        request.put("method", "tools/call");
        request.putObject("params").put("name", "get_issue");
        return request;
    }
}
