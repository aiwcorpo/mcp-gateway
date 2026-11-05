package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.net.ssl.SSLContext;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisURI;
import io.lettuce.core.api.StatefulRedisConnection;
import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.broker.CredentialCache;
import pl.aiwcorpo.mcp.gateway.broker.InvalidationListener;
import pl.aiwcorpo.mcp.gateway.jwt.InternalTokenIssuer;
import pl.aiwcorpo.mcp.gateway.jwt.UuidV7;
import pl.aiwcorpo.mcp.gateway.support.BrokerStub;
import pl.aiwcorpo.mcp.gateway.support.Contracts;
import pl.aiwcorpo.mcp.gateway.support.GatewayTestEnvironment;
import pl.aiwcorpo.mcp.testserver.TestMcpServer;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * One Spring context for every integration test class (same properties, so Spring Boot reuses it: the internal
 * port is fixed per JVM): IdP token -> gateway -> broker stub -> test MCP server over mTLS with the gateway's own
 * JWKS, PostgreSQL and Redis in containers.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@org.springframework.test.context.ActiveProfiles("devstack")
@org.springframework.context.annotation.Import(pl.aiwcorpo.mcp.gateway.support.RateLimitTestConfiguration.class)
@ExtendWith(OutputCaptureExtension.class)
public abstract class GatewayTestBase {

    protected static final GatewayTestEnvironment env = GatewayTestEnvironment.get();
    protected static final JsonMapper JSON = JsonMapper.builder().build();
    protected static final String ALICE_SUB = "6f1c2a9e-4d4b-4c51-9a53-1e0f0c7d2b11";
    protected static final String BOB_SUB = "0d6a7e2c-9c1b-4a0e-8f55-3b2d1c0e9f22";
    protected static final List<String> ALICE_GROUPS = List.of("mcp-jira-read", "mcp-jira-write", "mcp-jira-proj-ABC",
            "mcp-confluence-read", "other-group");

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        env.register(registry);
    }

    @LocalServerPort
    protected int port;

    @Autowired
    protected InternalTokenIssuer issuer;

    @Autowired
    protected InvalidationListener invalidations;

    @Autowired
    protected CredentialCache credentialCache;

    @Autowired
    protected JdbcClient jdbc;

    protected final HttpClient http = HttpClient.newHttpClient();

    @BeforeEach
    void reset() {
        env.broker.grant("alice-pat", 60);
        env.broker.clear();
        env.jira.clearRequests();
        env.wrongName.clearRequests();
        credentialCache.clear();
        await().atMost(Duration.ofSeconds(10)).until(invalidations::live);
    }

    protected GatewayUser alice() {
        return new GatewayUser(ALICE_SUB, "alice", "claude-code", ALICE_GROUPS, "unused");
    }

    protected String aliceToken() {
        return env.idp.token(ALICE_SUB, "alice", ALICE_GROUPS);
    }

    protected HttpResponse<String> callGetIssue(String token) throws Exception {
        return sendModern(token, "tools/call", "jira__get_issue",
                "{\"name\":\"jira__get_issue\",\"arguments\":{\"issueKey\":\"ABC-1\"}}");
    }

    protected long resolveCount() {
        return env.broker.received().stream().filter(r -> r.path().equals("/v1/credentials/resolve")).count();
    }

    protected void publishInvalidation(String sub, String system) {
        RedisClient client = RedisClient.create(RedisURI.builder().withHost(env.redis.getHost())
                .withPort(env.redis.getMappedPort(6379))
                .withAuthentication("admin", GatewayTestEnvironment.REDIS_ADMIN_PASSWORD.toCharArray()).build());
        try (StatefulRedisConnection<String, String> connection = client.connect()) {
            connection.sync().publish("credential.invalidated", "{\"sub\":\"" + sub + "\",\"system\":\"" + system + "\"}");
        } finally {
            client.shutdown();
        }
    }

    protected String initialize(String token, String version) throws Exception {
        HttpResponse<String> response = send(token, "/s/mcp-jira/mcp", initializeBody(version), Map.of());
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(JSON.readTree(response.body()).path("result").path("protocolVersion").asString()).isEqualTo(version);
        String session = response.headers().firstValue("Mcp-Session-Id").orElseThrow();
        assertThat(sendRpc(token, session, version, "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}", Map.of())
                .statusCode()).isEqualTo(202);
        return session;
    }

    protected JsonNode rpc(String token, String session, String version, String method, String params) throws Exception {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":\"" + UUID.randomUUID() + "\",\"method\":\"" + method + "\""
                + (params == null ? "" : ",\"params\":" + params) + "}";
        HttpResponse<String> response = sendRpc(token, session, version, body, Map.of());
        assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
        return JSON.readTree(response.body());
    }

    protected HttpResponse<String> sendRpc(String token, String session, String version, String body,
                                         Map<String, String> extra) throws Exception {
        Map<String, String> headers = new LinkedHashMap<>(extra);
        if (session != null) {
            headers.put("Mcp-Session-Id", session);
        }
        headers.put("MCP-Protocol-Version", version);
        return send(token, "/s/mcp-jira/mcp", body, headers);
    }

    protected HttpResponse<String> sendModern(String token, String method, String name, String params) throws Exception {
        return sendModern(token, "/s/mcp-jira/mcp", method, name, params);
    }

    protected HttpResponse<String> sendModern(String token, String path, String method, String name, String params)
            throws Exception {
        JsonNode paramsNode = JSON.readTree(params);
        ((tools.jackson.databind.node.ObjectNode) paramsNode).putObject("_meta")
                .put("io.modelcontextprotocol/protocolVersion", "2026-07-28")
                .putObject("io.modelcontextprotocol/clientCapabilities");
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"" + method + "\",\"params\":" + JSON.writeValueAsString(paramsNode) + "}";
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("MCP-Protocol-Version", "2026-07-28");
        headers.put("Mcp-Method", method);
        if (name != null) {
            headers.put("Mcp-Name", name);
        }
        return send(token, path, body, headers);
    }

    protected HttpResponse<String> send(String token, String path, String body, Map<String, String> headers) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream")
                .POST(HttpRequest.BodyPublishers.ofString(body));
        if (token != null) {
            builder.header("Authorization", "Bearer " + token);
        }
        headers.forEach(builder::header);
        return http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    protected static String initializeBody() {
        return initializeBody("2025-11-25");
    }

    protected static String initializeBody(String version) {
        return "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"" + version
                + "\",\"capabilities\":{},\"clientInfo\":{\"name\":\"test\",\"version\":\"1\"}}}";
    }

    protected static String toolCall(String name, String argument) {
        String arguments = name.endsWith("search_issues") ? "{\"project\":\"" + argument + "\"}" : "{\"issueKey\":\"" + argument + "\"}";
        return toolCallJson(name, arguments);
    }

    protected static String toolCallJson(String name, String arguments) {
        return "{\"jsonrpc\":\"2.0\",\"id\":11,\"method\":\"tools/call\",\"params\":{\"name\":\"" + name
                + "\",\"arguments\":" + arguments + "}}";
    }

    protected static TestMcpServer.RecordedRequest lastToolCall(TestMcpServer server) {
        return server.requests().stream().filter(r -> "tools/call".equals(r.rpcMethod())).reduce((a, b) -> b).orElseThrow();
    }

    protected static JsonNode toolError(HttpResponse<String> response) {
        JsonNode result = JSON.readTree(response.body()).path("result");
        if (!result.path("isError").asBoolean(false)) {
            return JSON.createObjectNode();
        }
        return JSON.readTree(result.path("content").get(0).path("text").asString());
    }

    protected static JsonNode claims(String authorization) {
        String token = authorization.substring("Bearer ".length());
        return JSON.readTree(Base64.getUrlDecoder().decode(token.split("\\.")[1]));
    }

    protected static List<JsonNode> auditEvents(CapturedOutput output, String requestId) {
        List<JsonNode> events = new ArrayList<>();
        for (String line : output.getOut().split("\n")) {
            if (line.startsWith("{") && line.contains(requestId) && line.contains("\"component\":\"gateway\"")) {
                events.add(JSON.readTree(line));
            }
        }
        return events;
    }

    protected String bobToken() {
        return env.idp.token(BOB_SUB, "bob", List.of("mcp-jira-read"));
    }

    /** The BFF's call to C5: mTLS identity {@code tls}, user token (aud mcp-gateway-admin) in {@code token}. */
    protected HttpResponse<String> admin(SSLContext tls, String method, String path, String token, String body)
            throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create("https://localhost:" + env.internalPort + path))
                .header("Content-Type", "application/json");
        if (token != null) {
            builder.header("Authorization", "Bearer " + token);
        }
        builder.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        return HttpClient.newBuilder().sslContext(tls).build().send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    protected HttpResponse<String> admin(String method, String path, String sub, String username, List<String> groups,
                                         String body) throws Exception {
        return admin(env.bffTls, method, path, env.idp.token(sub, username, groups, "mcp-gateway-admin", "mcp-portal-bff"), body);
    }
}
