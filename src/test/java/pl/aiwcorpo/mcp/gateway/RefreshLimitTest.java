package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import pl.aiwcorpo.mcp.gateway.support.GatewayProcess;
import pl.aiwcorpo.mcp.gateway.support.GatewayTestEnvironment;
import pl.aiwcorpo.mcp.gateway.support.TestPki;
import pl.aiwcorpo.mcp.testserver.JwksKeySource;
import pl.aiwcorpo.mcp.testserver.TestMcpServer;
import pl.aiwcorpo.mcp.testserver.Tls;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * {@code POST /admin/v1/servers/{serverId}/refresh} probes a server at once, but at most once in 5 s per server (C5): a faster call is
 * {@code 429 refresh_too_frequent} with {@code Retry-After}. The shared context of the other tests has no pause, so this runs a gateway of its own
 * with the default one.
 */
class RefreshLimitTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final String ADMIN_SUB = "3b0d6f2e-91c4-4d7a-8a52-6c1e4f7a9d10";

    private static GatewayTestEnvironment env;
    private static GatewayProcess gateway;
    private static TestMcpServer server;

    @BeforeAll
    static void startAGatewayWithTheDefaultPause() throws Exception {
        env = GatewayTestEnvironment.get();
        Path dir = Files.createTempDirectory("mcp-gateway-refresh");
        int port = GatewayProcess.freePort();
        int internal = GatewayProcess.freePort();
        JwksKeySource keys = new JwksKeySource(URI.create("https://localhost:" + internal + "/.well-known/jwks.json"), env.noClientCertificateTls,
                Duration.ZERO);
        server = new TestMcpServer(new TestMcpServer.Config("mcp-limit", "/mcp", "https://mcp-gateway.internal", false, null, keys),
                Tls.fromPkcs12(env.pki.issue("limit.p12", "mcp-limit", List.of("127.0.0.1", "localhost"), true, false), env.pki.truststore(),
                        TestPki.PASSWORD), new java.net.InetSocketAddress("127.0.0.1", 0)).start();
        Map<String, String> properties = new LinkedHashMap<>(env.properties());
        properties.remove("gateway.internal-endpoint.port");
        properties.put("spring.datasource.url", env.emptyDatabase("refreshlimit"));
        properties.put("gateway.servers.refresh-interval", "5s");
        properties.put("gateway.registry.bootstrap-from-server", "false");
        gateway = GatewayProcess.start("refresh-limit", dir, properties, port, internal);
    }

    @AfterAll
    static void stop() {
        if (gateway != null) {
            gateway.close();
        }
        if (server != null) {
            server.close();
        }
    }

    private static HttpResponse<String> admin(String method, String path, String body) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create("https://localhost:" + gateway.internalPort() + path))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + env.idp.token(ADMIN_SUB, "a.admin", List.of("mcp-platform-admin"), "mcp-gateway-admin",
                        "mcp-portal-bff"))
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        return HttpClient.newBuilder().sslContext(env.bffTls).build().send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void aSecondRefreshWithinFiveSecondsIsRefusedWithTheTimeToWaitAndThenAllowedAgain() throws Exception {
        HttpResponse<String> added = admin("POST", "/admin/v1/servers", "{\"internalUrl\":\"https://127.0.0.1:" + server.port() + "/mcp\"}");
        assertThat(added.statusCode()).as(added.body()).isEqualTo(201);

        HttpResponse<String> first = admin("POST", "/admin/v1/servers/mcp-limit/refresh", null);
        assertThat(first.statusCode()).as(first.body()).isEqualTo(200);

        HttpResponse<String> second = admin("POST", "/admin/v1/servers/mcp-limit/refresh", null);
        assertThat(second.statusCode()).isEqualTo(429);
        JsonNode body = JSON.readTree(second.body());
        assertThat(body.path("error").asString()).isEqualTo("refresh_too_frequent");
        int wait = Integer.parseInt(second.headers().firstValue("Retry-After").orElseThrow());
        assertThat(wait).isBetween(1, 5);
        assertThat(admin("POST", "/admin/v1/servers/mcp-nobody/refresh", null).statusCode()).as("another server has no pause of its own to wait for").isEqualTo(404);

        await().atMost(Duration.ofSeconds(wait + 3)).pollInterval(Duration.ofMillis(500)).untilAsserted(() ->
                assertThat(admin("POST", "/admin/v1/servers/mcp-limit/refresh", null).statusCode()).isEqualTo(200));
    }
}
