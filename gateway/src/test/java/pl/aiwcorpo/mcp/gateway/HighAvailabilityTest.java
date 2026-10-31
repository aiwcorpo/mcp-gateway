package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.images.builder.Transferable;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;

import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisURI;
import pl.aiwcorpo.mcp.gateway.support.BrokerStub;
import pl.aiwcorpo.mcp.gateway.support.GatewayProcess;
import pl.aiwcorpo.mcp.gateway.support.GatewayTestEnvironment;
import pl.aiwcorpo.mcp.gateway.support.TestPki;
import pl.aiwcorpo.mcp.testserver.InternalJwtVerifier;
import pl.aiwcorpo.mcp.testserver.JwksKeySource;
import pl.aiwcorpo.mcp.testserver.TestMcpServer;
import pl.aiwcorpo.mcp.testserver.Tls;
import pl.aiwcorpo.mcp.testserver.Totp;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Two gateways as two processes of their own against one Redis, one PostgreSQL, one broker stand-in and one MCP server (M5, point B):
 * a confirmation begun on one instance ends on the other, sessions, filters and cursors are valid on both, a lost Redis refuses
 * instead of guessing, and a killed instance costs the callers a retry and nothing else.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class HighAvailabilityTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final String SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    private static final List<String> GROUPS = List.of("mcp-jira-read", "mcp-jira-write", "mcp-jira-destructive");
    private static final int BULK_TOOLS = 120;

    private static GatewayTestEnvironment env;
    private static Path dir;
    private static GenericContainer<?> redis;
    private static BrokerStub broker;
    private static TestMcpServer jira;
    private static GatewayProcess a;
    private static GatewayProcess b;
    private static final HttpClient HTTP = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();

    @BeforeAll
    static void startTwoInstances() throws Exception {
        env = GatewayTestEnvironment.get();
        dir = Files.createTempDirectory("mcp-gateway-ha");
        redis = new GenericContainer<>("redis:8.8.4-alpine")
                .withCopyToContainer(Transferable.of(GatewayTestEnvironment.redisAcl()), "/etc/redis-users.acl")
                .withCommand("redis-server", "--aclfile", "/etc/redis-users.acl", "--appendonly", "no")
                .withExposedPorts(6379);
        redis.start();
        provenStore();

        int portA = GatewayProcess.freePort();
        int internalA = GatewayProcess.freePort();
        int portB = GatewayProcess.freePort();
        int internalB = GatewayProcess.freePort();
        TestPki pki = env.pki;
        InternalJwtVerifier.KeySource keys = new EitherInstance(jwks(internalA), jwks(internalB));
        broker = new BrokerStub(Tls.fromPkcs12(pki.issue("ha-broker.p12", "mcp-credential-broker", List.of("mcp-credential-broker.internal"),
                true, false), pki.truststore(), TestPki.PASSWORD), keys);
        jira = new TestMcpServer(new TestMcpServer.Config("mcp-jira", "/mcp", "https://mcp-gateway.internal", false, null, keys),
                Tls.fromPkcs12(pki.issue("ha-jira.p12", "mcp-jira", List.of("mcp-jira.internal", "localhost"), true, false),
                        pki.truststore(), TestPki.PASSWORD), new java.net.InetSocketAddress("127.0.0.1", 0));
        jira.extraTools(BULK_TOOLS);
        jira.start();
        broker.grant("ha-pat", 60);

        Path jwks = dir.resolve("internal-jwt.jwks");
        Files.writeString(jwks, new JWKSet(List.of(
                new ECKeyGenerator(Curve.P_256).keyID("ha-key-a").algorithm(JWSAlgorithm.ES256).keyUse(KeyUse.SIGNATURE).generate(),
                new ECKeyGenerator(Curve.P_256).keyID("ha-key-b").algorithm(JWSAlgorithm.ES256).keyUse(KeyUse.SIGNATURE).generate()))
                .toString(false));
        a = GatewayProcess.start("instance-a", dir, properties(jwks, "a"), portA, internalA);
        b = GatewayProcess.start("instance-b", dir, properties(jwks, "b"), portB, internalB);
        // The first start of the registry registers the manifest of the server; both instances must serve its tools before a test goes on.
        String probe = token(UUID.randomUUID().toString());
        for (GatewayProcess instance : new GatewayProcess[] {a, b}) {
            await().atMost(Duration.ofSeconds(60)).pollInterval(Duration.ofMillis(500)).untilAsserted(() ->
                    assertThat(JSON.readTree(modern(instance, probe, "/mcp?systems=jira", "tools/list", null, "{}").body())
                            .path("result").path("tools").size()).isPositive());
        }
    }

    private static JwksKeySource jwks(int internalPort) {
        return new JwksKeySource(URI.create("https://localhost:" + internalPort + "/.well-known/jwks.json"), env.noClientCertificateTls,
                Duration.ZERO);
    }

    /** Servers and the broker fetch the keys from whichever instance still lives. */
    private record EitherInstance(JwksKeySource first, JwksKeySource second) implements InternalJwtVerifier.KeySource {
        @Override
        public com.nimbusds.jose.jwk.JWK find(String kid) {
            com.nimbusds.jose.jwk.JWK key = first.find(kid);
            return key != null ? key : second.find(kid);
        }
    }

    private static Map<String, String> properties(Path jwks, String instance) throws IOException {
        Map<String, String> p = new LinkedHashMap<>(env.properties());
        p.remove("gateway.internal-endpoint.port");
        p.put("gateway.redis.host", redis.getHost());
        p.put("gateway.redis.port", Integer.toString(redis.getMappedPort(6379)));
        p.put("spring.data.redis.host", redis.getHost());
        p.put("spring.data.redis.port", Integer.toString(redis.getMappedPort(6379)));
        p.put("gateway.broker.url", "https://127.0.0.1:" + broker.port());
        p.put("gateway.servers.mcp-jira.internal-url", "https://127.0.0.1:" + jira.port() + "/mcp");
        p.put("gateway.servers.mcp-jira.manifest", "required");
        p.put("gateway.internal-jwt.keys-file", jwks.toString());
        p.put("gateway.internal-jwt.active-kid", "ha-key-a");
        p.put("gateway.activity.cursor-key", "ha-activity-cursor-key-shared");
        p.put("gateway.mcp.list-cursor-key", "ha-list-cursor-key-shared");
        p.put("gateway.policy.state-dir", Files.createDirectories(dir.resolve("state-" + instance)).toString());
        return p;
    }

    private static void provenStore() {
        RedisClient client = RedisClient.create(RedisURI.builder().withHost(redis.getHost()).withPort(redis.getMappedPort(6379))
                .withAuthentication("admin", GatewayTestEnvironment.REDIS_ADMIN_PASSWORD.toCharArray()).build());
        try (var connection = client.connect()) {
            connection.sync().set("gw:conf:epoch", Long.toString(System.currentTimeMillis() - 3_600_000L));
        } finally {
            client.shutdown();
        }
    }

    @AfterAll
    static void stop() {
        for (GatewayProcess instance : new GatewayProcess[] {a, b}) {
            if (instance != null) {
                instance.close();
            }
        }
        if (jira != null) {
            jira.close();
        }
        if (broker != null) {
            broker.close();
        }
        if (redis != null) {
            redis.stop();
        }
    }

    // --- helpers -----------------------------------------------------------------------------------------------

    private static String token(String sub) {
        return env.idp.token(sub, "u" + sub.substring(0, 8), GROUPS);
    }

    private static HttpResponse<String> post(GatewayProcess instance, String token, String path, String body, Map<String, String> headers)
            throws IOException, InterruptedException {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create("http://localhost:" + instance.port() + path))
                .timeout(Duration.ofSeconds(20)).header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream").header("Authorization", "Bearer " + token)
                .POST(HttpRequest.BodyPublishers.ofString(body));
        headers.forEach(builder::header);
        return HTTP.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> modern(GatewayProcess instance, String token, String path, String method, String name,
                                               String params) throws IOException, InterruptedException {
        JsonNode node = JSON.readTree(params);
        ((tools.jackson.databind.node.ObjectNode) node).putObject("_meta").put("io.modelcontextprotocol/protocolVersion", "2026-07-28")
                .putObject("io.modelcontextprotocol/clientCapabilities");
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("MCP-Protocol-Version", "2026-07-28");
        headers.put("Mcp-Method", method);
        if (name != null) {
            headers.put("Mcp-Name", name);
        }
        return post(instance, token, path, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"" + method + "\",\"params\":"
                + JSON.writeValueAsString(node) + "}", headers);
    }

    private static HttpResponse<String> callTool(GatewayProcess instance, String token, String tool, String arguments)
            throws IOException, InterruptedException {
        return modern(instance, token, "/mcp", "tools/call", tool, "{\"name\":\"" + tool + "\",\"arguments\":" + arguments + "}");
    }

    private static JsonNode toolError(HttpResponse<String> response) {
        JsonNode result = JSON.readTree(response.body()).path("result");
        return result.path("isError").asBoolean(false) ? JSON.readTree(result.path("content").get(0).path("text").asString())
                : JSON.createObjectNode();
    }

    private static long deletesAtTheServer() {
        return jira.requests().stream().filter(r -> "tools/call".equals(r.rpcMethod()) && "delete_issue".equals(r.toolName())).count();
    }

    // --- tests -------------------------------------------------------------------------------------------------

    @Test
    @Order(1)
    void aConfirmationBegunOnOneInstanceEndsOnTheOtherAndTheCodeWorksOnce() throws Exception {
        String sub = UUID.randomUUID().toString();
        broker.enroll(sub, SECRET);
        String token = token(sub);
        long before = deletesAtTheServer();

        JsonNode pending = toolError(callTool(a, token, "jira__delete_issue", "{\"issueKey\":\"ABC-1\"}"));
        assertThat(pending.path("error").asString()).isEqualTo("confirmation_required");
        assertThat(pending.path("confirmationId").asString()).startsWith("cnf_");

        String code = Totp.currentCode(SECRET, System.currentTimeMillis() / 1000);
        HttpResponse<String> finished = callTool(b, token, "jira__delete_issue", "{\"issueKey\":\"ABC-1\",\"confirmation_code\":\"" + code + "\"}");
        assertThat(toolError(finished).has("error")).as(finished.body()).isFalse();
        assertThat(deletesAtTheServer()).as("the tool ran on the server once").isEqualTo(before + 1);

        JsonNode replay = toolError(callTool(a, token, "jira__delete_issue", "{\"issueKey\":\"ABC-1\",\"confirmation_code\":\"" + code + "\"}"));
        assertThat(replay.path("error").asString()).as("the code is spent for both instances").isEqualTo("confirmation_failed");
        assertThat(deletesAtTheServer()).isEqualTo(before + 1);
    }

    @Test
    @Order(2)
    void sessionsFiltersAndCursorsAreValidOnBothInstances() throws Exception {
        String token = token(UUID.randomUUID().toString());
        HttpResponse<String> init = post(a, token, "/mcp?access=read",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\","
                        + "\"capabilities\":{},\"clientInfo\":{\"name\":\"test\",\"version\":\"1\"}}}", Map.of());
        assertThat(init.statusCode()).isEqualTo(200);
        String session = init.headers().firstValue("Mcp-Session-Id").orElseThrow();
        Map<String, String> headers = Map.of("Mcp-Session-Id", session, "MCP-Protocol-Version", "2025-11-25");

        HttpResponse<String> first = post(b, token, "/mcp?access=read", "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}", headers);
        assertThat(first.statusCode()).as("the session of instance A on instance B").isEqualTo(200);
        JsonNode firstPage = JSON.readTree(first.body()).path("result");
        assertThat(firstPage.path("tools").size()).isEqualTo(100);
        String cursor = firstPage.path("nextCursor").asString();
        assertThat(cursor).isNotBlank();

        HttpResponse<String> second = post(a, token, "/mcp?access=read", "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/list\",\"params\":"
                + "{\"cursor\":\"" + cursor + "\"}}", headers);
        JsonNode secondPage = JSON.readTree(second.body()).path("result");
        assertThat(secondPage.path("tools").size()).as("get_issue, search_issues and %d bulk tools make 122", BULK_TOOLS).isEqualTo(22);
        assertThat(secondPage.has("nextCursor")).isFalse();
        List<String> names = new ArrayList<>();
        firstPage.path("tools").forEach(t -> names.add(t.path("name").asString()));
        secondPage.path("tools").forEach(t -> names.add(t.path("name").asString()));
        assertThat(names).doesNotHaveDuplicates().hasSize(BULK_TOOLS + 2).isSorted();

        assertThat(post(b, token, "/mcp?access=write", "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/list\"}", headers).statusCode())
                .as("another filter on the other instance").isEqualTo(404);
        HttpResponse<String> foreign = post(b, token(UUID.randomUUID().toString()), "/mcp?access=read",
                "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/list\",\"params\":{\"cursor\":\"" + cursor + "\"}}",
                Map.of("MCP-Protocol-Version", "2026-07-28", "Mcp-Method", "tools/list"));
        assertThat(foreign.statusCode()).as("a cursor of another user").isIn(400, 200);
        if (foreign.statusCode() == 200) {
            assertThat(JSON.readTree(foreign.body()).path("error").path("code").asInt()).isEqualTo(-32602);
        }
    }

    @Test
    @Order(3)
    void aLostRedisIsRefusedNotGuessed() throws Exception {
        String token = token(UUID.randomUUID().toString());
        assertThat(toolError(callTool(a, token, "jira__get_issue", "{\"issueKey\":\"ABC-1\"}")).has("error")).isFalse();
        long callsBefore = jira.requests().stream().filter(r -> "tools/call".equals(r.rpcMethod())).count();
        redis.getDockerClient().pauseContainerCmd(redis.getContainerId()).exec();
        try {
            for (GatewayProcess instance : new GatewayProcess[] {a, b}) {
                HttpResponse<String> list = modern(instance, token, "/mcp", "tools/list", null, "{}");
                assertThat(list.statusCode()).as("a list needs the limits").isEqualTo(503);
                assertThat(JSON.readTree(list.body()).path("error").asString()).isEqualTo("upstream_unavailable");
                assertThat(toolError(callTool(instance, token, "jira__get_issue", "{\"issueKey\":\"ABC-1\"}")).path("error").asString())
                        .isEqualTo("upstream_unavailable");
                HttpResponse<String> init = post(instance, token, "/mcp",
                        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\"}}", Map.of());
                assertThat(init.statusCode()).as("no session is made up").isIn(503, 429);
                JsonNode destructive = toolError(callTool(instance, token, "jira__delete_issue", "{\"issueKey\":\"ABC-2\"}"));
                assertThat(destructive.path("error").asString()).isEqualTo("upstream_unavailable");
            }
            assertThat(jira.requests().stream().filter(r -> "tools/call".equals(r.rpcMethod())).count())
                    .as("nothing reached the server while the state was unknown").isEqualTo(callsBefore);
        } finally {
            redis.getDockerClient().unpauseContainerCmd(redis.getContainerId()).exec();
        }
        await().atMost(Duration.ofSeconds(30)).untilAsserted(() ->
                assertThat(toolError(callTool(b, token, "jira__get_issue", "{\"issueKey\":\"ABC-1\"}")).has("error")).isFalse());
    }

    @Test
    @Order(4)
    void killingOneInstanceInTheMiddleOfCallsCostsOnlyARetry() throws Exception {
        GatewayProcess[] balancer = {a, b};
        AtomicInteger turn = new AtomicInteger();
        AtomicInteger retries = new AtomicInteger();
        AtomicInteger done = new AtomicInteger();
        List<String> failures = java.util.Collections.synchronizedList(new ArrayList<>());
        ExecutorService pool = Executors.newFixedThreadPool(6);
        List<Future<?>> callers = new ArrayList<>();
        for (int caller = 0; caller < 6; caller++) {
            // One user per caller: the limits are shared by the instances, and 240 calls of one user would meet the limit of a tool.
            String token = token(UUID.randomUUID().toString());
            callers.add(pool.submit(() -> {
                for (int i = 0; i < 40; i++) {
                    boolean succeeded = false;
                    int start = turn.getAndIncrement();
                    for (int attempt = 0; attempt < 3 && !succeeded; attempt++) {
                        // A balancer that meets a dead node tries the other one.
                        GatewayProcess instance = balancer[Math.floorMod(start + attempt, 2)];
                        try {
                            HttpResponse<String> response = callTool(instance, token, "jira__get_issue", "{\"issueKey\":\"ABC-1\"}");
                            if (response.statusCode() == 200 && !toolError(response).has("error")) {
                                succeeded = true;
                            } else if (response.statusCode() >= 500 && !instance.alive()) {
                                retries.incrementAndGet();
                            } else {
                                failures.add(response.statusCode() + " " + response.body());
                                break;
                            }
                        } catch (IOException e) {
                            retries.incrementAndGet();
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            return null;
                        }
                    }
                    if (succeeded) {
                        done.incrementAndGet();
                    } else {
                        failures.add("call " + i + " failed on every attempt");
                    }
                }
                return null;
            }));
        }
        await().atMost(Duration.ofSeconds(30)).until(() -> done.get() >= 30);
        a.kill();
        for (Future<?> caller : callers) {
            caller.get(2, java.util.concurrent.TimeUnit.MINUTES);
        }
        pool.shutdown();
        assertThat(failures).as("errors other than the retry of a connection to the dead instance").isEmpty();
        assertThat(done.get()).isEqualTo(6 * 40);
        assertThat(a.alive()).isFalse();
        assertThat(toolError(callTool(b, token(UUID.randomUUID().toString()), "jira__get_issue", "{\"issueKey\":\"ABC-1\"}")).has("error")).isFalse();
        assertThat(retries.get()).as("the dead instance was met at least once").isPositive();
    }
}
