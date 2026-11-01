package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;

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
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.images.builder.Transferable;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;

import pl.aiwcorpo.mcp.gateway.support.BrokerStub;
import pl.aiwcorpo.mcp.gateway.support.GatewayProcess;
import pl.aiwcorpo.mcp.gateway.support.GatewayTestEnvironment;
import pl.aiwcorpo.mcp.gateway.support.TestPki;
import pl.aiwcorpo.mcp.testserver.JwksKeySource;
import pl.aiwcorpo.mcp.testserver.TestMcpServer;
import pl.aiwcorpo.mcp.testserver.Tls;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Saturation of one gateway on a small heap: far more callers than the gateway can serve, against a slow system. The gateway must
 * shed what it cannot serve at once with 503 and Retry-After (fail-closed) and stay inside its heap, never die of it. The system
 * properties {@code saturation.limit}, {@code saturation.callers}, {@code saturation.heap} and {@code saturation.seconds} scale the run
 * (for example a limit of 100000 shows what the same load does to a gateway that sheds nothing).
 */
class SaturationTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final List<String> GROUPS = List.of("mcp-jira-read", "mcp-jira-write");
    private static final int LIMIT = Integer.getInteger("saturation.limit", 20);
    private static final int CALLERS = Integer.getInteger("saturation.callers", 600);
    private static final int HEAP_MB = Integer.getInteger("saturation.heap", 320);
    private static final Duration LOAD = Duration.ofSeconds(Integer.getInteger("saturation.seconds", 15));
    private static final boolean WITH_LIMIT = Boolean.parseBoolean(System.getProperty("saturation.limited", "true"));

    private static GatewayTestEnvironment env;
    private static Path dir;
    private static GenericContainer<?> redis;
    private static BrokerStub broker;
    private static TestMcpServer jira;
    private static GatewayProcess gateway;

    @BeforeAll
    static void start() throws Exception {
        env = GatewayTestEnvironment.get();
        dir = Files.createTempDirectory("mcp-gateway-saturation");
        redis = new GenericContainer<>("redis:8.8.4-alpine")
                .withCopyToContainer(Transferable.of(GatewayTestEnvironment.redisAcl()), "/etc/redis-users.acl")
                .withCommand("redis-server", "--aclfile", "/etc/redis-users.acl", "--appendonly", "no").withExposedPorts(6379);
        redis.start();
        int port = GatewayProcess.freePort();
        int internal = GatewayProcess.freePort();
        TestPki pki = env.pki;
        JwksKeySource keys = new JwksKeySource(URI.create("https://localhost:" + internal + "/.well-known/jwks.json"), env.noClientCertificateTls,
                Duration.ZERO);
        broker = new BrokerStub(Tls.fromPkcs12(pki.issue("sat-broker.p12", "mcp-credential-broker", List.of("mcp-credential-broker.internal"),
                true, false), pki.truststore(), TestPki.PASSWORD), keys);
        broker.grant("sat-pat", 60);
        jira = new TestMcpServer(new TestMcpServer.Config("mcp-jira", "/mcp", "https://mcp-gateway.internal", false, null, keys),
                Tls.fromPkcs12(pki.issue("sat-jira.p12", "mcp-jira", List.of("mcp-jira.internal", "localhost"), true, false),
                        pki.truststore(), TestPki.PASSWORD), new java.net.InetSocketAddress("127.0.0.1", 0));
        jira.updateTool(true);
        jira.start();
        Path jwks = dir.resolve("internal-jwt.jwks");
        Files.writeString(jwks, new JWKSet(List.of(
                new ECKeyGenerator(Curve.P_256).keyID("sat-key-a").algorithm(JWSAlgorithm.ES256).keyUse(KeyUse.SIGNATURE).generate(),
                new ECKeyGenerator(Curve.P_256).keyID("sat-key-b").algorithm(JWSAlgorithm.ES256).keyUse(KeyUse.SIGNATURE).generate()))
                .toString(false));
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
        p.put("gateway.internal-jwt.active-kid", "sat-key-a");
        p.put("gateway.policy.state-dir", Files.createDirectories(dir.resolve("state")).toString());
        p.put("gateway.mcp.tools-list-timeout", "5000");
        // The limits of requests are not what is measured here.
        p.put("gateway.rate-limit.per-user", "1000000");
        p.put("gateway.rate-limit.per-client", "1000000");
        p.put("gateway.rate-limit.per-tool", "1000000");
        p.put("gateway.rate-limit.destructive-per-tool", "1000000");
        if (WITH_LIMIT) {
            p.put("gateway.mcp.max-concurrent-requests", Integer.toString(LIMIT));
        }
        gateway = GatewayProcess.start("saturated", dir, p, port, internal,
                List.of("-Xmx" + HEAP_MB + "m", "-XX:+ExitOnOutOfMemoryError", "-XX:+HeapDumpOnOutOfMemoryError", "-XX:HeapDumpPath=" + dir));
    }

    @AfterAll
    static void stop() {
        if (gateway != null) {
            gateway.close();
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

    private static String jcmd(String... args) throws Exception {
        List<String> command = new ArrayList<>();
        command.add(Path.of(System.getProperty("java.home"), "bin", "jcmd").toString());
        command.add(Long.toString(gateway.pid()));
        command.addAll(List.of(args));
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String out = new String(process.getInputStream().readAllBytes());
        process.waitFor(30, TimeUnit.SECONDS);
        return out;
    }

    @Test
    void manyMoreCallersThanTheGatewayCanServeAreShedWith503AndTheHeapHolds() throws Exception {
        jira.slowToolCalls(400);
        HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).executor(Executors.newVirtualThreadPerTaskExecutor()).build();
        // Wait until the tools of the server are served.
        String probe = env.idp.token(UUID.randomUUID().toString(), "probe", GROUPS);
        long ready = System.nanoTime() + Duration.ofSeconds(60).toNanos();
        while (System.nanoTime() < ready && !call(http, probe).contains("\"isError\":false")) {
            Thread.sleep(500);
        }

        Map<String, AtomicInteger> outcomes = new ConcurrentHashMap<>();
        AtomicInteger shedWithRetryAfter = new AtomicInteger();
        AtomicLong slowestShed = new AtomicLong();
        long end = System.nanoTime() + LOAD.toNanos();
        ExecutorService callers = Executors.newVirtualThreadPerTaskExecutor();
        for (int i = 0; i < CALLERS; i++) {
            String token = env.idp.token(UUID.randomUUID().toString(), "u" + i, GROUPS);
            callers.submit(() -> {
                while (System.nanoTime() < end) {
                    long started = System.nanoTime();
                    String outcome;
                    try {
                        HttpResponse<String> response = send(http, token);
                        if (response.statusCode() == 503) {
                            outcome = "503";
                            if (response.headers().firstValue("Retry-After").isPresent()) {
                                shedWithRetryAfter.incrementAndGet();
                            }
                            slowestShed.accumulateAndGet((System.nanoTime() - started) / 1_000_000, Math::max);
                            Thread.sleep(200);
                        } else if (response.statusCode() == 200 && response.body().contains("\"isError\":false")) {
                            outcome = "ok";
                        } else {
                            outcome = response.statusCode() + (response.body().length() > 120 ? response.body().substring(0, 120) : response.body());
                        }
                    } catch (IOException e) {
                        outcome = "io:" + e.getClass().getSimpleName();
                    } catch (InterruptedException e) {
                        return;
                    }
                    outcomes.computeIfAbsent(outcome, k -> new AtomicInteger()).incrementAndGet();
                }
            });
        }
        StringBuilder heap = new StringBuilder();
        String histogram = "";
        while (System.nanoTime() < end) {
            Thread.sleep(3000);
            if (gateway.alive()) {
                heap.append(jcmd("GC.heap_info").lines().filter(l -> l.contains("used")).findFirst().orElse("?").trim()).append('\n');
                if (Boolean.getBoolean("saturation.histograms")) {
                    histogram = "histogram at " + heap.length() + ":\n" + jcmd("GC.class_histogram").lines().limit(16).reduce("", (a, b) -> a + b + "\n");
                    Files.writeString(Path.of(System.getProperty("saturation.report") + ".histogram"), histogram);
                }
            }
        }
        histogram = gateway.alive() ? jcmd("GC.class_histogram").lines().limit(14).reduce("", (a, b) -> a + b + "\n") : histogram;
        HttpResponse<String> withoutToken = http.send(HttpRequest.newBuilder(URI.create("http://localhost:" + gateway.port() + "/mcp"))
                .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString("{}")).build(), HttpResponse.BodyHandlers.ofString());
        callers.shutdown();
        callers.awaitTermination(60, TimeUnit.SECONDS);

        Map<String, Integer> summary = new TreeMap<>();
        outcomes.forEach((k, v) -> summary.put(k, v.get()));
        String report = "limit=" + (WITH_LIMIT ? LIMIT : "none") + " callers=" + CALLERS + " heap=" + HEAP_MB + "m alive=" + gateway.alive()
                + "\noutcomes=" + summary + "\nshedWithRetryAfter=" + shedWithRetryAfter + " slowestShedMs=" + slowestShed
                + "\nmostCallsInFlightAtTheServer=" + jira.mostCallsInFlight() + "\nheap used:\n" + heap + histogram;
        Files.writeString(Path.of(System.getProperty("saturation.report", dir.resolve("report.txt").toString())), report);
        System.out.println(report);

        assertThat(gateway.alive()).as("the gateway lives: %s", report).isTrue();
        if (WITH_LIMIT) {
            assertThat(summary.getOrDefault("503", 0)).as("callers over the limit are shed").isPositive();
            assertThat(shedWithRetryAfter.get()).as("every 503 carries Retry-After").isEqualTo(summary.getOrDefault("503", 0));
            assertThat(summary.getOrDefault("ok", 0)).isPositive();
            assertThat(summary.keySet()).as("nothing but ok and 503").allMatch(k -> k.equals("ok") || k.equals("503"));
            assertThat(jira.mostCallsInFlight()).as("the system behind sees no more than the limit").isLessThanOrEqualTo(LIMIT);
            assertThat(withoutToken.statusCode()).as("a request without a token is answered 401 even when the gateway is full").isEqualTo(401);
        }
    }

    private static String call(HttpClient http, String token) throws Exception {
        try {
            return send(http, token).body();
        } catch (IOException e) {
            return "";
        }
    }

    private static HttpResponse<String> send(HttpClient http, String token) throws IOException, InterruptedException {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"jira__add_comment\","
                + "\"arguments\":{\"issueKey\":\"ABC-1\"},\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\","
                + "\"io.modelcontextprotocol/clientCapabilities\":{}}}}";
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://localhost:" + gateway.port() + "/mcp")).timeout(Duration.ofSeconds(60))
                .header("Content-Type", "application/json").header("Accept", "application/json, text/event-stream")
                .header("Authorization", "Bearer " + token).header("MCP-Protocol-Version", "2026-07-28").header("Mcp-Method", "tools/call")
                .header("Mcp-Name", "jira__add_comment").POST(HttpRequest.BodyPublishers.ofString(body)).build();
        return http.send(request, HttpResponse.BodyHandlers.ofString());
    }
}
