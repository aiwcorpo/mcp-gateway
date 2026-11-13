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
import java.util.concurrent.Future;
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
 * Saturation of one gateway on a small heap: far more callers than the gateway can serve. The calls the gateway admits (as many as its
 * limit) are held at the system behind it for the whole load, so the gateway is full whatever the speed of the machine; every other caller
 * must be shed with 503 and Retry-After (fail-closed) each time it asks, while the gateway stays alive and answers a request without a token
 * with 401. Once the system answers, every admitted call is served and the system never saw more calls than the limit. No heap threshold is
 * set. The default run is the production setting (limit 128, the heap of an image under 2 GiB at 60%). The system
 * properties {@code saturation.limit}, {@code saturation.callers}, {@code saturation.heap} and {@code saturation.seconds} scale the run
 * (for example a limit of 100000 shows what the same load does to a gateway that sheds nothing).
 */
class SaturationTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final List<String> GROUPS = List.of("mcp-jira-read", "mcp-jira-write");
    private static final int LIMIT = Integer.getInteger("saturation.limit", 128);
    private static final int CALLERS = Integer.getInteger("saturation.callers", 1000);
    private static final int HEAP_MB = Integer.getInteger("saturation.heap", 1228);
    private static final Duration LOAD = Duration.ofSeconds(Integer.getInteger("saturation.seconds", 15));
    private static final boolean WITH_LIMIT = Boolean.parseBoolean(System.getProperty("saturation.limited", "true"));

    private static final String UPSTREAM_UNAVAILABLE = "upstream_unavailable";

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
        assertThat(broker.servesInParallel()).as("a broker that serves one request at a time makes the first calls of %d users time out", 1000).isTrue();
        broker.grant("sat-pat", 60);
        jira = new TestMcpServer(new TestMcpServer.Config("mcp-jira", "/mcp", "https://mcp-gateway.internal", false, null, keys),
                Tls.fromPkcs12(pki.issue("sat-jira.p12", "mcp-jira", List.of("mcp-jira.internal", "localhost"), true, false),
                        pki.truststore(), TestPki.PASSWORD), new java.net.InetSocketAddress("127.0.0.1", 0));
        jira.updateTool(true);
        jira.start();
        String database = env.isolatedDatabase("saturation", Map.of("mcp-jira", "https://127.0.0.1:" + jira.port() + "/mcp"));
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
        p.put("spring.datasource.url", database);
        p.put("gateway.internal-jwt.keys-file", jwks.toString());
        p.put("gateway.internal-jwt.active-kid", "sat-key-a");
        p.put("gateway.mcp.tools-list-timeout", "5000");
        // The calls held at the server must outlive the whole load, and the definitions read before they were admitted must too: neither
        // the timeout of the upstream nor the TTL of the reading may end the hold, however slow the machine is.
        p.put("gateway.upstream.timeout", "120s");
        p.put("gateway.registry.definition-check-ttl", "60s");
        // The limits of requests are not what is measured here.
        p.put("gateway.rate-limit.per-user", "1000000");
        p.put("gateway.rate-limit.per-client", "1000000");
        p.put("gateway.rate-limit.per-tool", "1000000");
        p.put("gateway.rate-limit.destructive-per-tool", "1000000");
        p.put("gateway.mcp.max-concurrent-requests", Integer.toString(WITH_LIMIT ? LIMIT : 1_000_000));
        gateway = GatewayProcess.start("saturated", dir, p, port, internal,
                List.of("-Xmx" + HEAP_MB + "m", "-XX:+ExitOnOutOfMemoryError", "-XX:+HeapDumpOnOutOfMemoryError", "-XX:HeapDumpPath=" + dir));
    }

    @AfterAll
    static void stop() throws Exception {
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
        HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).executor(Executors.newVirtualThreadPerTaskExecutor()).build();
        int admitted = WITH_LIMIT ? Math.min(LIMIT, CALLERS) : CALLERS;
        List<String> tokens = new ArrayList<>();
        for (int i = 0; i < CALLERS; i++) {
            tokens.add(env.idp.token(UUID.randomUUID().toString(), "u" + i, GROUPS));
        }

        // The tools of the server are registered by the gateway after it starts serving; the first call that is served says when.
        long ready = System.nanoTime() + Duration.ofSeconds(60).toNanos();
        while (!call(http, tokens.get(0)).contains("\"isError\":false")) {
            assertThat(System.nanoTime()).as("the tools of the server are served within 60 s of the start").isLessThan(ready);
            Thread.sleep(500);
        }
        // Every caller that will be admitted makes one call on its own first, so that its credential and its session at the server exist and
        // the reading of the definitions is fresh when the held calls arrive: none of them depends on the speed of the broker or of the server.
        for (int i = 0; i < admitted; i++) {
            String outcome = classify(send(http, tokens.get(i)), new ConcurrentHashMap<>());
            assertThat(outcome).as("the warm-up call of caller %d is served: %s", i, gateway.output()).isEqualTo("ok");
        }

        // The admitted calls are held at the server, so the gateway is full for as long as the load lasts: what is shed does not depend on
        // how fast the calls are served.
        Runnable release = jira.holdToolCalls();
        ExecutorService heldCalls = Executors.newVirtualThreadPerTaskExecutor();
        ExecutorService shedCallers = Executors.newVirtualThreadPerTaskExecutor();
        Map<String, AtomicInteger> unavailableMessages = new ConcurrentHashMap<>();
        List<Future<String>> held = new ArrayList<>();
        for (int i = 0; i < admitted; i++) {
            String token = tokens.get(i);
            held.add(heldCalls.submit(() -> classify(send(http, token), unavailableMessages)));
        }
        assertThat(jira.awaitCallsInFlight(admitted, Duration.ofSeconds(60))).as("%d calls are admitted and held at the server", admitted).isTrue();

        Map<String, AtomicInteger> outcomes = new ConcurrentHashMap<>();
        AtomicInteger shedWithRetryAfter = new AtomicInteger();
        AtomicLong slowestShed = new AtomicLong();
        long end = System.nanoTime() + LOAD.toNanos();
        for (int i = admitted; i < CALLERS; i++) {
            String token = tokens.get(i);
            shedCallers.submit(() -> {
                while (System.nanoTime() < end) {
                    long started = System.nanoTime();
                    String outcome;
                    try {
                        HttpResponse<String> response = send(http, token);
                        outcome = classify(response, unavailableMessages);
                        if (response.statusCode() == 503) {
                            if (response.headers().firstValue("Retry-After").isPresent()) {
                                shedWithRetryAfter.incrementAndGet();
                            }
                            slowestShed.accumulateAndGet((System.nanoTime() - started) / 1_000_000, Math::max);
                            Thread.sleep(200);
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
        // A request that is still waiting for a place when the calls are released would be served: the last answers are collected while
        // the gateway is still full.
        shedCallers.shutdown();
        boolean finished = shedCallers.awaitTermination(60, TimeUnit.SECONDS);
        histogram = gateway.alive() ? jcmd("GC.class_histogram").lines().limit(14).reduce("", (a, b) -> a + b + "\n") : histogram;
        HttpResponse<String> withoutToken = http.send(HttpRequest.newBuilder(URI.create("http://localhost:" + gateway.port() + "/mcp"))
                .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString("{}")).build(), HttpResponse.BodyHandlers.ofString());
        int heldAtTheEnd = jira.callsInFlight();
        release.run();
        heldCalls.shutdown();
        Map<String, Integer> servedWhileHeld = new TreeMap<>();
        for (Future<String> call : held) {
            servedWhileHeld.merge(call.get(60, TimeUnit.SECONDS), 1, Integer::sum);
        }

        Map<String, Integer> summary = new TreeMap<>();
        outcomes.forEach((k, v) -> summary.put(k, v.get()));
        String report = "limit=" + (WITH_LIMIT ? LIMIT : "none") + " callers=" + CALLERS + " heap=" + HEAP_MB + "m alive=" + gateway.alive()
                + "\nadmittedAndHeld=" + admitted + " outcomesOfTheHeldCalls=" + servedWhileHeld
                + "\noutcomesOfTheOthers=" + summary + "\nshedWithRetryAfter=" + shedWithRetryAfter + " slowestShedMs=" + slowestShed
                + "\nunavailableMessages=" + unavailableMessages + "\ngateway warnings about the server:\n" + warnings()
                + "\nmostCallsInFlightAtTheServer=" + jira.mostCallsInFlight() + "\nheap used:\n" + heap + histogram;
        Files.writeString(Path.of(System.getProperty("saturation.report", dir.resolve("report.txt").toString())), report);
        System.out.println(report);

        assertThat(gateway.alive()).as("the gateway lives: %s", report).isTrue();
        assertThat(finished).as("the callers end").isTrue();
        assertThat(servedWhileHeld).as("every admitted call is served once the server answers: %s", report).isEqualTo(Map.of("ok", admitted));
        if (WITH_LIMIT) {
            assertThat(heldAtTheEnd).as("the admitted calls were held for the whole load").isEqualTo(admitted);
            assertThat(summary.keySet()).as("a caller over the limit is shed with 503 every time, nothing else comes back: %s", report)
                    .containsExactly("503");
            assertThat(shedWithRetryAfter.get()).as("every 503 carries Retry-After").isEqualTo(summary.get("503"));
            assertThat(jira.mostCallsInFlight()).as("the system behind sees exactly the limit and no more").isEqualTo(LIMIT);
            assertThat(withoutToken.statusCode()).as("a request without a token is answered 401 even when the gateway is full").isEqualTo(401);
        }
    }

    /** The outcome of one answer: ok, a shed (503), a refusal of an admitted call, or the status and the start of the body of anything else. */
    private static String classify(HttpResponse<String> response, Map<String, AtomicInteger> unavailableMessages) {
        if (response.statusCode() == 503) {
            return "503";
        }
        if (response.statusCode() == 200 && response.body().contains("\"isError\":false")) {
            return "ok";
        }
        if (response.statusCode() == 200 && response.body().contains("\"isError\":true")
                && response.body().contains("\"error\\\":\\\"upstream_unavailable\\\"")) {
            java.util.regex.Matcher said = java.util.regex.Pattern.compile("message\\\\\":\\\\\"([^\\\\]*)").matcher(response.body());
            unavailableMessages.computeIfAbsent(said.find() ? said.group(1) : "?", k -> new AtomicInteger()).incrementAndGet();
            return UPSTREAM_UNAVAILABLE;
        }
        return response.statusCode() + (response.body().length() > 220 ? response.body().substring(0, 220) : response.body());
    }

    private static String warnings() throws IOException {
        return gateway.output().lines().filter(l -> l.contains(" WARN ") && !l.contains("policy-sync") && !l.contains("ConcurrencyLimitFilter")).limit(20)
                .reduce("", (a, b) -> a + b + "\n");
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
