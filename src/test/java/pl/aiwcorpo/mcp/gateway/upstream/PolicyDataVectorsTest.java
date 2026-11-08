package pl.aiwcorpo.mcp.gateway.upstream;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.jwt.InternalTokenIssuer;
import pl.aiwcorpo.mcp.gateway.jwt.SigningKeys;
import pl.aiwcorpo.mcp.gateway.jwt.UuidV7;
import pl.aiwcorpo.mcp.gateway.server.CredentialPolicy;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.support.Vectors;
import pl.aiwcorpo.mcp.manifest.PolicyDataGate;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * The policy data gate of C14 (CC-249): the rule a server applies ({@code policy-data-gate/}, with the Java twin {@link PolicyDataGate}),
 * the replacement rule of a push, and the sequence of the gateway when a server answers {@code 409 policy_data_stale} ({@code policy-data-push/}),
 * run through the real {@link UpstreamSessions} against a server that applies the gate.
 */
class PolicyDataVectorsTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final GatewayUser ALICE = new GatewayUser("6f1c2a9e-4d4b-4c51-9a53-1e0f0c7d2b11", "alice", "claude-code",
            List.of("mcp-jira-read"), "raw");

    private static PolicyDataGate.Data data(JsonNode held) {
        return held == null || held.isNull() ? null : new PolicyDataGate.Data(held.path("revision").asLong(),
                Optional.ofNullable(held.path("approvedPoliciesHash").asString(null)), held.path("overridesValid").asBoolean(true));
    }

    private static OptionalLong prv(JsonNode value) {
        return value == null || value.isNull() ? OptionalLong.empty() : OptionalLong.of(value.asLong());
    }

    @TestFactory
    List<DynamicTest> theGateOfTheServer() {
        List<DynamicTest> tests = new ArrayList<>();
        for (Vectors.Vector vector : Vectors.of("policy-data-gate")) {
            tests.add(DynamicTest.dynamicTest(vector.name(), () -> {
                JsonNode input = vector.document().path("input");
                JsonNode expected = vector.document().path("expected");

                PolicyDataGate.Decision decision = PolicyDataGate.decide(input.path("ownHash").asString(), data(input.get("held")), prv(input.get("prv")));

                assertThat(decision.allowed() ? "continue" : "deny").as(vector.document().path("description").asString())
                        .isEqualTo(expected.path("decision").asString());
                if (!decision.allowed()) {
                    assertThat(decision.reason()).isEqualTo(expected.path("reason").asString());
                }
            }));
        }
        assertThat(tests).hasSize(10);
        return tests;
    }

    @TestFactory
    List<DynamicTest> theReplacementRuleOfAPush() {
        List<DynamicTest> tests = new ArrayList<>();
        for (Vectors.Vector vector : Vectors.of("policy-data-push")) {
            JsonNode input = vector.document().path("input");
            if (!input.has("offered")) {
                continue;
            }
            tests.add(DynamicTest.dynamicTest(vector.name(), () -> {
                PolicyDataGate.Data held = data(input.get("held"));
                long offered = input.path("offered").path("revision").asLong();

                boolean accepted = PolicyDataGate.acceptRevision(held == null ? OptionalLong.empty() : OptionalLong.of(held.revision()), offered);

                JsonNode expected = vector.document().path("expected");
                assertThat(accepted).as(vector.document().path("description").asString()).isEqualTo(expected.path("accepted").asBoolean());
                assertThat(accepted ? offered : held.revision()).isEqualTo(expected.path("revision").asLong());
            }));
        }
        assertThat(tests).hasSize(4);
        return tests;
    }

    @TestFactory
    List<DynamicTest> theAnswerToAPush() {
        List<DynamicTest> tests = new ArrayList<>();
        for (Vectors.Vector vector : Vectors.of("policy-data-push")) {
            JsonNode input = vector.document().path("input");
            if (!input.has("ack")) {
                continue;
            }
            tests.add(DynamicTest.dynamicTest(vector.name(), () -> {
                boolean failed = pl.aiwcorpo.mcp.gateway.link.ServerLinks.serverHoldsNewer(input.get("ack"), input.path("pushed").asLong());

                assertThat(failed).as(vector.document().path("description").asString())
                        .isEqualTo("failed".equals(vector.document().path("expected").path("outcome").asString()));
            }));
        }
        assertThat(tests).hasSize(3);
        return tests;
    }

    /** A server that holds policy data, applies the gate to every tools/call and counts what reaches it. */
    private static final class GatedServer implements AutoCloseable {
        final HttpServer http;
        final AtomicInteger calls = new AtomicInteger();
        final AtomicReference<PolicyDataGate.Data> held = new AtomicReference<>();
        final String ownHash;

        GatedServer(String ownHash, PolicyDataGate.Data held) throws IOException {
            this.ownHash = ownHash;
            this.held.set(held);
            this.http = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            http.createContext("/mcp", this::handle);
            http.start();
        }

        private void handle(HttpExchange exchange) throws IOException {
            try (exchange) {
                JsonNode message = JSON.readTree(exchange.getRequestBody().readAllBytes());
                String method = message.path("method").asString("");
                switch (method) {
                    case "initialize" -> {
                        exchange.getResponseHeaders().add("Mcp-Session-Id", "s-1");
                        ObjectNode result = JSON.createObjectNode();
                        result.put("protocolVersion", "2025-11-25");
                        send(exchange, 200, rpc(message.get("id"), result));
                    }
                    case "notifications/initialized" -> send(exchange, 202, null);
                    case "tools/call" -> {
                        calls.incrementAndGet();
                        String claims = new String(Base64.getUrlDecoder().decode(exchange.getRequestHeaders().getFirst("Authorization")
                                .substring("Bearer ".length()).split("\\.")[1]), StandardCharsets.UTF_8);
                        PolicyDataGate.Data now = held.get();
                        PolicyDataGate.Decision decision = PolicyDataGate.decide(ownHash, now, OptionalLong.of(JSON.readTree(claims).path("prv").asLong()));
                        if (decision.allowed()) {
                            send(exchange, 200, rpc(message.get("id"), JSON.createObjectNode().put("isError", false)));
                        } else if ("policy_data_stale".equals(decision.reason())) {
                            ObjectNode stale = JSON.createObjectNode().put("error", "policy_data_stale");
                            stale.put("requiredRevision", JSON.readTree(claims).path("prv").asLong());
                            send(exchange, 409, stale);
                        } else {
                            ObjectNode result = JSON.createObjectNode().put("isError", true);
                            result.putArray("content").addObject().put("type", "text").put("text", "{\"error\":\"upstream_unavailable\"}");
                            send(exchange, 200, rpc(message.get("id"), result));
                        }
                    }
                    default -> send(exchange, 400, null);
                }
            }
        }

        private static ObjectNode rpc(JsonNode id, ObjectNode result) {
            ObjectNode out = JSON.createObjectNode();
            out.put("jsonrpc", "2.0");
            out.set("id", id);
            out.set("result", result);
            return out;
        }

        private static void send(HttpExchange exchange, int status, JsonNode body) throws IOException {
            byte[] bytes = body == null ? new byte[0] : JSON.writeValueAsBytes(body);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
            if (bytes.length > 0) {
                exchange.getResponseBody().write(bytes);
            }
        }

        @Override
        public void close() {
            http.stop(0);
        }
    }

    @TestFactory
    List<DynamicTest> theSequenceOfTheGateway() {
        List<DynamicTest> tests = new ArrayList<>();
        for (Vectors.Vector vector : Vectors.of("policy-data-push")) {
            if (!vector.document().path("input").has("gateway")) {
                continue;
            }
            tests.add(DynamicTest.dynamicTest(vector.name(), () -> sequence(vector.document())));
        }
        assertThat(tests).hasSize(7);
        return tests;
    }

    private void sequence(JsonNode vector) throws Exception {
        JsonNode input = vector.path("input");
        JsonNode expected = vector.path("expected");
        PolicyDataGate.Data gateway = data(input.get("gateway"));
        boolean pushReaches = input.path("pushReachesServer").asBoolean(true);
        AtomicInteger pushes = new AtomicInteger();
        try (GatedServer server = new GatedServer(input.path("ownHash").asString(), data(input.get("held")))) {
            InternalTokenIssuer tokens = new InternalTokenIssuer(SigningKeys.load(null, null, false, false), "https://mcp-gateway.internal",
                    Duration.ofSeconds(30), gateway::revision, Clock.systemUTC());
            UpstreamSessions sessions = new UpstreamSessions(
                    mcp -> new StreamableHttpClient(mcp.internalUrl(), HttpClient.newHttpClient(), JSON, Duration.ofSeconds(5), 1 << 20),
                    mcp -> {
                        pushes.incrementAndGet();
                        if (pushReaches) {
                            PolicyDataGate.Data now = server.held.get();
                            if (PolicyDataGate.acceptRevision(now == null ? OptionalLong.empty() : OptionalLong.of(now.revision()), gateway.revision())) {
                                server.held.set(gateway);
                            }
                        }
                        return pushReaches;
                    }, tokens, JSON, Duration.ofMinutes(5), Clock.systemUTC(), "mcp-gateway", "test");
            McpServer target = new McpServer("mcp-jira", "jira", URI.create("http://127.0.0.1:" + server.http.getAddress().getPort() + "/mcp"), "1.0.0",
                    true, new CredentialPolicy(false, java.util.Set.of(), List.of(), false, null), java.util.Map.of());
            ObjectNode request = JSON.createObjectNode();
            request.put("jsonrpc", "2.0");
            request.put("id", 7);
            request.put("method", "tools/call");
            request.putObject("params").put("name", "get_issue");

            String result;
            try {
                JsonNode answer = sessions.call(target, UuidV7.next(), ALICE, UuidV7.next(), request, "get_issue", null, true);
                result = answer.path("result").path("isError").asBoolean(false) ? "upstream_unavailable" : "executed";
            } catch (UpstreamException e) {
                result = "upstream_unavailable";
            }

            String description = vector.path("description").asString();
            assertThat(server.calls.get()).as("calls: " + description).isEqualTo(expected.path("calls").asInt());
            assertThat(pushes.get()).as("pushes: " + description).isEqualTo(expected.path("pushes").asInt());
            assertThat(result).as(description).isEqualTo(expected.path("result").asString());
        }
    }
}
