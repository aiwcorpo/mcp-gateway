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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
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
 * End-to-end through the real gateway: IdP token -> gateway -> broker stub -> test MCP server, over mTLS with
 * the gateway's own JWKS. Covers the M1 Definition of Done points of ws-05.
 */
class GatewayIntegrationTest extends GatewayTestBase {

    @org.springframework.beans.factory.annotation.Autowired
    pl.aiwcorpo.mcp.gateway.registry.DefinitionGuard definitions;

    // --- C1: OAuth resource server, RFC 9728 -------------------------------------------------------------

    @Test
    void missingTokenGets401WithResourceMetadata() throws Exception {
        HttpResponse<String> response = send(null, "/s/mcp-jira/mcp", initializeBody(), Map.of());
        assertThat(response.statusCode()).isEqualTo(401);
        assertThat(response.headers().firstValue("WWW-Authenticate")).hasValue(
                "Bearer resource_metadata=\"" + GatewayTestEnvironment.PUBLIC_URL
                        + "/.well-known/oauth-protected-resource/s/mcp-jira/mcp\"");
        assertThat(env.jira.requests()).isEmpty();

        HttpResponse<String> metadata = http.send(HttpRequest.newBuilder(
                URI.create("http://localhost:" + port + "/.well-known/oauth-protected-resource/s/mcp-jira/mcp")).build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(metadata.statusCode()).isEqualTo(200);
        JsonNode document = JSON.readTree(metadata.body());
        assertThat(document.path("resource").asString()).isEqualTo(GatewayTestEnvironment.PUBLIC_URL + "/s/mcp-jira/mcp");
        assertThat(document.path("authorization_servers").path(0).asString()).as(metadata.body()).isEqualTo("http://localhost:18080/realms/corp");
    }

    @Test
    void tokenForAnotherAudienceOrUnknownSignerIsRejected() throws Exception {
        String otherAudience = env.idp.token(ALICE_SUB, "alice", ALICE_GROUPS, "mcp-credential-broker", "claude-code");
        HttpResponse<String> response = send(otherAudience, "/s/mcp-jira/mcp", initializeBody(), Map.of());
        assertThat(response.statusCode()).isEqualTo(401);
        assertThat(response.headers().firstValue("WWW-Authenticate").orElse("")).startsWith("Bearer resource_metadata=").doesNotContain("invalid_token");

        String gatewayInternalToken = issuer.forUser("mcp-gateway", alice(), null, UuidV7.next());
        assertThat(send(gatewayInternalToken, "/s/mcp-jira/mcp", initializeBody(), Map.of()).statusCode()).isEqualTo(401);
        assertThat(send(aliceToken(), "/s/mcp-jira/other", initializeBody(), Map.of()).statusCode()).isIn(404, 405);
    }

    @Test
    void unknownServerAndUnknownLinkAre404() throws Exception {
        assertThat(send(aliceToken(), "/s/mcp-nothing/mcp", initializeBody(), Map.of()).statusCode()).isEqualTo(404);
        assertThat(send(aliceToken(), "/v/team-a/mcp", initializeBody(), Map.of()).statusCode()).isEqualTo(404);
    }

    @Test
    void jwksOnlyOnTheInternalTlsPort() throws Exception {
        HttpClient internal = HttpClient.newBuilder().sslContext(env.gatewayClientTls).build();
        HttpResponse<String> jwks = internal.send(HttpRequest.newBuilder(
                URI.create("https://localhost:" + env.internalPort + "/.well-known/jwks.json")).build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(jwks.statusCode()).isEqualTo(200);
        JsonNode keys = JSON.readTree(jwks.body()).path("keys");
        assertThat(keys.size()).isEqualTo(2);
        keys.forEach(k -> {
            assertThat(k.has("d")).isFalse();
            assertThat(k.path("kid").asString()).doesNotStartWith("test-");
            assertThat(k.path("crv").asString()).isEqualTo("P-256");
        });
        assertThat(http.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/.well-known/jwks.json")).build(),
                HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(404);
        assertThat(internal.send(HttpRequest.newBuilder(
                URI.create("https://localhost:" + env.internalPort + "/s/mcp-jira/mcp")).POST(HttpRequest.BodyPublishers.ofString("{}"))
                .build(), HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(404);
        assertThat(http.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/actuator/prometheus")).build(),
                HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(404);
        for (String path : List.of("/.well-known/jwks.json", "/actuator/health", "/actuator/prometheus", "/admin/v1/catalog")) {
            assertThat(http.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + path))
                    .POST(HttpRequest.BodyPublishers.ofString("{}")).build(), HttpResponse.BodyHandlers.ofString()).statusCode())
                    .as("POST " + path + " on the public port is not a 405 that confirms the path").isEqualTo(404);
        }
    }

    @Test
    void prometheusNeedsTheScrapersClientCertificate() throws Exception {
        URI metrics = URI.create("https://localhost:" + env.internalPort + "/actuator/prometheus");
        for (var tls : List.of(env.noClientCertificateTls, env.foreignCaTls, env.serverIdentityTls)) {
            assertThat(java.net.http.HttpClient.newBuilder().sslContext(tls).build()
                    .send(HttpRequest.newBuilder(metrics).build(), HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(401);
        }
        assertThat(java.net.http.HttpClient.newBuilder().sslContext(env.bffTls).build()
                .send(HttpRequest.newBuilder(metrics).build(), HttpResponse.BodyHandlers.ofString()).statusCode())
                .as("a valid certificate of another component").isEqualTo(403);
        HttpResponse<String> scraped = java.net.http.HttpClient.newBuilder().sslContext(env.scraperTls).build()
                .send(HttpRequest.newBuilder(metrics).build(), HttpResponse.BodyHandlers.ofString());
        assertThat(scraped.statusCode()).isEqualTo(200);
        assertThat(scraped.body()).contains("jvm_memory");
        assertThat(java.net.http.HttpClient.newBuilder().sslContext(env.scraperTls).build()
                .send(HttpRequest.newBuilder(URI.create("https://localhost:" + env.internalPort + "/actuator/health")).build(),
                        HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(200);
    }

    // --- Legacy clients (2025-11-25): sessions, tools, C2/C3 towards the server ---------------------------

    @Test
    void legacyClientListsAndCallsToolsWithInjectedCredential(CapturedOutput output) throws Exception {
        String token = aliceToken();
        String session = initialize(token, "2025-11-25");

        JsonNode list = rpc(token, session, "2025-11-25", "tools/list", null);
        List<String> names = new ArrayList<>();
        list.path("result").path("tools").forEach(t -> names.add(t.path("name").asString()));
        assertThat(names).containsExactlyInAnyOrder("jira__get_issue", "jira__search_issues");

        Map<String, String> clientHeaders = new LinkedHashMap<>();
        clientHeaders.put("X-MCP-Credential", "Bearer stolen-pat");
        clientHeaders.put("X-MCP-Credential-Type", "service-account");
        clientHeaders.put("X-PAT-Jira", "client-supplied-pat");
        clientHeaders.put("X-Request-Id", "client-req-42");
        HttpResponse<String> call = sendRpc(token, session, "2025-11-25", toolCall("jira__get_issue", "ABC-1"), clientHeaders);
        assertThat(call.statusCode()).isEqualTo(200);
        String requestId = call.headers().firstValue("X-Request-Id").orElseThrow();
        assertThat(requestId).matches("^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$");
        JsonNode result = JSON.readTree(call.body()).path("result");
        assertThat(result.path("isError").asBoolean()).isFalse();
        assertThat(result.path("content").get(0).path("text").asString()).contains("user-secret");

        TestMcpServer.RecordedRequest atServer = lastToolCall(env.jira);
        assertThat(atServer.status()).isEqualTo(200);
        assertThat(atServer.toolName()).isEqualTo("get_issue");
        assertThat(atServer.header("x-mcp-credential")).isEqualTo("Bearer alice-pat");
        assertThat(atServer.header("x-mcp-credential-type")).isEqualTo("user-secret");
        assertThat(atServer.header("x-request-id")).isEqualTo(requestId);
        assertThat(atServer.header("x-pat-jira")).isNull();
        assertThat(atServer.header("authorization")).doesNotContain(token);
        assertThat(atServer.headers().keySet()).noneMatch(h -> h.startsWith("x-pat-"));
        for (TestMcpServer.RecordedRequest request : env.jira.requests()) {
            assertThat(request.header("x-mcp-credential")).isNotEqualTo("Bearer stolen-pat");
            assertThat(request.header("x-request-id")).isNotEqualTo("client-req-42");
        }
        JsonNode jwtClaims = claims(atServer.header("authorization"));
        assertThat(jwtClaims.path("aud").isString()).isTrue();
        assertThat(jwtClaims.path("tool").asString()).isEqualTo("get_issue");
        assertThat(jwtClaims.path("rid").asString()).isEqualTo(requestId);
        assertThat(jwtClaims.path("grp").toString()).doesNotContain("other-group");
        assertThat(Contracts.schemaErrors("schemas/internal-jwt.schema.json", jwtClaims)).isEmpty();

        BrokerStub.Received resolve = env.broker.received().stream()
                .filter(r -> r.path().equals("/v1/credentials/resolve")).reduce((a, b) -> b).orElseThrow();
        assertThat(resolve.rejectReason()).isNull();
        assertThat(resolve.tool()).isEqualTo("get_issue");
        assertThat(resolve.requestId()).isEqualTo(requestId);
        assertThat(JSON.readTree(resolve.body()).path("subjectToken").isMissingNode()).isTrue();

        List<JsonNode> events = auditEvents(output, requestId);
        assertThat(events).extracting(e -> e.path("event").asString()).contains("policy_decision", "tool_call");
        for (JsonNode event : events) {
            assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", event)).isEmpty();
        }
        JsonNode toolCall = events.stream().filter(e -> e.path("event").asString().equals("tool_call")).findFirst().orElseThrow();
        assertThat(toolCall.path("outcome").asString()).isEqualTo("ok");
        assertThat(toolCall.path("clientRequestId").asString()).isEqualTo("client-req-42");
        assertThat(toolCall.path("credentialType").asString()).isEqualTo("user-secret");
        assertThat(output.getAll()).doesNotContain("alice-pat").doesNotContain(token);
    }

    @Test
    void everyServerRequestHasAFreshTokenAndToolOnlyOnToolsCall() throws Exception {
        String token = aliceToken();
        String session = initialize(token, "2025-06-18");
        rpc(token, session, "2025-06-18", "tools/list", null);
        sendRpc(token, session, "2025-06-18", toolCall("jira__search_issues", "ABC"), Map.of());

        List<TestMcpServer.RecordedRequest> requests = env.jira.requests();
        assertThat(requests).isNotEmpty().allSatisfy(r -> assertThat(r.rejectReason()).isNull());
        List<String> jtis = requests.stream().map(r -> claims(r.header("authorization")).path("jti").asString()).toList();
        assertThat(jtis).doesNotHaveDuplicates();
        for (TestMcpServer.RecordedRequest request : requests) {
            JsonNode claims = claims(request.header("authorization"));
            assertThat(claims.path("sub").asString()).isEqualTo(ALICE_SUB);
            if ("tools/call".equals(request.rpcMethod())) {
                assertThat(claims.path("tool").asString()).isEqualTo(request.toolName());
            } else {
                assertThat(claims.has("tool")).as(request.rpcMethod()).isFalse();
                assertThat(request.header("x-mcp-credential")).isNull();
            }
        }
    }

    @Test
    void serverRejectsTokenWhoseToolDiffersFromTheCalledTool() throws Exception {
        String token = aliceToken();
        String session = initialize(token, "2025-11-25");
        sendRpc(token, session, "2025-11-25", toolCall("jira__get_issue", "ABC-1"), Map.of());
        TestMcpServer.RecordedRequest call = lastToolCall(env.jira);

        String rid = UuidV7.next();
        String forged = issuer.forUser("mcp-jira", alice(), "get_issue", rid);
        String body = toolCallJson("search_issues", "{\"project\":\"ABC\"}");
        HttpResponse<String> response = HttpClient.newBuilder().sslContext(env.gatewayClientTls).build().send(
                HttpRequest.newBuilder(URI.create("https://localhost:" + env.jira.port() + "/mcp"))
                        .header("Authorization", "Bearer " + forged).header("X-Request-Id", rid)
                        .header("Mcp-Session-Id", call.sessionId()).header("Content-Type", "application/json")
                        .header("Accept", "application/json, text/event-stream")
                        .POST(HttpRequest.BodyPublishers.ofString(body)).build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(401);
        assertThat(env.jira.requests().getLast().rejectReason()).isEqualTo("tool_mismatch");
    }

    @Test
    void sessionsAreNeverSharedBetweenUsers() throws Exception {
        String aliceToken = aliceToken();
        String bobToken = env.idp.token(BOB_SUB, "bob", List.of("mcp-jira-read"));
        String aliceSession = initialize(aliceToken, "2025-11-25");

        HttpResponse<String> hijack = sendRpc(bobToken, aliceSession, "2025-11-25",
                "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/list\"}", Map.of());
        assertThat(hijack.statusCode()).isEqualTo(404);

        String bobSession = initialize(bobToken, "2025-11-25");
        // The definitions of a server are read once for everyone within the check interval: a read that an earlier request made a moment ago
        // would leave Alice without a session upstream, so each of the two lists starts from no reading.
        definitions.forget("mcp-jira");
        rpc(aliceToken, aliceSession, "2025-11-25", "tools/list", null);
        definitions.forget("mcp-jira");
        rpc(bobToken, bobSession, "2025-11-25", "tools/list", null);
        Map<String, String> upstreamSessionOwner = new LinkedHashMap<>();
        for (TestMcpServer.RecordedRequest request : env.jira.requests()) {
            if (request.sessionId() != null && request.sub() != null) {
                String previous = upstreamSessionOwner.putIfAbsent(request.sessionId(), request.sub());
                assertThat(previous == null || previous.equals(request.sub())).as("upstream session shared").isTrue();
            }
        }
        assertThat(upstreamSessionOwner.values()).contains(ALICE_SUB, BOB_SUB);
        assertThat(env.jira.requests()).noneMatch(r -> "session_of_other_user".equals(r.rejectReason()));
    }

    @Test
    void aSessionCannotBeDeletedByAnotherUser() throws Exception {
        String aliceToken = aliceToken();
        String aliceSession = initialize(aliceToken, "2025-11-25");
        HttpResponse<String> foreignDelete = http.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/s/mcp-jira/mcp"))
                .header("Authorization", "Bearer " + bobToken()).header("Mcp-Session-Id", aliceSession).DELETE().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(foreignDelete.statusCode()).isEqualTo(404);
        assertThat(rpc(aliceToken, aliceSession, "2025-11-25", "tools/list", null).path("result").path("tools").size())
                .as("the owner's session survived").isEqualTo(2);
    }

    @Test
    void lostServerSessionIsReinitialized() throws Exception {
        String token = aliceToken();
        String session = initialize(token, "2025-11-25");
        rpc(token, session, "2025-11-25", "tools/list", null);
        env.jira.dropSessions();
        JsonNode list = rpc(token, session, "2025-11-25", "tools/list", null);
        assertThat(list.path("result").path("tools").size()).isEqualTo(2);
    }

    @Test
    void legacyProtocolRules() throws Exception {
        String token = aliceToken();
        assertThat(sendRpc(token, null, "2025-11-25", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}", Map.of())
                .statusCode()).isEqualTo(400);
        HttpResponse<String> init = send(token, "/s/mcp-jira/mcp",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\","
                        + "\"capabilities\":{},\"clientInfo\":{\"name\":\"t\",\"version\":\"1\"}}}", Map.of());
        assertThat(JSON.readTree(init.body()).path("result").path("protocolVersion").asString()).isEqualTo("2025-11-25");
        String session = init.headers().firstValue("Mcp-Session-Id").orElseThrow();
        assertThat(sendRpc(token, session, "2025-06-18", "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}", Map.of())
                .statusCode()).isEqualTo(400);
        assertThat(sendRpc(token, session, "2025-11-25", "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}",
                Map.of()).statusCode()).isEqualTo(202);
        assertThat(http.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/s/mcp-jira/mcp"))
                .header("Authorization", "Bearer " + token).GET().build(), HttpResponse.BodyHandlers.ofString())
                .statusCode()).isEqualTo(405);
        HttpResponse<String> delete = http.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/s/mcp-jira/mcp"))
                .header("Authorization", "Bearer " + token).header("Mcp-Session-Id", session).DELETE().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(delete.statusCode()).isEqualTo(204);
        assertThat(sendRpc(token, session, "2025-11-25", "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"ping\"}", Map.of())
                .statusCode()).isEqualTo(404);
        assertThat(send(token, "/s/mcp-jira/mcp", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}",
                Map.of("Origin", "https://evil.example")).statusCode()).isEqualTo(403);
    }

    // --- Modern clients (2026-07-28) ----------------------------------------------------------------------

    @Test
    void modernClientWorksWithoutSession() throws Exception {
        String token = aliceToken();
        HttpResponse<String> discover = sendModern(token, "server/discover", null, "{}");
        assertThat(discover.statusCode()).isEqualTo(200);
        JsonNode discovered = JSON.readTree(discover.body()).path("result");
        assertThat(discovered.path("resultType").asString()).isEqualTo("complete");
        assertThat(discovered.path("supportedVersions").toString()).contains("2026-07-28", "2025-11-25");

        HttpResponse<String> list = sendModern(token, "tools/list", null, "{}");
        assertThat(JSON.readTree(list.body()).path("result").path("tools").size()).isEqualTo(2);
        assertThat(list.headers().firstValue("Mcp-Session-Id")).isEmpty();

        HttpResponse<String> call = sendModern(token, "tools/call", "jira__get_issue",
                "{\"name\":\"jira__get_issue\",\"arguments\":{\"issueKey\":\"ABC-1\"}}");
        JsonNode result = JSON.readTree(call.body()).path("result");
        assertThat(result.path("resultType").asString()).isEqualTo("complete");
        assertThat(result.path("isError").asBoolean()).isFalse();
        assertThat(lastToolCall(env.jira).header("x-mcp-credential")).isEqualTo("Bearer alice-pat");

        HttpResponse<String> encodedName = sendModern(token, "tools/call",
                "=?base64?" + Base64.getEncoder().encodeToString("jira__get_issue".getBytes(StandardCharsets.UTF_8)) + "?=",
                "{\"name\":\"jira__get_issue\",\"arguments\":{\"issueKey\":\"ABC-1\"}}");
        assertThat(encodedName.statusCode()).isEqualTo(200);
    }

    @Test
    void modernHeaderAndVersionErrors() throws Exception {
        String token = aliceToken();
        HttpResponse<String> mismatch = sendModern(token, "tools/call", "jira__search_issues",
                "{\"name\":\"jira__get_issue\",\"arguments\":{\"issueKey\":\"ABC-1\"}}");
        assertThat(mismatch.statusCode()).isEqualTo(400);
        assertThat(JSON.readTree(mismatch.body()).path("error").path("code").asInt()).isEqualTo(-32020);

        String unsupported = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{\"_meta\":{"
                + "\"io.modelcontextprotocol/protocolVersion\":\"2099-01-01\",\"io.modelcontextprotocol/clientCapabilities\":{}}}}";
        HttpResponse<String> version = send(token, "/s/mcp-jira/mcp", unsupported,
                Map.of("MCP-Protocol-Version", "2099-01-01", "Mcp-Method", "tools/list"));
        assertThat(version.statusCode()).isEqualTo(400);
        JsonNode error = JSON.readTree(version.body()).path("error");
        assertThat(error.path("code").asInt()).isEqualTo(-32022);
        assertThat(error.path("data").path("supported").toString()).contains("2026-07-28");

        HttpResponse<String> unknown = sendModern(token, "resources/list", null, "{}");
        assertThat(unknown.statusCode()).isEqualTo(404);
        assertThat(JSON.readTree(unknown.body()).path("error").path("code").asInt()).isEqualTo(-32601);
    }

    // --- Authorization (M1 stand-in), unknown tools --------------------------------------------------------

    @Test
    void userWithoutGroupsSeesNothingAndIsDenied(CapturedOutput output) throws Exception {
        String mallory = env.idp.token("a8d1b0c2-0000-4000-8000-000000000001", "mallory", List.of());
        HttpResponse<String> list = sendModern(mallory, "tools/list", null, "{}");
        assertThat(JSON.readTree(list.body()).path("result").path("tools").size()).isZero();
        HttpResponse<String> call = sendModern(mallory, "tools/call", "jira__get_issue",
                "{\"name\":\"jira__get_issue\",\"arguments\":{\"issueKey\":\"ABC-1\"}}");
        assertThat(toolError(call).path("error").asString()).as("a tool the user may not call is a tool that does not exist (CC-178)")
                .isEqualTo("not_found_or_denied");
        assertThat(toolError(call).has("requiredEntitlements")).isFalse();
        assertThat(env.broker.received()).noneMatch(r -> r.path().equals("/v1/credentials/resolve"));
        assertThat(env.jira.requests()).isEmpty();
        String rid = call.headers().firstValue("X-Request-Id").orElseThrow();
        assertThat(auditEvents(output, rid)).anySatisfy(e -> {
            assertThat(e.path("event").asString()).isEqualTo("tool_call");
            assertThat(e.path("outcome").asString()).isEqualTo("denied");
            assertThat(e.path("reason").asString()).isEqualTo("not_granted");
        });
    }

    @Test
    void unconfiguredToolIsNotFound() throws Exception {
        HttpResponse<String> call = sendModern(aliceToken(), "tools/call", "jira__drop_project",
                "{\"name\":\"jira__drop_project\",\"arguments\":{\"issueKey\":\"ABC-1\"}}");
        assertThat(toolError(call).path("error").asString()).isEqualTo("not_found_or_denied");
        assertThat(env.jira.requests()).noneMatch(r -> "tools/call".equals(r.rpcMethod()));
        HttpResponse<String> unprefixed = sendModern(aliceToken(), "tools/call", "get_issue",
                "{\"name\":\"get_issue\",\"arguments\":{\"issueKey\":\"ABC-1\"}}");
        assertThat(toolError(unprefixed).path("error").asString()).isEqualTo("not_found_or_denied");
    }

    // --- Credentials: broker errors, cache, invalidation ---------------------------------------------------

    @Test
    void brokerUnavailableMeansUpstreamUnavailableAndNoServerCall() throws Exception {
        env.broker.mode(BrokerStub.Mode.UNAVAILABLE);
        HttpResponse<String> call = sendModern(aliceToken(), "tools/call", "jira__get_issue",
                "{\"name\":\"jira__get_issue\",\"arguments\":{\"issueKey\":\"ABC-1\"}}");
        assertThat(toolError(call).path("error").asString()).isEqualTo("upstream_unavailable");
        assertThat(env.jira.requests()).noneMatch(r -> "tools/call".equals(r.rpcMethod()));
    }

    @Test
    void brokerConnectionFailureMeansUpstreamUnavailable() throws Exception {
        env.broker.mode(BrokerStub.Mode.DROP);
        String token = env.idp.token("c0ffee00-0000-4000-8000-00000000000a", "carol", List.of("mcp-jira-read"));
        HttpResponse<String> call = sendModern(token, "tools/call", "jira__get_issue",
                "{\"name\":\"jira__get_issue\",\"arguments\":{\"issueKey\":\"ABC-1\"}}");
        assertThat(toolError(call).path("error").asString()).isEqualTo("upstream_unavailable");
        assertThat(env.jira.requests()).noneMatch(r -> "tools/call".equals(r.rpcMethod()));
    }

    @Test
    void missingConnectionMeansCredentialRequiredWithConnectUrl() throws Exception {
        env.broker.mode(BrokerStub.Mode.REQUIRED);
        String token = env.idp.token("d00d0000-0000-4000-8000-00000000000b", "dave", List.of("mcp-jira-read"));
        HttpResponse<String> call = sendModern(token, "tools/call", "jira__get_issue",
                "{\"name\":\"jira__get_issue\",\"arguments\":{\"issueKey\":\"ABC-1\"}}");
        JsonNode error = toolError(call);
        assertThat(error.path("error").asString()).isEqualTo("credential_required");
        assertThat(error.path("system").asString()).isEqualTo("jira");
        assertThat(error.path("connectUrl").asString()).isEqualTo(GatewayTestEnvironment.PUBLIC_URL + "/connections?system=jira");
        assertThat(Contracts.schemaErrors("schemas/tool-error.schema.json", error)).isEmpty();
        assertThat(env.jira.requests()).noneMatch(r -> "tools/call".equals(r.rpcMethod()));
    }

    @Test
    void invalidationEventDropsCachedCredentialWithinOneSecond() throws Exception {
        String sub = "e0e0e0e0-0000-4000-8000-00000000000c";
        String token = env.idp.token(sub, "erin", List.of("mcp-jira-read"));
        callGetIssue(token);
        callGetIssue(token);
        assertThat(resolveCount()).as("second call served from cache").isEqualTo(1);

        env.broker.mode(BrokerStub.Mode.REQUIRED);
        publishInvalidation(sub, "jira");
        long published = System.nanoTime();
        await().atMost(Duration.ofSeconds(1)).pollInterval(Duration.ofMillis(50)).untilAsserted(() ->
                assertThat(toolError(callGetIssue(token)).path("error").asString()).isEqualTo("credential_required"));
        assertThat(Duration.ofNanos(System.nanoTime() - published)).isLessThan(Duration.ofSeconds(1));
    }

    @Test
    void invalidationOfAnotherUserOrSystemKeepsTheEntry() throws Exception {
        String sub = "f0f0f0f0-0000-4000-8000-00000000000d";
        String token = env.idp.token(sub, "frank", List.of("mcp-jira-read"));
        callGetIssue(token);
        publishInvalidation("someone-else", "jira");
        publishInvalidation(sub, "gitlab");
        Thread.sleep(300);
        callGetIssue(token);
        assertThat(resolveCount()).isEqualTo(1);
    }

    @Test
    void cachedCredentialExpiresWithItsTtl() throws Exception {
        env.broker.grant("alice-pat", 1);
        String token = env.idp.token("a1a1a1a1-0000-4000-8000-00000000000e", "gina", List.of("mcp-jira-read"));
        callGetIssue(token);
        env.broker.mode(BrokerStub.Mode.REQUIRED);
        assertThat(toolError(callGetIssue(token)).has("error")).as("still cached").isFalse();
        Thread.sleep(1100);
        assertThat(toolError(callGetIssue(token)).path("error").asString()).isEqualTo("credential_required");
    }

    @Test
    void serverCertificateMustNameTheServer() throws Exception {
        HttpResponse<String> list = sendModern(aliceToken(), "/s/mcp-confluence/mcp", "tools/list", null, "{}");
        assertThat(list.statusCode()).isEqualTo(200);
        assertThat(JSON.readTree(list.body()).path("result").path("tools").size()).as("a server that cannot be read is left out (CC-180)").isZero();
        assertThat(env.pinnedElsewhere.requests()).isEmpty();
    }

    @Test
    void startupCheckUsesTheServiceVariantAtTheBroker() {
        await().atMost(Duration.ofSeconds(10)).untilAsserted(() -> assertThat(env.broker.systemsCalls()).isNotEmpty());
        BrokerStub.Received systems = env.broker.systemsCalls().getFirst();
        assertThat(systems.rejectReason()).isNull();
        assertThat(systems.tool()).isNull();
    }

    // --- Review M1 findings: authorization levels, credential charset, Redis outage, limits ---------------

    @Test
    void destructiveToolNeedsItsGroupAndThenAConfirmation() throws Exception {
        String withoutGroup = env.idp.token("de570000-0000-4000-8000-000000000009", "dan", List.of("mcp-jira-read", "mcp-jira-write"));
        assertThat(sendModern(withoutGroup, "tools/list", null, "{}").body()).doesNotContain("jira__delete_issue");
        HttpResponse<String> refused = sendModern(withoutGroup, "tools/call", "jira__delete_issue",
                "{\"name\":\"jira__delete_issue\",\"arguments\":{\"issueKey\":\"ABC-1\"}}");
        assertThat(toolError(refused).path("error").asString()).isEqualTo("not_found_or_denied");

        String token = env.idp.token("de570000-0000-4000-8000-000000000010", "dora",
                List.of("mcp-jira-read", "mcp-jira-write", "mcp-jira-destructive"));
        assertThat(sendModern(token, "tools/list", null, "{}").body()).contains("jira__delete_issue").contains("confirmation_code");
        HttpResponse<String> call = sendModern(token, "tools/call", "jira__delete_issue",
                "{\"name\":\"jira__delete_issue\",\"arguments\":{\"issueKey\":\"ABC-1\"}}");
        JsonNode error = toolError(call);
        assertThat(error.path("error").asString()).isEqualTo("confirmation_required");
        assertThat(error.path("registerUrl").asString()).as("Dora has no authenticator").endsWith("/authenticator");
        assertThat(env.jira.requests()).noneMatch(r -> "tools/call".equals(r.rpcMethod()));
        assertThat(resolveCount()).as("the account is checked before the confirmation gate (CC-178), and the credential is not used").isEqualTo(1);
    }

    @Test
    void readOnlyUserCannotCallUpdateTool() throws Exception {
        String token = env.idp.token("4ead0000-0000-4000-8000-000000000011", "rita", List.of("mcp-jira-read"));
        HttpResponse<String> call = sendModern(token, "tools/call", "jira__add_comment",
                "{\"name\":\"jira__add_comment\",\"arguments\":{\"issueKey\":\"ABC-1\",\"body\":\"x\"}}");
        JsonNode error = toolError(call);
        assertThat(error.path("error").asString()).isEqualTo("not_found_or_denied");
        assertThat(resolveCount()).isZero();
        assertThat(env.jira.requests()).noneMatch(r -> "tools/call".equals(r.rpcMethod()));
    }

    @Test
    void credentialOutsideVisibleAsciiIsRejectedAndNeverLogged(CapturedOutput output) throws Exception {
        String value = "secret-\u0100-pat";
        env.broker.grant(value, 60);
        String token = env.idp.token("a5c11000-0000-4000-8000-000000000012", "ann", List.of("mcp-jira-read"));
        HttpResponse<String> call = callGetIssue(token);
        assertThat(call.statusCode()).isEqualTo(200);
        assertThat(toolError(call).path("error").asString()).isEqualTo("internal_error");
        assertThat(credentialCache.size()).isZero();
        assertThat(env.jira.requests()).noneMatch(r -> "tools/call".equals(r.rpcMethod()));
        assertThat(output.getAll()).doesNotContain(value).doesNotContain("secret-");
        String rid = call.headers().firstValue("X-Request-Id").orElseThrow();
        assertThat(auditEvents(output, rid)).anySatisfy(e -> assertThat(e.path("errorCode").asString()).isEqualTo("internal_error"));
    }

    @Test
    void brokerAnswersOutsideTheContractAreInternalErrorsWithoutServerCall() throws Exception {
        String token = env.idp.token("b40c0000-0000-4000-8000-000000000013", "ben", List.of("mcp-jira-read"));
        for (BrokerStub.Mode mode : List.of(BrokerStub.Mode.REJECT, BrokerStub.Mode.BAD_BODY)) {
            env.broker.mode(mode);
            assertThat(toolError(callGetIssue(token)).path("error").asString()).as(mode.name()).isEqualTo("internal_error");
        }
        assertThat(env.jira.requests()).noneMatch(r -> "tools/call".equals(r.rpcMethod()));
    }

    @Test
    void redisOutageDisablesTheCacheUntilTheSubscriptionIsBack() throws Exception {
        String token = env.idp.token("4ed15000-0000-4000-8000-000000000014", "ivy", List.of("mcp-jira-read"));
        callGetIssue(token);
        assertThat(credentialCache.size()).isEqualTo(1);
        // The limits fail closed without Redis (RateLimitTest); this test is about the cache, so the limits are off here.
        pl.aiwcorpo.mcp.gateway.support.RateLimitTestConfiguration.use(new pl.aiwcorpo.mcp.gateway.config.GatewayProperties.RateLimit(false,
                Duration.ofMinutes(1), 1, 1, 1, 1, java.util.Map.of(), Duration.ofSeconds(10)));
        var docker = env.redis.getDockerClient();
        docker.pauseContainerCmd(env.redis.getContainerId()).exec();
        try {
            await().atMost(Duration.ofSeconds(15)).until(() -> !invalidations.live());
            await().atMost(Duration.ofSeconds(5)).until(() -> credentialCache.size() == 0);
            callGetIssue(token);
            callGetIssue(token);
            assertThat(resolveCount()).as("cache bypassed while Redis is unreachable").isEqualTo(3);
        } finally {
            docker.unpauseContainerCmd(env.redis.getContainerId()).exec();
            pl.aiwcorpo.mcp.gateway.support.RateLimitTestConfiguration.restore();
        }
        await().atMost(Duration.ofSeconds(20)).until(invalidations::live);
        env.broker.clear();
        callGetIssue(token);
        callGetIssue(token);
        assertThat(resolveCount()).as("cache used again after re-subscription").isEqualTo(1);
    }

    @Test
    void longLivedOrServiceLikeIdpTokensAreRejected() throws Exception {
        String longLived = env.idp.token(ALICE_SUB, "alice", ALICE_GROUPS, "mcp-gateway", "claude-code", 2 * 3600);
        assertThat(sendModern(longLived, "tools/list", null, "{}").statusCode()).isEqualTo(401);
        String systemSub = env.idp.token("system:mcp-gateway", "x", List.of("mcp-jira-read"));
        assertThat(sendModern(systemSub, "tools/list", null, "{}").statusCode()).isEqualTo(401);
    }

    @Test
    void requestBodyLimitAndAllowedOrigin() throws Exception {
        String big = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"params\":{\"pad\":\"" + "x".repeat(1024 * 1024)
                + "\"}}";
        assertThat(send(aliceToken(), "/s/mcp-jira/mcp", big, Map.of()).statusCode()).isEqualTo(413);
        assertThat(send(aliceToken(), "/s/mcp-jira/mcp", initializeBody(), Map.of("Origin", "https://allowed.test"))
                .statusCode()).isEqualTo(200);
        HttpResponse<String> delete = http.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/s/mcp-jira/mcp"))
                .header("Authorization", "Bearer " + aliceToken()).header("Mcp-Session-Id", "x".repeat(32))
                .header("Origin", "https://evil.test").DELETE().build(), HttpResponse.BodyHandlers.ofString());
        assertThat(delete.statusCode()).isEqualTo(403);
    }

    @Test
    void invalidToolsCallIsAudited(CapturedOutput output) throws Exception {
        HttpResponse<String> call = sendModern(aliceToken(), "tools/call", "jira__get_issue",
                "{\"name\":\"jira__get_issue\",\"arguments\":[1]}");
        assertThat(call.statusCode()).isEqualTo(400);
        String rid = call.headers().firstValue("X-Request-Id").orElseThrow();
        assertThat(auditEvents(output, rid)).anySatisfy(e -> {
            assertThat(e.path("event").asString()).isEqualTo("tool_call");
            assertThat(e.path("errorCode").asString()).isEqualTo("invalid_argument");
        });
    }
}
