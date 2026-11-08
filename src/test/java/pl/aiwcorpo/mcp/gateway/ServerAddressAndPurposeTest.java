package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import pl.aiwcorpo.mcp.gateway.audit.AuditLog;
import pl.aiwcorpo.mcp.gateway.jwt.JwksController;
import pl.aiwcorpo.mcp.gateway.jwt.UuidV7;
import pl.aiwcorpo.mcp.gateway.link.ServerLinks;
import pl.aiwcorpo.mcp.gateway.net.AddressPolicy;
import pl.aiwcorpo.mcp.gateway.policy.PolicyService;
import pl.aiwcorpo.mcp.gateway.registry.ManifestValidator;
import pl.aiwcorpo.mcp.gateway.registry.Outcome;
import pl.aiwcorpo.mcp.gateway.registry.RegistryService;
import pl.aiwcorpo.mcp.gateway.registry.RegistryStore;
import pl.aiwcorpo.mcp.gateway.registry.ServerAdmin;
import pl.aiwcorpo.mcp.gateway.registry.ServerChecks;
import pl.aiwcorpo.mcp.gateway.registry.ServerConfig;
import pl.aiwcorpo.mcp.gateway.tls.ServerTls;
import pl.aiwcorpo.mcp.testserver.TestMcpServer;
import tools.jackson.databind.JsonNode;

/**
 * The address a server is reached at and the purpose of the tokens the gateway sends it (C2, C5, C14, CC-249): the addresses that are refused when
 * a server is added and again at every connection, a token that is used for one purpose and nothing else, and the public key set that servers
 * fetch their keys from.
 */
class ServerAddressAndPurposeTest extends GatewayTestBase {

    @Autowired
    RegistryStore store;
    @Autowired
    RegistryService registry;
    @Autowired
    ServerChecks checks;
    @Autowired
    ManifestValidator validator;
    @Autowired
    PolicyService policies;
    @Autowired
    AuditLog audit;
    @Autowired
    ServerTls serverTls;

    private final List<TestMcpServer> started = new ArrayList<>();

    @AfterEach
    void cleanUp() throws Exception {
        adminCall("DELETE", "/admin/v1/servers/mcp-addr", null);
        started.forEach(TestMcpServer::close);
        started.clear();
    }

    private JsonNode json(HttpResponse<String> response) {
        return JSON.readTree(response.body());
    }

    // --- the address ---------------------------------------------------------------------------------------------

    @Test
    void anAddressThatIsRefusedIsRefusedWhateverWayItIsWrittenAndNothingIsStored() throws Exception {
        for (String url : List.of("https://169.254.169.254/latest", "http://169.254.169.254/latest", "https://0.0.0.0/mcp", "https://224.0.0.1/mcp",
                "https://[fe80::1]/mcp", "https://[fd00:ec2::254]/mcp", "http://2852039166/mcp", "http://0xa9.0xfe.0xa9.0xfe/mcp",
                "https://[::ffff:169.254.169.254]/mcp", "http://255.255.255.255/mcp", "https://[64:ff9b::a9fe:a9fe]/mcp", "http://169.254.169.254.:80/")) {
            HttpResponse<String> response = adminCall("POST", "/admin/v1/servers", "{\"internalUrl\":\"" + url + "\"}");
            if (response.statusCode() == 400) {
                continue; // a form that is no address of a server at all
            }
            assertThat(response.statusCode()).as(url + ": " + response.body()).isEqualTo(422);
            assertThat(json(response).path("error").asString()).isEqualTo("server_rejected");
            assertThat(json(response).path("reason").asString()).as(url).isEqualTo("address_refused");
            assertThat(json(response).path("message").asString()).as("names the address and its class").contains("address");
        }
        assertThat(json(adminCall("GET", "/admin/v1/servers", null)).findValuesAsString("serverId")).doesNotContain("mcp-addr");
    }

    @Test
    void loopbackIsRefusedUnlessTheDevelopmentStackAllowsItAndNothingIsConnectedTo() throws Exception {
        TestMcpServer server = env.startServer("mcp-addr");
        started.add(server);
        ServerAdmin strict = new ServerAdmin(store, registry, checks, validator, new AddressPolicy(false), policies, audit, "mcp-gateway", JSON,
                Clock.systemUTC(), Duration.ZERO, id -> { });
        pl.aiwcorpo.mcp.gateway.auth.GatewayUser administrator = new pl.aiwcorpo.mcp.gateway.auth.GatewayUser(ADMIN_SUB, "a.admin", "mcp-portal-bff",
                List.of("mcp-platform-admin"), "unused");

        Outcome<ServerAdmin.Item> outcome = strict.create(UuidV7.next(), JSON.readTree("{\"internalUrl\":\"https://127.0.0.1:" + server.port() + "/mcp\"}"),
                administrator);

        assertThat(outcome.status()).isEqualTo(Outcome.Status.REJECTED);
        assertThat(outcome.reason()).isEqualTo("address_refused");
        assertThat(outcome.message()).contains("127.0.0.1").contains("loopback");
        assertThat(server.requests()).as("the address was judged before any connection").isEmpty();
        assertThat(server.manifestReads()).isEmpty();
        assertThat(store.config("mcp-addr")).isEmpty();
    }

    @Test
    void theAddressIsJudgedAgainAtEveryConnectionOnTheAddressThatIsConnectedTo() throws Exception {
        TestMcpServer server = env.startServer("mcp-addr");
        started.add(server);
        JsonNode added = JSON.readTree(adminCall("POST", "/admin/v1/servers", "{\"internalUrl\":\"https://127.0.0.1:" + server.port() + "/mcp\"}").body());
        String fingerprint = added.path("pendingConnection").path("fingerprint").asString();
        assertThat(adminCall("POST", "/admin/v1/servers/mcp-addr/connection/approve", "{\"tlsMode\":\"ca\",\"fingerprint\":\"" + fingerprint + "\"}")
                .statusCode()).isEqualTo(200);
        server.clearRequests();
        // The same server and the same name, but now the host resolves to an address that is refused (as DNS rebinding makes it).
        ServerLinks strict = new ServerLinks(new AddressPolicy(false), serverTls, issuer, JSON);

        ServerLinks.Pull pull = strict.pullManifest(URI.create("https://127.0.0.1:" + server.port() + "/mcp"), "ca", null);
        assertThat(pull.succeeded()).isFalse();
        assertThat(pull.failure()).isEqualTo(ServerLinks.Failure.ADDRESS_REFUSED);
        assertThat(strict.pushPolicyData(URI.create("https://127.0.0.1:" + server.port() + "/mcp"), "mcp-addr", "ca", null, 1, JSON.createObjectNode())
                .failure()).isEqualTo(ServerLinks.Failure.ADDRESS_REFUSED);
        assertThat(server.manifestReads()).isEmpty();
        assertThat(server.policyPushes()).isEmpty();

        ServerChecks strictChecks = new ServerChecks(store, registry, strict, audit, "mcp-gateway", Clock.systemUTC(), Duration.ofSeconds(60), Duration.ofSeconds(60));
        try {
            ServerConfig after = strictChecks.check(UuidV7.next(), "mcp-addr").orElseThrow();
            assertThat(after.status()).isEqualTo(ServerConfig.UNREACHABLE);
            assertThat(after.lastError()).isEqualTo("address_refused");
            assertThat(after.connection()).as("what was approved is untouched").isNotNull();
            assertThat(server.requests()).isEmpty();
        } finally {
            strictChecks.destroy();
        }
    }

    // --- the purpose of a token -------------------------------------------------------------------------------------

    @Test
    void everyTokenOfTheGatewayCarriesTheUseOfItsRequestAndNoneServesAnother() throws Exception {
        env.jira.clearRequests();
        assertThat(toolError(callGetIssue(aliceToken())).path("error").asString()).isEmpty();
        env.jira.forgetPolicyData();
        assertThat(toolError(callGetIssue(aliceToken())).path("error").asString()).as("through a stale push").isEmpty();
        assertThat(adminCall("POST", "/admin/v1/servers/mcp-jira/refresh", null).statusCode()).isEqualTo(200);

        await().atMost(Duration.ofSeconds(10)).untilAsserted(() -> assertThat(env.jira.policyPushes()).isNotEmpty());
        assertThat(env.jira.requests()).isNotEmpty().allSatisfy(request -> {
            if (request.header("authorization") != null) {
                assertThat(claims(request.header("authorization")).path("use").asString()).as(request.rpcMethod()).isEqualTo("call");
            }
        });
        assertThat(env.jira.manifestReads()).as("the manifest is pulled without a token").isNotEmpty().allSatisfy(read ->
                assertThat(read.header("authorization")).isNull());
        assertThat(env.jira.policyPushes()).allSatisfy(push ->
                assertThat(claims(push.header("authorization")).path("use").asString()).isEqualTo("policy-data"));
        assertThat(env.broker.received()).as("the broker takes call tokens only, and refused none").isNotEmpty().allSatisfy(received ->
                assertThat(received.rejectReason()).isNull());
    }

    @Test
    void theManifestNeedsNoTokenAndAPolicyDataTokenIsRefusedForAnotherPurposeAndWorksOnce() throws Exception {
        env.jira.clearRequests();
        String ridCall = UuidV7.next();
        assertThat(manifestGet(null, ridCall)).as("no token at the manifest").isEqualTo(200);
        assertThat(manifestGet(issuer.forService("mcp-jira", ridCall), ridCall)).as("a token that arrives is not read").isEqualTo(200);
        assertThat(refused(env.jira.manifestReads())).isEmpty();

        String ridUser = UuidV7.next();
        assertThat(pushWith(issuer.forUser("mcp-jira", alice(), null, ridUser), ridUser)).as("a user token at policy-data").isEqualTo(401);
        String ridService = UuidV7.next();
        assertThat(pushWith(issuer.forService("mcp-jira", ridService), ridService)).as("a call token at policy-data").isEqualTo(401);
        assertThat(refused(env.jira.policyPushes())).containsExactly("wrong_purpose", "wrong_purpose");

        String ridData = UuidV7.next();
        String data = issuer.forPolicyData("mcp-jira", ridData, 1);
        assertThat(pushWith(data, ridData)).as("the right purpose passes the check").isNotEqualTo(401);
        assertThat(pushWith(data, ridData)).as("the same token again").isEqualTo(401);
        assertThat(refused(env.jira.policyPushes())).last().isEqualTo("replayed_jti");
    }

    /** The reasons of the requests a server refused, in order. */
    private static List<String> refused(List<TestMcpServer.RecordedRequest> requests) {
        return requests.stream().map(TestMcpServer.RecordedRequest::rejectReason).filter(java.util.Objects::nonNull).toList();
    }

    private int manifestGet(String token, String requestId) throws Exception {
        return sendToJira("GET", "/.well-known/mcp-manifest", token, requestId, null);
    }

    private int pushWith(String token, String requestId) throws Exception {
        return sendToJira("POST", "/.well-known/mcp-policy-data", token, requestId, "{\"revision\":1,\"scopeMapping\":[]}");
    }

    private int sendToJira(String method, String path, String token, String requestId, String body) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create("https://127.0.0.1:" + env.jira.port() + path))
                .header("X-Request-Id", requestId).timeout(Duration.ofSeconds(5));
        if (token != null) {
            request.header("Authorization", "Bearer " + token);
        }
        request.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        HttpClient client = HttpClient.newBuilder().sslContext(env.noClientCertificateTls).build();
        return client.send(request.build(), HttpResponse.BodyHandlers.discarding()).statusCode();
    }

    // --- the public key set -----------------------------------------------------------------------------------------

    @Test
    void theKeysOfTheGatewayArePublicOnThePublicPortWithoutAnyCredential() throws Exception {
        HttpResponse<String> response = http.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + JwksController.PUBLIC_PATH)).GET().build(),
                HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.headers().firstValue("Cache-Control").orElse("")).contains("public").contains("max-age=300");
        assertThat(response.headers().firstValue("Content-Type").orElse("")).startsWith("application/json");
        JsonNode keys = JSON.readTree(response.body()).path("keys");
        assertThat(keys).isNotEmpty();
        keys.forEach(key -> assertThat(key.has("d")).as("no private part").isFalse());
        HttpResponse<String> internal = java.net.http.HttpClient.newBuilder().sslContext(env.noClientCertificateTls).build().send(
                HttpRequest.newBuilder(URI.create("https://localhost:" + env.internalPort + "/.well-known/jwks.json")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(JSON.readTree(internal.body())).as("the same document as on the internal port").isEqualTo(JSON.readTree(response.body()));
        assertThat(http.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/.well-known/jwks.json")).GET().build(),
                HttpResponse.BodyHandlers.ofString()).statusCode()).as("the old internal path is not public").isEqualTo(404);
        assertThat(http.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + JwksController.PUBLIC_PATH)).POST(
                HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.ofString()).statusCode()).isNotEqualTo(200);
    }
}
