package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.system.CapturedOutput;

import pl.aiwcorpo.mcp.gateway.jwt.UuidV7;
import pl.aiwcorpo.mcp.gateway.registry.ServerChecks;
import pl.aiwcorpo.mcp.gateway.support.Contracts;
import pl.aiwcorpo.mcp.gateway.support.Manifests;
import pl.aiwcorpo.mcp.testserver.TestMcpServer;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * Adding a server by its address, approving its connection and what the gateway does when the certificate it meets is not the one it
 * knows (C5, CC-249), on real TLS servers: a certificate of the internal CA that names the host (proposed as {@code ca}), a self-signed one
 * and one for another host (proposed as {@code pinned}), and plain http; the three modes in use; a pinned certificate that changes, a
 * {@code ca} certificate that renews or stops validating.
 */
class ServerConnectionTest extends GatewayTestBase {

    private static final String SERVER = "/admin/v1/servers/mcp-conn";
    private static final List<String> GROUPS = List.of("mcp-conn-read");

    @Autowired
    ServerChecks checks;

    private final List<TestMcpServer> started = new ArrayList<>();

    @AfterEach
    void cleanUp() throws Exception {
        adminCall("DELETE", SERVER, null);
        started.forEach(TestMcpServer::close);
        started.clear();
    }

    private TestMcpServer track(TestMcpServer server) {
        started.add(server);
        return server;
    }

    private static String urlOf(TestMcpServer server) {
        return "https://127.0.0.1:" + server.port() + "/mcp";
    }

    private JsonNode json(HttpResponse<String> response) {
        return JSON.readTree(response.body());
    }

    private JsonNode add(String body) throws Exception {
        HttpResponse<String> created = adminCall("POST", "/admin/v1/servers", body);
        assertThat(created.statusCode()).as(created.body()).isEqualTo(201);
        JsonNode server = json(created);
        assertThat(Contracts.gatewayAdminErrors("ServerConfig", server)).isEmpty();
        return server;
    }

    private JsonNode get() throws Exception {
        return json(adminCall("GET", SERVER, null));
    }

    private HttpResponse<String> approveConnection(String mode, String fingerprint) throws Exception {
        return adminCall("POST", SERVER + "/connection/approve", "{\"tlsMode\":\"" + mode + "\",\"fingerprint\":"
                + (fingerprint == null ? "null" : "\"" + fingerprint + "\"") + "}");
    }

    private HttpResponse<String> refresh() throws Exception {
        return adminCall("POST", SERVER + "/refresh", null);
    }

    /** Everything an administrator approves after the connection: the policies and the read tool. */
    private void approvePoliciesAndTool(TestMcpServer server) throws Exception {
        ObjectNode manifest = server.manifest();
        assertThat(adminCall("POST", "/admin/v1/registry/servers/mcp-conn/policies/approve",
                "{\"policiesHash\":\"" + manifest.path("policiesHash").asString() + "\"}").statusCode()).isEqualTo(200);
        assertThat(adminCall("POST", "/admin/v1/registry/servers/mcp-conn/tools/get_issue/approve",
                "{\"definitionHash\":\"" + Manifests.tool(manifest, "get_issue").path("definitionHash").asString() + "\"}").statusCode()).isEqualTo(204);
    }

    private JsonNode callConn() throws Exception {
        String token = env.idp.token(UUID.randomUUID().toString(), "cora", GROUPS);
        return toolError(sendModern(token, "/mcp", "tools/call", "conn__get_issue",
                "{\"name\":\"conn__get_issue\",\"arguments\":{\"issueKey\":\"ABC-1\"}}"));
    }

    private static List<JsonNode> events(CapturedOutput output, String reason) {
        List<JsonNode> found = new ArrayList<>();
        for (String line : output.getOut().split("\n")) {
            if (line.startsWith("{") && line.contains("\"reason\":\"" + reason + "\"") && line.contains("\"server\":\"mcp-conn\"")) {
                found.add(JSON.readTree(line));
            }
        }
        return found;
    }

    // --- the proposal --------------------------------------------------------------------------------------------

    @Test
    void aCertificateOfTheInternalCaThatNamesTheHostIsProposedAsCaAndTheAdministratorMayPinItInstead(CapturedOutput output) throws Exception {
        TestMcpServer server = track(env.startServer("mcp-conn"));
        JsonNode added = add("{\"internalUrl\":\"" + urlOf(server) + "\"}");
        JsonNode pending = added.path("pendingConnection");
        assertThat(pending.path("tlsMode").asString()).isEqualTo("ca");
        assertThat(pending.path("validatesAsCa").asBoolean()).isTrue();
        assertThat(pending.path("subject").asString()).isEqualTo("CN=mcp-conn");
        assertThat(pending.path("issuer").asString()).isEqualTo("CN=test-internal-ca");
        assertThat(pending.path("sans").toString()).contains("127.0.0.1", "localhost");
        assertThat(pending.path("notAfter").asString()).isNotEmpty();
        assertThat(pending.path("fingerprint").asString()).isEqualTo(env.fingerprint(server));

        String requestId = UuidV7.next();
        HttpResponse<String> approved = adminCall("POST", SERVER + "/connection/approve", "{\"tlsMode\":\"pinned\",\"fingerprint\":\""
                + env.fingerprint(server) + "\"}", Map.of("X-Request-Id", requestId));

        assertThat(approved.statusCode()).as(approved.body()).isEqualTo(200);
        JsonNode connected = json(approved);
        assertThat(Contracts.gatewayAdminErrors("ServerConfig", connected)).isEmpty();
        assertThat(connected.path("connection").path("tlsMode").asString()).as("stricter than the proposal is allowed").isEqualTo("pinned");
        assertThat(connected.path("connection").path("fingerprint").asString()).isEqualTo(env.fingerprint(server));
        assertThat(connected.path("connection").path("approvedBy").asString()).isEqualTo(ADMIN_SUB);
        assertThat(connected.path("pendingConnection").isNull()).isTrue();
        assertThat(connected.path("status").asString()).as("the gateway connected under the approved trust").isEqualTo("connected");
        JsonNode event = auditEvents(output, requestId).stream().filter(e -> "server_connection_approved".equals(e.path("reason").asString()))
                .findFirst().orElseThrow();
        assertThat(event.path("tlsMode").asString()).isEqualTo("pinned");
        assertThat(event.path("fingerprint").asString()).isEqualTo(env.fingerprint(server));
        assertThat(event.path("sub").asString()).isEqualTo(ADMIN_SUB);
        assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", event)).isEmpty();
        assertThat(event.toString()).as("never the certificate").doesNotContain("BEGIN CERTIFICATE");
    }

    @Test
    void aSelfSignedCertificateIsProposedAsPinnedAndCaIsRefusedForIt() throws Exception {
        TestMcpServer server = track(env.startSelfSignedServer("mcp-conn"));
        JsonNode pending = add("{\"internalUrl\":\"" + urlOf(server) + "\"}").path("pendingConnection");
        assertThat(pending.path("tlsMode").asString()).isEqualTo("pinned");
        assertThat(pending.path("validatesAsCa").asBoolean()).isFalse();
        assertThat(pending.path("reason").asString()).isEqualTo("first_connection");
        assertThat(pending.path("subject").asString()).isEqualTo(pending.path("issuer").asString());
        String fingerprint = pending.path("fingerprint").asString();

        HttpResponse<String> asCa = approveConnection("ca", fingerprint);
        assertThat(asCa.statusCode()).isEqualTo(422);
        assertThat(json(asCa).path("error").asString()).isEqualTo("server_rejected");
        assertThat(json(asCa).path("reason").asString()).isEqualTo("tls_mode_not_allowed");
        assertThat(approveConnection("plain", null).statusCode()).as("plain is never for https: another fingerprint than the one that waits").isEqualTo(409);
        assertThat(json(approveConnection("plain", null)).path("error").asString()).isEqualTo("connection_changed");

        HttpResponse<String> pinned = approveConnection("pinned", fingerprint);
        assertThat(pinned.statusCode()).as(pinned.body()).isEqualTo(200);
        assertThat(json(pinned).path("connection").path("tlsMode").asString()).isEqualTo("pinned");
        assertThat(json(pinned).path("status").asString()).isEqualTo("connected");
    }

    @Test
    void aCertificateThatDoesNotNameTheHostIsProposedAsPinnedToo() throws Exception {
        TestMcpServer server = track(env.startServerForAnotherHost("mcp-conn"));

        JsonNode pending = add("{\"internalUrl\":\"" + urlOf(server) + "\"}").path("pendingConnection");

        assertThat(pending.path("tlsMode").asString()).isEqualTo("pinned");
        assertThat(pending.path("validatesAsCa").asBoolean()).as("signed by a CA of the trust, but for another host").isFalse();
    }

    @Test
    void anApprovalNeedsWhatTheAdministratorSawAndSomethingToApprove() throws Exception {
        TestMcpServer server = track(env.startSelfSignedServer("mcp-conn"));
        JsonNode pending = add("{\"internalUrl\":\"" + urlOf(server) + "\"}").path("pendingConnection");
        String other = "sha256:" + "b".repeat(64);

        HttpResponse<String> changed = approveConnection("pinned", other);
        assertThat(changed.statusCode()).isEqualTo(409);
        assertThat(json(changed).path("error").asString()).isEqualTo("connection_changed");
        assertThat(get().path("connection").isNull()).as("nothing was approved").isTrue();
        assertThat(adminCall("POST", SERVER + "/connection/approve", "{\"tlsMode\":\"pinned\"}").statusCode()).as("the fingerprint is part of the body").isEqualTo(400);
        assertThat(adminCall("POST", SERVER + "/connection/approve", "{\"tlsMode\":\"unknown\",\"fingerprint\":null}").statusCode()).isEqualTo(400);

        assertThat(approveConnection("pinned", pending.path("fingerprint").asString()).statusCode()).isEqualTo(200);
        HttpResponse<String> nothing = approveConnection("pinned", pending.path("fingerprint").asString());
        assertThat(nothing.statusCode()).isEqualTo(409);
        assertThat(json(nothing).path("error").asString()).isEqualTo("no_pending_connection");
        assertThat(adminCall("POST", "/admin/v1/servers/mcp-nobody/connection/approve", "{\"tlsMode\":\"ca\",\"fingerprint\":null}").statusCode()).isEqualTo(404);
    }

    @Test
    void addingAndApprovingNeedAFreshMfaAndRefreshingDoesNot() throws Exception {
        TestMcpServer server = track(env.startServer("mcp-conn"));
        String stale = env.idp.adminToken(ADMIN_SUB, "a.admin", List.of("mcp-platform-admin"), 3600L, List.of("pwd"), null);

        HttpResponse<String> add = admin(env.bffTls, "POST", "/admin/v1/servers", stale, "{\"internalUrl\":\"" + urlOf(server) + "\"}");
        assertThat(add.statusCode()).isEqualTo(401);
        assertThat(json(add).path("error").asString()).isEqualTo("step_up_required");
        assertThat(adminCall("GET", SERVER, null).statusCode()).as("nothing was added").isEqualTo(404);

        JsonNode pending = add("{\"internalUrl\":\"" + urlOf(server) + "\"}").path("pendingConnection");
        HttpResponse<String> approve = admin(env.bffTls, "POST", SERVER + "/connection/approve", stale, "{\"tlsMode\":\"ca\",\"fingerprint\":\""
                + pending.path("fingerprint").asString() + "\"}");
        assertThat(approve.statusCode()).isEqualTo(401);
        assertThat(json(approve).path("error").asString()).isEqualTo("step_up_required");
        assertThat(admin(env.bffTls, "POST", SERVER + "/refresh", stale, null).statusCode()).as("it approves nothing").isEqualTo(200);
    }

    // --- plain http ------------------------------------------------------------------------------------------------

    @Test
    void aPlainHttpServerNeedsTheFlagWhenAddedAndIsThenApprovedAsPlainAndCalled() throws Exception {
        TestMcpServer server = track(env.startPlainServer("mcp-conn"));
        String url = "http://127.0.0.1:" + server.port() + "/mcp";
        HttpResponse<String> without = adminCall("POST", "/admin/v1/servers", "{\"internalUrl\":\"" + url + "\"}");
        assertThat(without.statusCode()).isEqualTo(422);
        assertThat(json(without).path("reason").asString()).isEqualTo("plain_http_not_allowed");

        JsonNode added = add("{\"internalUrl\":\"" + url + "\",\"allowPlainHttp\":true}");
        assertThat(added.path("allowPlainHttp").asBoolean()).isTrue();
        JsonNode pending = added.path("pendingConnection");
        assertThat(pending.path("tlsMode").asString()).isEqualTo("plain");
        assertThat(pending.path("fingerprint").isNull()).isTrue();
        assertThat(pending.path("subject").isNull()).isTrue();
        assertThat(pending.path("sans")).isEmpty();
        assertThat(pending.path("validatesAsCa").asBoolean()).isFalse();
        assertThat(approveConnection("pinned", null).statusCode()).as("pinned has no certificate to pin on http").isEqualTo(422);
        assertThat(approveConnection("ca", null).statusCode()).isEqualTo(422);

        assertThat(approveConnection("plain", null).statusCode()).isEqualTo(200);
        approvePoliciesAndTool(server);

        assertThat(callConn().path("error").asString()).as("a call over plain http reaches the server").isEmpty();
        assertThat(server.requests().stream().filter(r -> "tools/call".equals(r.rpcMethod()) && r.status() == 200)).isNotEmpty();
    }

    // --- the three modes in use ----------------------------------------------------------------------------------

    @Test
    void aCaServerIsCalledOnceEverythingIsApprovedAndNotBefore() throws Exception {
        TestMcpServer server = track(env.startServer("mcp-conn"));
        JsonNode pending = add("{\"internalUrl\":\"" + urlOf(server) + "\"}").path("pendingConnection");
        assertThat(callConn().path("error").asString()).as("nothing approved").isEqualTo("tool_disabled");

        assertThat(approveConnection("ca", pending.path("fingerprint").asString()).statusCode()).isEqualTo(200);
        assertThat(callConn().path("error").asString()).as("the connection alone is not enough").isEqualTo("tool_disabled");
        approvePoliciesAndTool(server);

        assertThat(callConn().path("error").asString()).isEmpty();
        assertThat(get().path("connection").path("tlsMode").asString()).isEqualTo("ca");
        JsonNode hostile = null;
        for (TestMcpServer.RecordedRequest request : server.requests()) {
            if ("tools/call".equals(request.rpcMethod()) && request.status() == 200) {
                hostile = claims(request.header("authorization"));
            }
        }
        assertThat(hostile.path("use").asString()).isEqualTo("call");
    }

    @Test
    void aPinnedServerThatIsNotApprovedYetIsNeverCalledAndAnApprovedOneIs() throws Exception {
        TestMcpServer server = track(env.startSelfSignedServer("mcp-conn"));
        JsonNode pending = add("{\"internalUrl\":\"" + urlOf(server) + "\"}").path("pendingConnection");
        server.clearRequests();
        assertThat(callConn().path("error").asString()).isEqualTo("tool_disabled");
        assertThat(server.requests()).as("no connection is made for a tool that waits").noneMatch(r -> "tools/call".equals(r.rpcMethod()));

        assertThat(approveConnection("pinned", pending.path("fingerprint").asString()).statusCode()).isEqualTo(200);
        approvePoliciesAndTool(server);

        assertThat(callConn().path("error").asString()).isEmpty();
    }

    // --- the certificate changes ---------------------------------------------------------------------------------

    @Test
    void aPinnedServerThatPresentsAnotherCertificateIsUnreachableUntilTheNewOneIsApproved(CapturedOutput output) throws Exception {
        TestMcpServer first = track(env.startSelfSignedServer("mcp-conn"));
        int port = first.port();
        JsonNode pending = add("{\"internalUrl\":\"" + urlOf(first) + "\"}").path("pendingConnection");
        assertThat(approveConnection("pinned", pending.path("fingerprint").asString()).statusCode()).isEqualTo(200);
        approvePoliciesAndTool(first);
        assertThat(callConn().path("error").asString()).isEmpty();

        String firstFingerprint = env.fingerprint(first);
        first.close();
        TestMcpServer second = track(env.startSelfSignedServer("mcp-conn", port));
        String requestId = UuidV7.next();
        JsonNode after = json(adminCall("POST", SERVER + "/refresh", null, Map.of("X-Request-Id", requestId)));

        assertThat(after.path("status").asString()).isEqualTo("certificate_changed");
        assertThat(after.path("lastError").asString()).isEqualTo("certificate_changed");
        assertThat(after.path("connection").path("fingerprint").asString()).as("what was approved is still on record").isEqualTo(firstFingerprint);
        JsonNode waiting = after.path("pendingConnection");
        assertThat(waiting.path("tlsMode").asString()).isEqualTo("pinned");
        assertThat(waiting.path("reason").asString()).isEqualTo("certificate_changed");
        assertThat(waiting.path("fingerprint").asString()).isEqualTo(env.fingerprint(second));
        assertThat(Contracts.gatewayAdminErrors("ServerConfig", after)).isEmpty();
        assertThat(callConn().path("error").asString()).as("a certificate nobody approved is not talked to").isEqualTo("upstream_unavailable");
        JsonNode event = auditEvents(output, requestId).stream().filter(e -> "server_connection_changed".equals(e.path("reason").asString()))
                .findFirst().orElseThrow();
        assertThat(event.path("tlsMode").asString()).isEqualTo("pinned");
        assertThat(event.path("fingerprint").asString()).isEqualTo(env.fingerprint(second));
        assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", event)).isEmpty();
        assertThat(approveConnection("pinned", firstFingerprint).statusCode()).as("the old certificate is not what waits").isEqualTo(409);

        HttpResponse<String> approved = approveConnection("pinned", env.fingerprint(second));
        assertThat(approved.statusCode()).as(approved.body()).isEqualTo(200);
        assertThat(json(approved).path("status").asString()).isEqualTo("connected");
        assertThat(json(approved).path("pendingConnection").isNull()).isTrue();
        assertThat(callConn().path("error").asString()).as("the new certificate is the one in use now").isEmpty();
    }

    @Test
    void aCaServerThatRenewsItsCertificateNeedsNothing() throws Exception {
        TestMcpServer first = track(env.startServer("mcp-conn"));
        int port = first.port();
        JsonNode pending = add("{\"internalUrl\":\"" + urlOf(first) + "\"}").path("pendingConnection");
        assertThat(approveConnection("ca", pending.path("fingerprint").asString()).statusCode()).isEqualTo(200);
        approvePoliciesAndTool(first);

        String firstFingerprint = env.fingerprint(first);
        first.close();
        TestMcpServer renewed = track(env.startServer("mcp-conn", port));
        assertThat(env.fingerprint(renewed)).isNotEqualTo(firstFingerprint);
        JsonNode after = json(refresh());

        assertThat(after.path("status").asString()).isEqualTo("connected");
        assertThat(after.path("pendingConnection").isNull()).isTrue();
        assertThat(after.path("connection").path("fingerprint").asString()).as("the fingerprint shown is refreshed without an approval")
                .isEqualTo(env.fingerprint(renewed));
        assertThat(after.path("connection").path("approvedBy").asString()).isEqualTo(ADMIN_SUB);
        assertThat(callConn().path("error").asString()).isEmpty();
    }

    @Test
    void aCaServerWhoseCertificateStopsValidatingBecomesCertificateChangedWithAPinnedProposal() throws Exception {
        TestMcpServer first = track(env.startServer("mcp-conn"));
        int port = first.port();
        JsonNode pending = add("{\"internalUrl\":\"" + urlOf(first) + "\"}").path("pendingConnection");
        assertThat(approveConnection("ca", pending.path("fingerprint").asString()).statusCode()).isEqualTo(200);

        first.close();
        TestMcpServer selfSigned = track(env.startSelfSignedServer("mcp-conn", port));
        JsonNode after = json(refresh());

        assertThat(after.path("status").asString()).isEqualTo("certificate_changed");
        assertThat(after.path("pendingConnection").path("tlsMode").asString()).isEqualTo("pinned");
        assertThat(after.path("pendingConnection").path("reason").asString()).isEqualTo("ca_validation_failed");
        assertThat(after.path("pendingConnection").path("fingerprint").asString()).isEqualTo(env.fingerprint(selfSigned));
        assertThat(after.path("connection").path("tlsMode").asString()).as("the trust that was approved stays on record").isEqualTo("ca");
    }

    @Test
    void aPinnedServerWhoseNewCertificateValidatesAsCaGetsACaProposalThatStillNeedsApproval() throws Exception {
        TestMcpServer first = track(env.startSelfSignedServer("mcp-conn"));
        int port = first.port();
        JsonNode pending = add("{\"internalUrl\":\"" + urlOf(first) + "\"}").path("pendingConnection");
        assertThat(approveConnection("pinned", pending.path("fingerprint").asString()).statusCode()).isEqualTo(200);

        first.close();
        TestMcpServer signed = track(env.startServer("mcp-conn", port));
        JsonNode after = json(refresh());

        assertThat(after.path("status").asString()).isEqualTo("certificate_changed");
        assertThat(after.path("pendingConnection").path("tlsMode").asString()).isEqualTo("ca");
        assertThat(after.path("pendingConnection").path("validatesAsCa").asBoolean()).isTrue();
        assertThat(after.path("pendingConnection").path("fingerprint").asString()).isEqualTo(env.fingerprint(signed));
        assertThat(after.path("connection").path("tlsMode").asString()).isEqualTo("pinned");
    }

    @Test
    void aServerThatStopsAnsweringIsUnreachableAndTheCertificateThatWaitedStaysPending() throws Exception {
        TestMcpServer first = track(env.startSelfSignedServer("mcp-conn"));
        int port = first.port();
        JsonNode pending = add("{\"internalUrl\":\"" + urlOf(first) + "\"}").path("pendingConnection");
        assertThat(approveConnection("pinned", pending.path("fingerprint").asString()).statusCode()).isEqualTo(200);

        first.close();
        TestMcpServer other = track(env.startSelfSignedServer("mcp-conn", port));
        assertThat(json(refresh()).path("status").asString()).isEqualTo("certificate_changed");
        other.close();

        JsonNode down = json(refresh());
        assertThat(down.path("status").asString()).isEqualTo("unreachable");
        assertThat(down.path("lastError").asString()).isEqualTo("tls_handshake_failed");
        assertThat(down.path("pendingConnection").path("reason").asString()).isEqualTo("certificate_changed");
    }

    // --- refresh --------------------------------------------------------------------------------------------------

    @Test
    void aServerThatCannotBeReachedIsReportedInTheAnswerAndNotAsAnHttpError() throws Exception {
        TestMcpServer server = track(env.startServer("mcp-conn"));
        JsonNode pending = add("{\"internalUrl\":\"" + urlOf(server) + "\"}").path("pendingConnection");
        assertThat(approveConnection("ca", pending.path("fingerprint").asString()).statusCode()).isEqualTo(200);

        server.manifestStatus(404);
        JsonNode noManifest = json(refresh());
        assertThat(noManifest.path("status").asString()).isEqualTo("unreachable");
        assertThat(noManifest.path("lastError").asString()).isEqualTo("manifest_unreachable");

        server.manifestStatus(200);
        assertThat(json(refresh()).path("status").asString()).isEqualTo("connected");
        assertThat(json(refresh()).path("lastError").isNull()).isTrue();
        assertThat(adminCall("POST", "/admin/v1/servers/mcp-nobody/refresh", null).statusCode()).isEqualTo(404);
        assertThat(admin("POST", SERVER + "/refresh", BOB_SUB, "bob", List.of("mcp-jira-read"), null).statusCode()).as("administrators only").isEqualTo(403);
        assertThat(get().path("lastCheckedAt").asString()).isNotEmpty();
    }

    @Test
    void theLoopPullsTheManifestAndAChangedHashIsPendingAndBlocksTheToolOnceTheServerServesIt() throws Exception {
        TestMcpServer server = track(env.startServer("mcp-conn"));
        JsonNode pending = add("{\"internalUrl\":\"" + urlOf(server) + "\"}").path("pendingConnection");
        assertThat(approveConnection("ca", pending.path("fingerprint").asString()).statusCode()).isEqualTo(200);
        approvePoliciesAndTool(server);
        assertThat(callConn().path("error").asString()).isEmpty();
        server.clearRequests();

        ObjectNode changed = server.manifest();
        ((ObjectNode) Manifests.tool(changed, "get_issue").get("definition")).put("description", "A different text, pulled by the loop.");
        Manifests.rehash(changed, "get_issue");
        server.serveManifest(changed);
        forgetTheLastLooks();
        checks.tick();

        await().atMost(Duration.ofSeconds(10)).untilAsserted(() -> {
            assertThat(server.manifestReads()).as("the loop pulled the manifest").isNotEmpty();
            JsonNode tool = registryTool("get_issue");
            assertThat(tool.path("status").asString()).isEqualTo("pending_approval");
            assertThat(tool.path("source").asString()).isEqualTo("manifest");
        });
        assertThat(claims(server.manifestReads().getFirst().header("authorization")).path("use").asString()).isEqualTo("manifest");
        assertThat(callConn().path("error").asString()).as("the approved definition stays in force while the server still serves it").isEmpty();

        // The server now runs the new code: what it lists differs from what was approved, so the tool is blocked until the change is approved.
        server.describeDifferently("get_issue", "A different text, pulled by the loop.");
        await().atMost(Duration.ofSeconds(10)).untilAsserted(() ->
                assertThat(callConn().path("error").asString()).as("blocked until an administrator approves the change").isEqualTo("tool_disabled"));
    }

    private JsonNode registryTool(String name) throws Exception {
        for (JsonNode entry : json(adminCall("GET", "/admin/v1/registry/servers", null))) {
            if ("mcp-conn".equals(entry.path("serverId").asString())) {
                for (JsonNode tool : entry.path("tools")) {
                    if (name.equals(tool.path("name").asString())) {
                        return tool;
                    }
                }
            }
        }
        throw new AssertionError(name);
    }

    /** The loop looks at a server at most once in its interval; the test makes it due. */
    private void forgetTheLastLooks() {
        @SuppressWarnings("unchecked")
        Map<String, java.time.Instant> looks = (Map<String, java.time.Instant>) org.springframework.test.util.ReflectionTestUtils.getField(checks, "lastLooked");
        looks.clear();
    }
}
