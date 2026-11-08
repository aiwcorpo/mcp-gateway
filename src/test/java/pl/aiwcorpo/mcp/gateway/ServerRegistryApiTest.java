package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.system.CapturedOutput;

import pl.aiwcorpo.mcp.gateway.jwt.UuidV7;
import pl.aiwcorpo.mcp.gateway.support.Contracts;
import pl.aiwcorpo.mcp.gateway.support.Fragments;
import pl.aiwcorpo.mcp.gateway.support.SseClient;
import pl.aiwcorpo.mcp.testserver.TestMcpServer;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * The registry of servers through the admin API (C5 /admin/v1/servers): the only list of servers, changed at runtime. A server made
 * from the template is added by its address, is approved (connection, policies, tools) and called without a restart of anything, and
 * removed again.
 */
class ServerRegistryApiTest extends GatewayTestBase {

    private static final String NOTES = "/admin/v1/servers/mcp-notes";
    private static final List<String> NOTES_USER = List.of("mcp-notes-read", "mcp-notes-write");

    private final List<TestMcpServer> started = new java.util.ArrayList<>();

    @AfterEach
    void removeWhatTheTestAdded() throws Exception {
        for (String serverId : List.of("mcp-notes", "mcp-notesb", "mcp-xnotes", "mcp-floor")) {
            adminCall("DELETE", "/admin/v1/servers/" + serverId, null);
        }
        started.forEach(TestMcpServer::close);
        jdbc.sql("UPDATE policy_state SET scope_mapping = '[]'::jsonb WHERE id = 1").update();
        policies.reload();
    }

    @org.springframework.beans.factory.annotation.Autowired
    pl.aiwcorpo.mcp.gateway.policy.PolicyService policies;

    private static String addBody(String url) {
        return "{\"internalUrl\":\"" + url + "\"}";
    }

    private TestMcpServer start(String serverId) throws Exception {
        TestMcpServer server = env.startServer(serverId);
        started.add(server);
        return server;
    }

    private TestMcpServer startNotes() throws Exception {
        return start("mcp-notes");
    }

    private String url(TestMcpServer server) {
        return "https://127.0.0.1:" + server.port() + "/mcp";
    }

    private JsonNode json(HttpResponse<String> response) {
        return JSON.readTree(response.body());
    }

    private void approveEverything(String serverId, ObjectNode manifest, String... tools) throws Exception {
        HttpResponse<String> server = adminCall("GET", "/admin/v1/servers/" + serverId, null);
        JsonNode pending = json(server).path("pendingConnection");
        assertThat(adminCall("POST", "/admin/v1/servers/" + serverId + "/connection/approve",
                "{\"tlsMode\":\"" + pending.path("tlsMode").asString() + "\",\"fingerprint\":\"" + pending.path("fingerprint").asString()
                        + "\"}").statusCode()).isEqualTo(200);
        assertThat(adminCall("POST", "/admin/v1/registry/servers/" + serverId + "/policies/approve",
                "{\"policiesHash\":\"" + manifest.path("policiesHash").asString() + "\"}").statusCode()).isEqualTo(200);
        for (String tool : tools) {
            assertThat(adminCall("POST", "/admin/v1/registry/servers/" + serverId + "/tools/" + tool + "/approve",
                    "{\"definitionHash\":\"" + pl.aiwcorpo.mcp.gateway.support.Manifests.tool(manifest, tool).path("definitionHash").asString()
                            + "\"}").statusCode()).isEqualTo(204);
        }
    }

    @Test
    void aServerIsAddedByItsAddressReadChangedAndDeletedWithItsETag(CapturedOutput output) throws Exception {
        TestMcpServer notes = startNotes();
        String requestId = UuidV7.next();
        Map<String, String> asRequest = Map.of("X-Request-Id", requestId);

        HttpResponse<String> created = adminCall("POST", "/admin/v1/servers", addBody(url(notes)), asRequest);
        assertThat(created.statusCode()).as(created.body()).isEqualTo(201);
        assertThat(created.headers().firstValue("Location")).contains(NOTES);
        JsonNode body = json(created);
        assertThat(body.path("serverId").asString()).as("derived from the manifest: mcp-<system>").isEqualTo("mcp-notes");
        assertThat(body.path("system").asString()).isEqualTo("notes");
        assertThat(body.path("enabled").asBoolean()).isTrue();
        assertThat(body.path("adapter").asBoolean()).isFalse();
        assertThat(body.path("allowPlainHttp").asBoolean()).isFalse();
        assertThat(body.path("status").asString()).isEqualTo("pending_approval");
        assertThat(body.path("connection").isNull()).isTrue();
        assertThat(body.path("pendingConnection").path("tlsMode").asString()).as("the certificate of the internal CA names the host").isEqualTo("ca");
        assertThat(body.path("pendingConnection").path("reason").asString()).isEqualTo("first_connection");
        assertThat(body.path("pendingConnection").path("validatesAsCa").asBoolean()).isTrue();
        assertThat(body.path("pendingConnection").path("fingerprint").asString()).isEqualTo(env.fingerprint(notes));
        assertThat(body.path("credential").path("acceptedTypes").toString()).as("derived from the manifest").isEqualTo("[\"user-secret\"]");
        assertThat(Contracts.gatewayAdminErrors("ServerConfig", body)).isEmpty();

        HttpResponse<String> read = adminCall("GET", NOTES, null);
        assertThat(read.statusCode()).isEqualTo(200);
        assertThat(etag(read)).isEqualTo(etag(created));
        HttpResponse<String> list = adminCall("GET", "/admin/v1/servers", null);
        assertThat(json(list).findValuesAsString("serverId")).contains("mcp-notes", "mcp-jira", "mcp-gitlab");

        String disable = "{\"enabled\":false}";
        assertThat(adminCall("PATCH", NOTES, disable).statusCode()).as("If-Match is required").isEqualTo(428);
        assertThat(adminCall("PATCH", NOTES, disable, Map.of("If-Match", "\"stale-version-0000\"")).statusCode()).isEqualTo(412);
        assertThat(adminCall("PATCH", NOTES, disable, Map.of("If-Match", "not an etag")).statusCode()).isEqualTo(400);
        HttpResponse<String> updated = adminCall("PATCH", NOTES, disable, Map.of("If-Match", etag(created), "X-Request-Id", requestId));
        assertThat(updated.statusCode()).as(updated.body()).isEqualTo(200);
        assertThat(json(updated).path("enabled").asBoolean()).isFalse();
        assertThat(etag(updated)).as("the document changed, so did its ETag").isNotEqualTo(etag(created));
        assertThat(adminCall("PATCH", NOTES, "{\"enabled\":true}", Map.of("If-Match", etag(created))).statusCode())
                .as("the old ETag is stale now").isEqualTo(412);
        for (String field : List.of("{\"serverId\":\"mcp-other\"}", "{\"adapter\":true}", "{\"internalUrl\":\"https://127.0.0.1:9/mcp\"}",
                "{\"allowPlainHttp\":true}", "{\"tlsName\":\"mcp-notes.internal\"}")) {
            assertThat(adminCall("PATCH", NOTES, field, Map.of("If-Match", etag(updated))).statusCode()).as(field).isEqualTo(400);
        }

        assertThat(adminCall("DELETE", NOTES, null, asRequest).statusCode()).isEqualTo(204);
        assertThat(adminCall("GET", NOTES, null).statusCode()).isEqualTo(404);
        assertThat(adminCall("DELETE", NOTES, null).statusCode()).isEqualTo(404);

        List<JsonNode> ofTheServer = auditEvents(output, requestId).stream().filter(e -> "admin_change".equals(e.path("event").asString())).toList();
        List<String> reasons = ofTheServer.stream().map(e -> e.path("reason").asString()).toList();
        assertThat(reasons).contains("server_created", "server_updated", "server_deleted");
        assertThat(reasons).as("what the first pull brought is pending, READ_ONLY tools included").contains("definition_submitted", "policies_submitted");
        assertThat(reasons).doesNotContain("definition_registered");
        JsonNode update = ofTheServer.stream().filter(e -> "server_updated".equals(e.path("reason").asString())).findFirst().orElseThrow();
        assertThat(update.path("changedFields").toString()).as("names, never values").isEqualTo("[\"enabled\"]");
        assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", update)).isEmpty();
        assertThat(ofTheServer).allSatisfy(event -> assertThat(event.path("server").asString()).isEqualTo("mcp-notes"));
        assertThat(ofTheServer.stream().filter(e -> List.of("server_created", "server_updated", "server_deleted").contains(e.path("reason").asString())))
                .allSatisfy(event -> assertThat(event.path("sub").asString()).isEqualTo(ADMIN_SUB));
    }

    @Test
    void anAddressIsRefusedForAReasonBeforeAnythingIsStored() throws Exception {
        for (String system : List.of("gateway", "offboarding", "portal", "broker", "prometheus", "platform", "admin", "registry", "adapter",
                "internal", "ci")) {
            TestMcpServer reserved = start("mcp-" + system);
            HttpResponse<String> response = adminCall("POST", "/admin/v1/servers", addBody(url(reserved)));
            assertThat(response.statusCode()).as(system).isEqualTo(422);
            assertThat(json(response).path("error").asString()).isEqualTo("server_rejected");
            assertThat(json(response).path("reason").asString()).as(system).isEqualTo("system_reserved");
        }
        TestMcpServer notes = startNotes();
        String mixed = "{\"internalUrl\":\"" + url(notes) + "\",\"credential\":"
                + "{\"required\":true,\"acceptedTypes\":[\"service-account\",\"user-secret\"],\"type\":\"service-account\"}}";
        assertThat(json(adminCall("POST", "/admin/v1/servers", mixed)).path("reason").asString()).isEqualTo("credential_types_mixed");
        String notAccepted = "{\"internalUrl\":\"" + url(notes) + "\",\"credential\":"
                + "{\"required\":true,\"acceptedTypes\":[\"user-secret\"],\"type\":\"user-oauth\"}}";
        assertThat(json(adminCall("POST", "/admin/v1/servers", notAccepted)).path("reason").asString()).isEqualTo("credential_type_not_accepted");
        String otherTypes = "{\"internalUrl\":\"" + url(notes) + "\",\"credential\":"
                + "{\"required\":true,\"acceptedTypes\":[\"user-oauth\"],\"type\":\"user-oauth\"}}";
        HttpResponse<String> mismatch = adminCall("POST", "/admin/v1/servers", otherTypes);
        assertThat(mismatch.statusCode()).as("the manifest accepts user-secret only").isEqualTo(422);
        assertThat(json(mismatch).path("reason").asString()).isEqualTo("manifest_invalid");
        assertThat(json(mismatch).path("manifestReason").asString()).isEqualTo("credential_type_mismatch");
        assertThat(Contracts.gatewayAdminErrors("ServerRejected", json(mismatch))).isEmpty();

        assertThat(json(adminCall("POST", "/admin/v1/servers", addBody("http://127.0.0.1:" + notes.port() + "/mcp"))).path("reason").asString())
                .as("http needs the flag").isEqualTo("plain_http_not_allowed");
        String closed = "https://127.0.0.1:" + GatewayProcessPorts.unused() + "/mcp";
        assertThat(json(adminCall("POST", "/admin/v1/servers", addBody(closed))).path("reason").asString())
                .as("nothing listens there").isEqualTo("tls_handshake_failed");
        notes.manifestStatus(404);
        assertThat(json(adminCall("POST", "/admin/v1/servers", addBody(url(notes)))).path("reason").asString())
                .isEqualTo("manifest_unreachable");
        notes.manifestStatus(200);
        ObjectNode broken = notes.manifest();
        pl.aiwcorpo.mcp.gateway.support.Manifests.tool(broken, "get_issue").put("definitionHash", "sha256:" + "0".repeat(64));
        notes.serveManifest(broken);
        HttpResponse<String> invalid = adminCall("POST", "/admin/v1/servers", addBody(url(notes)));
        assertThat(json(invalid).path("reason").asString()).isEqualTo("manifest_invalid");
        notes.serveManifest(null);

        for (String bad : List.of("{}", "[]", "not json", "{\"internalUrl\":1}", "{\"internalUrl\":\"https://u:p@127.0.0.1:9/mcp\"}",
                "{\"internalUrl\":\"https://127.0.0.1:9/mcp#x\"}", "{\"internalUrl\":\"ftp://127.0.0.1/mcp\"}", "{\"internalUrl\":\"https:///mcp\"}",
                "{\"internalUrl\":\"https://" + "a".repeat(260) + "/mcp\"}", "{\"internalUrl\":\"https://127.0.0.1:99999/mcp\"}",
                "{\"internalUrl\":\"https://127.0.0.1:9/mcp\",\"serverId\":\"mcp-notes\"}",
                "{\"internalUrl\":\"https://127.0.0.1:9/mcp\",\"allowPlainHttp\":\"yes\"}",
                "{\"internalUrl\":\"https://127.0.0.1:9/mcp\",\"credential\":{\"required\":true,\"acceptedTypes\":[],\"type\":\"user-secret\"}}")) {
            assertThat(adminCall("POST", "/admin/v1/servers", bad).statusCode()).as(bad).isEqualTo(400);
        }
        assertThat(adminCall("GET", NOTES, null).statusCode()).as("nothing was stored").isEqualTo(404);
    }

    @Test
    void aServerThatExistsIsAConflictAndOnlyAnAdministratorChangesTheRegistry() throws Exception {
        TestMcpServer notes = startNotes();
        assertThat(adminCall("POST", "/admin/v1/servers", addBody(url(notes))).statusCode()).isEqualTo(201);
        HttpResponse<String> again = adminCall("POST", "/admin/v1/servers", addBody(url(notes)));
        assertThat(again.statusCode()).isEqualTo(409);
        assertThat(json(again).path("error").asString()).isEqualTo("server_exists");

        String user = env.idp.token(BOB_SUB, "bob", List.of("mcp-jira-read"), "mcp-gateway-admin", "mcp-portal-bff");
        for (String[] call : new String[][] {{"GET", "/admin/v1/servers"}, {"POST", "/admin/v1/servers"}, {"GET", NOTES}, {"DELETE", NOTES},
                {"POST", NOTES + "/refresh"}, {"POST", NOTES + "/connection/approve"}}) {
            HttpResponse<String> refused = admin(env.bffTls, call[0], call[1], user, call[0].equals("POST") ? "{}" : null);
            assertThat(refused.statusCode()).as(call[0] + " " + call[1]).isEqualTo(403);
        }
        assertThat(admin(env.otherComponentTls, "GET", "/admin/v1/servers", user, null).statusCode()).as("another certificate").isEqualTo(403);
        assertThat(admin(env.bffTls, "GET", "/admin/v1/servers", null, null).statusCode()).as("no token").isEqualTo(401);
    }

    @Test
    void aServerAddedAtRuntimeServesItsToolsOnlyOnceEverythingIsApprovedAndLeavesNothingWhenRemoved(CapturedOutput output) throws Exception {
        TestMcpServer notes = startNotes();
        String sub = UUID.randomUUID().toString();
        String token = env.idp.token(sub, "nora", NOTES_USER);
        assertThat(listedTools(token)).as("no such server yet").noneMatch(name -> name.startsWith("notes__"));
        SseClient stream = listen(token);
        assertThat(stream.nextMessage(Duration.ofSeconds(2)).path("method").asString()).isEqualTo("notifications/subscriptions/acknowledged");
        assertThat(stream.nextMessage(Duration.ofSeconds(1))).as("nothing changed yet").isNull();

        HttpResponse<String> added = adminCall("POST", "/admin/v1/servers", addBody(url(notes)));
        assertThat(added.statusCode()).isEqualTo(201);
        ObjectNode manifest = notes.manifest();
        JsonNode entry = registryEntryOf("mcp-notes");
        assertThat(entry.path("policiesStatus").asString()).isEqualTo("pending_approval");
        for (JsonNode tool : entry.path("tools")) {
            assertThat(tool.path("status").asString()).as(tool.path("name").asString() + ": a pulled READ_ONLY tool is not approved").isEqualTo("pending_approval");
            assertThat(tool.path("source").asString()).isEqualTo("manifest");
        }
        assertThat(listedTools(token)).as("nothing is listed until the connection, the policies and the tool are approved")
                .noneMatch(name -> name.startsWith("notes__"));
        assertThat(toolError(callNotes(token, "{\"issueKey\":\"ABC-1\"}")).path("error").asString()).isEqualTo("tool_disabled");

        JsonNode pending = json(added).path("pendingConnection");
        assertThat(adminCall("POST", NOTES + "/connection/approve", "{\"tlsMode\":\"ca\",\"fingerprint\":\"" + pending.path("fingerprint").asString() + "\"}")
                .statusCode()).isEqualTo(200);
        assertThat(asAdminWithBody("POST", "/admin/v1/registry/servers/mcp-notes/policies/approve",
                "{\"policiesHash\":\"" + manifest.path("policiesHash").asString() + "\"}").statusCode()).isEqualTo(200);
        assertThat(listedTools(token)).as("the tools themselves still wait").noneMatch(name -> name.startsWith("notes__"));
        for (String tool : List.of("get_issue", "search_issues")) {
            assertThat(adminCall("POST", "/admin/v1/registry/servers/mcp-notes/tools/" + tool + "/approve", "{\"definitionHash\":\""
                    + pl.aiwcorpo.mcp.gateway.support.Manifests.tool(manifest, tool).path("definitionHash").asString() + "\"}").statusCode())
                    .isEqualTo(204);
        }

        assertThat(stream.nextMessage(Duration.ofSeconds(6))).as("the list of the client changed: no restart, no reconnect").isNotNull();
        assertThat(listedTools(token)).contains("notes__get_issue", "notes__search_issues").doesNotContain("notes__delete_issue");
        HttpResponse<String> result = callNotes(token, "{\"issueKey\":\"ABC-1\"}");
        assertThat(JSON.readTree(result.body()).path("result").path("isError").asBoolean(false)).as(result.body()).isFalse();
        assertThat(notes.requests().stream().filter(r -> "tools/call".equals(r.rpcMethod()) && r.status() == 200)).hasSize(1);

        JsonNode approved = registryEntryOf("mcp-notes");
        assertThat(approved.path("policiesStatus").asString()).isEqualTo("approved");
        assertThat(approved.path("policiesHash").asString()).isEqualTo(manifest.path("policiesHash").asString());

        String requestId = UuidV7.next();
        assertThat(adminCall("DELETE", NOTES, null, Map.of("X-Request-Id", requestId)).statusCode()).isEqualTo(204);

        assertThat(stream.nextMessage(Duration.ofSeconds(6))).as("listChanged to the clients that held the tools").isNotNull();
        assertThat(listedTools(token)).noneMatch(name -> name.startsWith("notes__"));
        assertThat(toolError(callNotes(token, "{\"issueKey\":\"ABC-1\"}")).path("error").asString()).isEqualTo("not_found_or_denied");
        assertThat(jdbc.sql("SELECT count(*) FROM registry_tools WHERE server_id = 'mcp-notes'").query(Long.class).single()).isZero();
        assertThat(jdbc.sql("SELECT count(*) FROM registry_policies WHERE server_id = 'mcp-notes'").query(Long.class).single()).isZero();
        assertThat(auditEvents(output, requestId).stream().map(e -> e.path("reason").asString())).contains("server_deleted")
                .as("one event for each thing the removal took").contains("tool_removed", "policies_removed", "namespace_released");
        assertThat(auditEvents(output, requestId)).allSatisfy(e -> assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", e)).isEmpty());
        stream.close();
    }

    @Test
    void deletingAServerRemovesItsMappingEntriesAndFreesItsNamespace(CapturedOutput output) throws Exception {
        TestMcpServer notes = startNotes();
        assertThat(adminCall("POST", "/admin/v1/servers", addBody(url(notes))).statusCode()).isEqualTo(201);
        ObjectNode manifest = notes.manifest();
        assertThat(asAdminWithBody("POST", "/admin/v1/registry/servers/mcp-notes/policies/approve",
                "{\"policiesHash\":\"" + manifest.path("policiesHash").asString() + "\"}").statusCode()).isEqualTo(200);
        String mapping = "{\"scopeMapping\":[{\"group\":\"mcp-notes-proj-ABC\",\"scopes\":[\"Notes::Project/ABC\"]},"
                + "{\"group\":\"mcp-team\",\"scopes\":[\"Jira::Project/ABC\",\"Notes::Project/XYZ\"]}]}";
        HttpResponse<String> put = adminCall("PUT", "/admin/v1/policy/scope-mapping", mapping, Map.of("If-Match", etag(adminCall("GET",
                "/admin/v1/policy/scope-mapping", null))));
        assertThat(put.statusCode()).as(put.body()).isEqualTo(200);

        // A second server cannot take the namespace of the first one, whatever its manifest says.
        TestMcpServer thief = start("mcp-xnotes");
        thief.serveManifest(xnotesManifest());
        HttpResponse<String> refused = adminCall("POST", "/admin/v1/servers", addBody(url(thief)));
        assertThat(refused.statusCode()).as(refused.body()).isEqualTo(422);
        assertThat(json(refused).path("reason").asString()).as(refused.body()).isEqualTo("namespace_conflict");
        assertThat(adminCall("GET", "/admin/v1/servers/mcp-xnotes", null).statusCode()).as("nothing was stored").isEqualTo(404);

        String requestId = UuidV7.next();
        assertThat(adminCall("DELETE", NOTES, null, Map.of("X-Request-Id", requestId)).statusCode()).isEqualTo(204);

        JsonNode after = json(adminCall("GET", "/admin/v1/policy/scope-mapping", null));
        assertThat(after.path("scopeMapping").toString()).contains("Jira::Project/ABC").doesNotContain("Notes::");
        assertThat(after.path("scopeMapping").size()).as("the group that had only Notes scopes is gone").isEqualTo(1);
        List<JsonNode> removed = auditEvents(output, requestId).stream()
                .filter(e -> "scope_mapping_entry_removed".equals(e.path("reason").asString())).toList();
        assertThat(removed.stream().map(e -> e.path("resource").path("type").asString() + "/" + e.path("resource").path("id").asString()))
                .containsExactlyInAnyOrder("Notes::Project/ABC", "Notes::Project/XYZ");
        assertThat(adminCall("POST", "/admin/v1/servers", addBody(url(thief))).statusCode()).as("the namespace is free again").isEqualTo(201);
    }

    @Test
    void theRiskFloorsOutliveTheServerAndLeftoverRowsAreNotTakenByTheServerThatComesNext() throws Exception {
        TestMcpServer floor = start("mcp-floor");
        ObjectNode destructive = pl.aiwcorpo.mcp.gateway.support.Manifests.manifest("mcp-floor", "floor", "1.0.0", List.of("user-secret"),
                pl.aiwcorpo.mcp.gateway.support.Manifests.Tool.destructive("wipe"));
        floor.serveManifest(destructive);
        assertThat(adminCall("POST", "/admin/v1/servers", addBody(url(floor))).statusCode()).isEqualTo(201);
        assertThat(adminCall("DELETE", "/admin/v1/servers/mcp-floor", null).statusCode()).isEqualTo(204);
        assertThat(jdbc.sql("SELECT risk FROM registry_risk_floor WHERE server_id = 'mcp-floor' AND tool = 'wipe'").query(Long.class).single())
                .as("the floor stays when the server is deleted").isEqualTo(2L);

        // A row that a race left behind is not what the new server starts with.
        jdbc.sql("INSERT INTO registry_policies (server_id, pending_hash, pending_policies, pending_resource_types, pending_version, pending_source) "
                + "VALUES ('mcp-floor', 'sha256:" + "a".repeat(64) + "', '{}'::jsonb, '[]'::jsonb, '1.0.0', 'manifest')").update();
        ObjectNode lowered = pl.aiwcorpo.mcp.gateway.support.Manifests.manifest("mcp-floor", "floor", "1.1.0", List.of("user-secret"),
                pl.aiwcorpo.mcp.gateway.support.Manifests.Tool.readOnly("wipe"));
        floor.serveManifest(lowered);
        assertThat(adminCall("POST", "/admin/v1/servers", addBody(url(floor))).statusCode()).isEqualTo(201);
        assertThat(jdbc.sql("SELECT pending_hash FROM registry_policies WHERE server_id = 'mcp-floor'").query(String.class).single())
                .as("the leftover row was purged, the policies are those of the pulled manifest").isEqualTo(lowered.path("policiesHash").asString());
        JsonNode entry = registryEntryOf("mcp-floor");
        assertThat(entry.path("tools").get(0).path("status").asString()).as("not approved as READ_ONLY without an administrator").isEqualTo("pending_approval");
        assertThat(entry.path("tools").get(0).path("riskLowered").asBoolean()).isTrue();

        // Nothing is adopted: the serverId comes from a manifest that anyone at the address can write, so an approval that an old row
        // carries must not pass to whoever claims the id.
        adminCall("DELETE", "/admin/v1/servers/mcp-floor", null);
        jdbc.sql("DELETE FROM registry_risk_floor WHERE server_id = 'mcp-floor'").update();
        jdbc.sql("INSERT INTO registry_policies (server_id, approved_hash, approved_policies, approved_resource_types, approved_version) "
                + "VALUES ('mcp-floor', 'sha256:" + "b".repeat(64) + "', '{}'::jsonb, '[]'::jsonb, '1.0.0')").update();
        assertThat(adminCall("POST", "/admin/v1/servers", addBody(url(floor))).statusCode()).isEqualTo(201);
        assertThat(jdbc.sql("SELECT approved_hash FROM registry_policies WHERE server_id = 'mcp-floor'").query(String.class).optional())
                .as("the approved policies of a row that was there are gone").isEmpty();
        assertThat(jdbc.sql("SELECT pending_hash FROM registry_policies WHERE server_id = 'mcp-floor'").query(String.class).single())
                .isEqualTo(lowered.path("policiesHash").asString());
        adminCall("DELETE", "/admin/v1/servers/mcp-floor", null);
        jdbc.sql("DELETE FROM registry_risk_floor WHERE server_id = 'mcp-floor'").update();
        jdbc.sql("DELETE FROM registry_policies WHERE server_id = 'mcp-floor'").update();
    }

    @Test
    void theLegacyTableIsGone() {
        assertThat(jdbc.sql("SELECT count(*) FROM information_schema.tables WHERE table_name = 'registry_legacy'").query(Long.class).single())
                .as("migration V15 drops it, nothing is adopted any more").isZero();
    }

    @Test
    void aManifestThatClaimsAnotherSystemThanTheAdministratorExpectedIsRefusedAndNothingIsStored(CapturedOutput output) throws Exception {
        TestMcpServer notes = startNotes();
        String requestId = UuidV7.next();

        HttpResponse<String> refused = adminCall("POST", "/admin/v1/servers",
                "{\"internalUrl\":\"" + url(notes) + "\",\"expectedSystem\":\"jira\"}", Map.of("X-Request-Id", requestId));

        assertThat(refused.statusCode()).as(refused.body()).isEqualTo(422);
        assertThat(json(refused).path("error").asString()).isEqualTo("server_rejected");
        assertThat(json(refused).path("reason").asString()).isEqualTo("system_mismatch");
        assertThat(Contracts.gatewayAdminErrors("ServerRejected", json(refused))).isEmpty();
        assertThat(adminCall("GET", NOTES, null).statusCode()).as("nothing was stored").isEqualTo(404);
        assertThat(auditEvents(output, requestId)).anySatisfy(event -> {
            assertThat(event.path("reason").asString()).isEqualTo("system_mismatch");
            assertThat(event.path("outcome").asString()).isEqualTo("denied");
        });

        for (String bad : List.of("\"Notes\"", "5", "\"gateway\"", "\"\"", "null")) {
            assertThat(adminCall("POST", "/admin/v1/servers", "{\"internalUrl\":\"" + url(notes) + "\",\"expectedSystem\":" + bad + "}").statusCode())
                    .as(bad).isEqualTo(400);
        }
        HttpResponse<String> accepted = adminCall("POST", "/admin/v1/servers",
                "{\"internalUrl\":\"" + url(notes) + "\",\"expectedSystem\":\"notes\"}");
        assertThat(accepted.statusCode()).as(accepted.body()).isEqualTo(201);
    }

    @Test
    void aManifestInvalidRefusalNamesTheServerInTheAuditOnlyWhenTheSystemHasTheShapeOfOne(CapturedOutput output) throws Exception {
        TestMcpServer notes = startNotes();
        ObjectNode broken = notes.manifest();
        pl.aiwcorpo.mcp.gateway.support.Manifests.tool(broken, "get_issue").put("definitionHash", "sha256:" + "0".repeat(64));
        notes.serveManifest(broken);
        String shaped = UuidV7.next();
        assertThat(json(adminCall("POST", "/admin/v1/servers", addBody(url(notes)), Map.of("X-Request-Id", shaped))).path("reason").asString())
                .isEqualTo("manifest_invalid");
        assertThat(auditEvents(output, shaped)).anySatisfy(event -> {
            assertThat(event.path("reason").asString()).isEqualTo("manifest_invalid");
            assertThat(event.path("server").asString()).isEqualTo("mcp-notes");
        });

        String hostile = "NOT A SYSTEM " + "x".repeat(5000);
        ObjectNode other = notes.manifest();
        other.put("system", hostile);
        notes.serveManifest(other);
        String unshaped = UuidV7.next();
        HttpResponse<String> response = adminCall("POST", "/admin/v1/servers", addBody(url(notes)), Map.of("X-Request-Id", unshaped));

        assertThat(response.statusCode()).isEqualTo(422);
        List<JsonNode> events = auditEvents(output, unshaped);
        assertThat(events).anySatisfy(event -> assertThat(event.path("reason").asString()).isEqualTo("manifest_invalid"));
        assertThat(events).allSatisfy(event -> {
            assertThat(event.has("server")).as("no unvalidated text in the server field").isFalse();
            assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", event)).isEmpty();
        });
    }

    // --- helpers -----------------------------------------------------------------------------------------------

    private JsonNode registryEntryOf(String serverId) throws Exception {
        for (JsonNode server : json(adminCall("GET", "/admin/v1/registry/servers", null))) {
            if (serverId.equals(server.path("serverId").asString())) {
                return server;
            }
        }
        throw new AssertionError(serverId + " is not in the registry");
    }

    private ObjectNode xnotesManifest() {
        ObjectNode manifest = pl.aiwcorpo.mcp.gateway.support.Manifests.manifest("mcp-xnotes", "xnotes", "1.0.0", List.of("user-secret"),
                pl.aiwcorpo.mcp.gateway.support.Manifests.Tool.readOnly("get_note"));
        manifest.set("resourceTypes", Fragments.resourceTypes("notes"));
        manifest.set("policies", Fragments.policies("notes"));
        manifest.put("policiesHash", Fragments.hash((ObjectNode) manifest.get("policies"), (tools.jackson.databind.node.ArrayNode) manifest.get("resourceTypes")));
        return manifest;
    }

    private HttpResponse<String> asAdminWithBody(String method, String path, String body) throws Exception {
        return adminCall(method, path, body);
    }

    private List<String> listedTools(String token) throws Exception {
        HttpResponse<String> response = sendModern(token, "/mcp", "tools/list", null, "{}");
        assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
        return JSON.readTree(response.body()).path("result").path("tools").findValuesAsString("name");
    }

    private HttpResponse<String> callNotes(String token, String arguments) throws Exception {
        return sendModern(token, "/mcp", "tools/call", "notes__get_issue",
                "{\"name\":\"notes__get_issue\",\"arguments\":" + arguments + "}");
    }

    private SseClient listen(String token) throws Exception {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"subscriptions/listen\",\"params\":{\"_meta\":{"
                + "\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{}},"
                + "\"notifications\":{\"toolsListChanged\":true}}}";
        SseClient client = SseClient.post(http, "http://localhost:" + port + "/mcp", body, Map.of("Authorization", "Bearer " + token,
                "MCP-Protocol-Version", "2026-07-28", "Mcp-Method", "subscriptions/listen"));
        await().atMost(Duration.ofSeconds(3)).until(() -> client.status() == 200);
        return client;
    }

    /** A port nothing listens on. */
    private static final class GatewayProcessPorts {
        static int unused() throws java.io.IOException {
            return pl.aiwcorpo.mcp.gateway.support.GatewayProcess.freePort();
        }
    }
}
