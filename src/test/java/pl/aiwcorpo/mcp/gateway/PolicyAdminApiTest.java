package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.system.CapturedOutput;

import pl.aiwcorpo.mcp.gateway.jwt.UuidV7;
import pl.aiwcorpo.mcp.gateway.policy.PolicyService;
import pl.aiwcorpo.mcp.gateway.support.Contracts;
import tools.jackson.databind.JsonNode;

/**
 * The administrator's policy data (C5 scope mapping and overrides) and what the gateway decides with it: the mapping is validated against
 * the approved resource types and written with If-Match, an override is one forbid for a target and is validated for it, the revision
 * rises with every change, entries of the mapping that are no longer valid are skipped and audited, and the allowed clients are checked
 * in code before Cedar.
 */
class PolicyAdminApiTest extends GatewayTestBase {

    private static final String MAPPING = "/admin/v1/policy/scope-mapping";
    private static final String OVERRIDES = "/admin/v1/policy/overrides/";

    @Autowired
    PolicyService policies;

    @AfterEach
    void clean() {
        jdbc.sql("UPDATE policy_state SET scope_mapping = '[]'::jsonb WHERE id = 1").update();
        jdbc.sql("DELETE FROM policy_overrides").update();
        jdbc.sql("UPDATE policy_state SET allowed_clients = 'claude-ai,claude-code' WHERE id = 1").update();
        policies.reload();
    }

    private HttpResponse<String> putMapping(String entries, String ifMatch) throws Exception {
        return adminCall("PUT", MAPPING, "{\"scopeMapping\":" + entries + "}", ifMatch == null ? Map.of() : Map.of("If-Match", ifMatch));
    }

    private HttpResponse<String> putMapping(String entries) throws Exception {
        return putMapping(entries, etag(adminCall("GET", MAPPING, null)));
    }

    private HttpResponse<String> createOverride(String id, String target, String text) throws Exception {
        String body = JSON.writeValueAsString(JSON.createObjectNode().put("target", target).put("text", text));
        return adminCall("PUT", OVERRIDES + id, body, Map.of("If-None-Match", "*"));
    }

    private static JsonNode json(HttpResponse<String> response) {
        return JSON.readTree(response.body());
    }

    // --- scope mapping -----------------------------------------------------------------------------------------

    @Test
    void theMappingIsReadAndReplacedAsAWholeWithItsETag(CapturedOutput output) throws Exception {
        HttpResponse<String> empty = adminCall("GET", MAPPING, null);
        assertThat(empty.statusCode()).isEqualTo(200);
        assertThat(json(empty).path("scopeMapping").size()).as("empty until an administrator writes one").isZero();
        long before = policies.snapshot().revision();
        String requestId = UuidV7.next();

        HttpResponse<String> put = adminCall("PUT", MAPPING, "{\"scopeMapping\":[{\"group\":\"mcp-jira-proj-DEF\",\"scopes\":[\"Jira::Project/DEF\"]},"
                + "{\"group\":\"mcp-jira-proj-ABC\",\"scopes\":[\"Jira::Project/ZZZ\",\"Jira::Project/ABC\"]}]}",
                Map.of("If-Match", etag(empty), "X-Request-Id", requestId));

        assertThat(put.statusCode()).as(put.body()).isEqualTo(200);
        assertThat(Contracts.gatewayAdminErrors("ScopeMappingDocument", json(put))).isEmpty();
        assertThat(json(put).path("scopeMapping").get(0).path("group").asString()).as("stored in order").isEqualTo("mcp-jira-proj-ABC");
        assertThat(json(put).path("scopeMapping").get(0).path("scopes").get(0).asString()).isEqualTo("Jira::Project/ABC");
        assertThat(etag(put)).isNotEqualTo(etag(empty));
        assertThat(etag(adminCall("GET", MAPPING, null))).isEqualTo(etag(put));
        assertThat(policies.snapshot().revision()).as("raised on this instance at once").isGreaterThan(before);
        assertThat(auditEvents(output, requestId).stream().map(e -> e.path("reason").asString())).containsExactly("scope_mapping_changed");

        assertThat(putMapping("[]", etag(empty)).statusCode()).as("the old ETag is stale").isEqualTo(412);
        assertThat(putMapping("[]", null).statusCode()).isEqualTo(428);
        assertThat(putMapping("[]", "nonsense").statusCode()).isEqualTo(400);
        long same = policies.snapshot().revision();
        assertThat(putMapping(json(put).path("scopeMapping").toString(), etag(put)).statusCode()).isEqualTo(200);
        assertThat(policies.snapshot().revision()).as("the same document is no change").isEqualTo(same);
    }

    @Test
    void everyScopeIsCheckedAgainstTheApprovedResourceTypes() throws Exception {
        record Case(String entries, int status, String reason) {
        }
        for (Case bad : List.of(
                new Case("[{\"group\":\"mcp-a\",\"scopes\":[\"Mystery::Place/x\"]}]", 422, "unknown_resource_type"),
                new Case("[{\"group\":\"mcp-a\",\"scopes\":[\"Jira::Issue/ABC-1\"]}]", 422, "scope_not_grantable"),
                new Case("[{\"group\":\"mcp-a\",\"scopes\":[\"Jira::Project/abc\"]}]", 422, "scope_invalid"),
                new Case("[{\"group\":\"mcp-a\",\"scopes\":[\"Jira::Project/ABC\"]},{\"group\":\"mcp-a\",\"scopes\":[]}]", 422, "group_duplicate"),
                new Case("[{\"group\":\"admins\",\"scopes\":[\"Jira::Project/ABC\"]}]", 400, null),
                new Case("[{\"group\":\"mcp-a\",\"scopes\":[\"Jira::Project/ABC\",\"Jira::Project/ABC\"]}]", 400, null),
                new Case("[{\"group\":\"mcp-a\",\"scopes\":[\"not a scope\"]}]", 400, null),
                new Case("[{\"group\":\"mcp-a\"}]", 400, null))) {
            HttpResponse<String> response = putMapping(bad.entries());
            assertThat(response.statusCode()).as(bad.entries() + " " + response.body()).isEqualTo(bad.status());
            if (bad.reason() != null) {
                assertThat(json(response).path("error").asString()).isEqualTo("scope_mapping_rejected");
                assertThat(json(response).path("reason").asString()).isEqualTo(bad.reason());
                assertThat(Contracts.gatewayAdminErrors("ScopeMappingRejected", json(response))).isEmpty();
            }
        }
        assertThat(json(adminCall("GET", MAPPING, null)).path("scopeMapping").size()).as("nothing was stored").isZero();
    }

    @Test
    void anEntryThatIsNoLongerValidIsSkippedAuditedAndTheOthersKeepWorking(CapturedOutput output) throws Exception {
        // A server that was removed (or a narrower pattern) leaves entries behind in the stored document.
        jdbc.sql("UPDATE policy_state SET scope_mapping = ?::jsonb, revision = revision + 1 WHERE id = 1")
                .param("[{\"group\":\"mcp-jira-proj-ABC\",\"scopes\":[\"Jira::Project/ABC\"]},"
                        + "{\"group\":\"mcp-gone\",\"scopes\":[\"Gone::Thing/x\",\"Jira::Project/lowercase\"]}]").update();

        policies.reload();

        assertThat(policies.snapshot().usable()).isTrue();
        assertThat(policies.snapshot().mapping().scopesOf("mcp-jira-proj-ABC")).containsExactly("Jira::Project/ABC");
        assertThat(policies.snapshot().mapping().ignored()).extracting(i -> i.scope() + ":" + i.reason())
                .containsExactlyInAnyOrder("Gone::Thing/x:undeclared_type", "Jira::Project/lowercase:invalid_scope");
        assertThat(output.getOut()).contains("\"reason\":\"scope_mapping_entry_ignored\"");

        String token = env.idp.token(UUID.randomUUID().toString(), "wanda", List.of("mcp-jira-write", "mcp-jira-proj-ABC", "mcp-gone"));
        HttpResponse<String> inScope = sendModern(token, "tools/call", "jira__add_comment",
                "{\"name\":\"jira__add_comment\",\"arguments\":{\"issueKey\":\"ABC-1\"}}");
        assertThat(toolError(inScope).path("error").asString()).as("the grant that is valid still counts: the call is not refused by scope")
                .isNotEqualTo("access_denied");
    }

    // --- overrides ---------------------------------------------------------------------------------------------

    @Test
    void anOverrideIsCreatedWithIfNoneMatchReplacedAndDeletedWithIfMatch(CapturedOutput output) throws Exception {
        String text = "forbid (principal, action == Action::\"call\", resource is Tool) when { resource.name == \"delete_issue\" };";
        long before = policies.snapshot().revision();
        String requestId = UuidV7.next();

        HttpResponse<String> created = adminCall("PUT", OVERRIDES + "override-no-delete",
                JSON.writeValueAsString(JSON.createObjectNode().put("target", "gateway").put("text", text)),
                Map.of("If-None-Match", "*", "X-Request-Id", requestId));

        assertThat(created.statusCode()).as(created.body()).isEqualTo(200);
        assertThat(Contracts.gatewayAdminErrors("Override", json(created))).isEmpty();
        assertThat(json(created).path("setBy").asString()).isEqualTo(ADMIN_SUB);
        assertThat(policies.snapshot().revision()).isGreaterThan(before);
        assertThat(etag(adminCall("GET", OVERRIDES + "override-no-delete", null))).isEqualTo(etag(created));
        assertThat(json(adminCall("GET", "/admin/v1/policy/overrides", null)).findValuesAsString("id")).contains("override-no-delete");

        assertThat(createOverride("override-no-delete", "gateway", text).statusCode()).as("it exists").isEqualTo(412);
        String replacement = JSON.writeValueAsString(JSON.createObjectNode().put("target", "all-servers")
                .put("text", "forbid (principal, action, resource) when { context.client == \"claude-ai\" };"));
        assertThat(adminCall("PUT", OVERRIDES + "override-no-delete", replacement).statusCode()).as("needs If-Match or If-None-Match").isEqualTo(428);
        assertThat(adminCall("PUT", OVERRIDES + "override-no-delete", replacement, Map.of("If-Match", "\"stale-version-0000\"")).statusCode()).isEqualTo(412);
        HttpResponse<String> replaced = adminCall("PUT", OVERRIDES + "override-no-delete", replacement, Map.of("If-Match", etag(created)));
        assertThat(replaced.statusCode()).as(replaced.body()).isEqualTo(200);
        assertThat(json(replaced).path("target").asString()).isEqualTo("all-servers");

        assertThat(adminCall("DELETE", OVERRIDES + "override-no-delete", null).statusCode()).isEqualTo(428);
        assertThat(adminCall("DELETE", OVERRIDES + "override-no-delete", null, Map.of("If-Match", etag(created))).statusCode()).isEqualTo(412);
        assertThat(adminCall("DELETE", OVERRIDES + "override-no-delete", null, Map.of("If-Match", etag(replaced), "X-Request-Id", requestId)).statusCode())
                .isEqualTo(204);
        assertThat(adminCall("GET", OVERRIDES + "override-no-delete", null).statusCode()).isEqualTo(404);
        assertThat(adminCall("DELETE", OVERRIDES + "override-no-delete", null, Map.of("If-Match", etag(replaced))).statusCode()).isEqualTo(404);
        assertThat(auditEvents(output, requestId).stream().map(e -> e.path("reason").asString())).containsExactly("override_set", "override_removed");
    }

    @Test
    void anOverrideThatIsNotAValidForbidForItsTargetIsRefusedWithItsReason() throws Exception {
        record Case(String id, String target, String text, String reason) {
        }
        String call = "action == Action::\"call\", resource is Tool";
        for (Case bad : List.of(
                new Case("override-a", "gateway", "permit (principal, " + call + ");", "not_forbid"),
                new Case("override-a", "gateway", "forbid (principal, " + call + "); forbid (principal, " + call + ");", "not_one_policy"),
                new Case("override-a", "gateway", "forbid (principal, action, resource);", "target_mismatch"),
                new Case("override-a", "gateway", "forbid (principal, action == Action::\"call\", resource);", "target_mismatch"),
                new Case("override-a", "gateway", "forbid (principal, " + call + ") when { resource.nope == 1 };", "invalid_policy"),
                new Case("override-a", "gateway", "this is not cedar", "invalid_policy"),
                new Case("override-a", "gateway", "@id(\"override-b\") forbid (principal, " + call + ");", "id_mismatch"),
                new Case("override-a", "mcp-jira", "forbid (principal, action == Action::\"call\", resource is Tool);", "target_mismatch"),
                new Case("override-a", "mcp-jira", "forbid (principal, action == Jira::Action::\"delete\", resource is Tool);", "target_mismatch"),
                new Case("override-a", "mcp-jira", "forbid (principal, action == Gitlab::Action::\"delete\", resource);", "invalid_policy"),
                new Case("override-a", "all-servers", "forbid (principal, action == Jira::Action::\"delete\", resource);", "invalid_policy"),
                new Case("override-a", "mcp-nothere", "forbid (principal, action, resource);", "target_unknown"))) {
            HttpResponse<String> response = createOverride(bad.id(), bad.target(), bad.text());
            assertThat(response.statusCode()).as(bad.target() + " " + bad.text() + " " + response.body()).isEqualTo(422);
            assertThat(json(response).path("error").asString()).isEqualTo("override_rejected");
            assertThat(json(response).path("reason").asString()).as(bad.text()).isEqualTo(bad.reason());
            assertThat(Contracts.gatewayAdminErrors("OverrideRejected", json(response))).isEmpty();
        }
        for (String id : List.of("not-an-override", "platform-call-by-group", "override-", "override-UPPER", "override-" + "x".repeat(60))) {
            HttpResponse<String> response = createOverride(id, "gateway", "forbid (principal, " + call + ");");
            assertThat(response.statusCode()).as(id).isIn(400, 404);
        }
        assertThat(createOverride("override-ok", "gateway", "forbid (principal, " + call + ");").statusCode()).isEqualTo(200);
        assertThat(adminCall("PUT", OVERRIDES + "override-ok", "{\"target\":\"gateway\"}", Map.of("If-None-Match", "*")).statusCode())
                .as("a text is required").isEqualTo(400);
        assertThat(adminCall("PUT", OVERRIDES + "override-ok2", "{\"target\":\"gateway\",\"text\":\"x\",\"extra\":1}", Map.of("If-None-Match", "*")).statusCode()).isEqualTo(400);
    }

    @Test
    void anOverrideForEachTargetIsValidatedForIt() throws Exception {
        assertThat(createOverride("override-gateway", "gateway",
                "forbid (principal, action == Action::\"call\", resource is Tool) when { resource.name == \"never_called\" };").statusCode()).isEqualTo(200);
        assertThat(createOverride("override-server", "mcp-jira", "forbid (principal, action == Jira::Action::\"delete\", resource);").statusCode())
                .isEqualTo(200);
        assertThat(createOverride("override-everywhere", "all-servers",
                "forbid (principal, action, resource) when { context.client == \"claude-ai\" };").statusCode()).isEqualTo(200);
        assertThat(json(adminCall("GET", "/admin/v1/policy/overrides", null)).findValuesAsString("id"))
                .containsExactly("override-everywhere", "override-gateway", "override-server");
    }

    @Test
    void aGatewayOverrideBlocksTheCallAndHidesTheToolUntilItIsRemoved() throws Exception {
        String token = aliceToken();
        assertThat(toolError(callGetIssue(token)).path("error").asString()).as("allowed before").isEmpty();
        HttpResponse<String> created = createOverride("override-block-get-issue", "gateway",
                "forbid (principal, action == Action::\"call\", resource is Tool) when { resource.name == \"get_issue\" };");
        assertThat(created.statusCode()).isEqualTo(200);

        JsonNode blocked = toolError(callGetIssue(token));
        assertThat(blocked.path("error").asString()).isIn("not_found_or_denied", "access_denied");
        HttpResponse<String> list = sendModern(token, "/mcp?systems=jira", "tools/list", null, "{}");
        assertThat(json(list).path("result").path("tools").findValuesAsString("name")).doesNotContain("jira__get_issue")
                .contains("jira__search_issues");

        assertThat(adminCall("DELETE", OVERRIDES + "override-block-get-issue", null, Map.of("If-Match", etag(created))).statusCode()).isEqualTo(204);
        assertThat(toolError(callGetIssue(token)).path("error").asString()).as("allowed again").isEmpty();
    }

    // --- allowed clients ---------------------------------------------------------------------------------------

    @Test
    void onlyTheConfiguredClientsMayCallAndTheyAreCheckedBeforeCedar(CapturedOutput output) throws Exception {
        for (String client : List.of("claude-code", "claude-ai")) {
            String token = env.idp.token(ALICE_SUB, "alice", ALICE_GROUPS, "mcp-gateway", client);
            assertThat(toolError(callGetIssue(token)).path("error").asString()).as(client).isEmpty();
        }
        String other = env.idp.token(ALICE_SUB, "alice", ALICE_GROUPS, "mcp-gateway", "some-other-client");

        HttpResponse<String> call = callGetIssue(other);

        assertThat(toolError(call).path("error").asString()).isEqualTo("not_found_or_denied");
        HttpResponse<String> list = sendModern(other, "/mcp?systems=jira", "tools/list", null, "{}");
        assertThat(json(list).path("result").path("tools").size()).as("nothing is listed for a client that may not call").isZero();
    }

    @Test
    void theAllowedClientsComeFromTheDatabaseAndAreServedAndEnforcedTheSameWay() throws Exception {
        jdbc.sql("UPDATE policy_state SET allowed_clients = 'claude-code', revision = revision + 1 WHERE id = 1").update();
        policies.reload();

        String ai = env.idp.token(ALICE_SUB, "alice", ALICE_GROUPS, "mcp-gateway", "claude-ai");
        assertThat(toolError(callGetIssue(ai)).path("error").asString()).as("the list of the database is the one in force").isEqualTo("not_found_or_denied");
        assertThat(toolError(callGetIssue(aliceToken())).path("error").asString()).isEmpty();
        await().atMost(java.time.Duration.ofSeconds(10)).untilAsserted(() -> {
            java.util.List<pl.aiwcorpo.mcp.testserver.TestMcpServer.RecordedRequest> pushes = env.jira.policyPushes();
            assertThat(pushes).isNotEmpty();
            assertThat(JSON.readTree(pushes.getLast().body()).path("allowedClients").toString()).as("the data the gateway pushed to the server")
                    .isEqualTo("[\"claude-code\"]");
        });
    }

    @Test
    void theRevisionIsAtLeastTheClockInMillisecondsAndNeverFalls() throws Exception {
        long before = policies.snapshot().revision();
        long start = System.currentTimeMillis();

        assertThat(putMapping("[{\"group\":\"mcp-jira-proj-ABC\",\"scopes\":[\"Jira::Project/ABC\"]}]").statusCode()).isEqualTo(200);
        long first = policies.snapshot().revision();
        assertThat(putMapping("[]").statusCode()).isEqualTo(200);
        long second = policies.snapshot().revision();

        assertThat(first).isGreaterThanOrEqualTo(start);
        assertThat(second).isGreaterThan(first);
        assertThat(first).isGreaterThan(before);
    }

    @Test
    void overrideEventsCarryTheIdTheTargetAndHashesOfTheTextNeverTheText(CapturedOutput output) throws Exception {
        String requestId = UuidV7.next();
        String text = "forbid (principal, action == Action::\"call\", resource is Tool) when { resource.name == \"never_called\" };";
        String replacement = "forbid (principal, action == Action::\"call\", resource is Tool) when { resource.name == \"never_called_either\" };";
        HttpResponse<String> created = adminCall("PUT", OVERRIDES + "override-audited", JSON.writeValueAsString(
                JSON.createObjectNode().put("target", "gateway").put("text", text)), Map.of("If-None-Match", "*", "X-Request-Id", requestId));
        HttpResponse<String> replaced = adminCall("PUT", OVERRIDES + "override-audited", JSON.writeValueAsString(
                JSON.createObjectNode().put("target", "gateway").put("text", replacement)), Map.of("If-Match", etag(created), "X-Request-Id", requestId));
        HttpResponse<String> rejected = adminCall("PUT", OVERRIDES + "override-bad", JSON.writeValueAsString(
                JSON.createObjectNode().put("target", "gateway").put("text", "permit (principal, action, resource);")),
                Map.of("If-None-Match", "*", "X-Request-Id", requestId));
        assertThat(rejected.statusCode()).isEqualTo(422);
        assertThat(adminCall("DELETE", OVERRIDES + "override-audited", null, Map.of("If-Match", etag(replaced), "X-Request-Id", requestId)).statusCode())
                .isEqualTo(204);

        List<JsonNode> events = auditEvents(output, requestId).stream().filter(e -> e.path("reason").asString().startsWith("override_")).toList();
        assertThat(events.stream().map(e -> e.path("reason").asString())).containsExactly("override_set", "override_set", "override_rejected",
                "override_removed");
        assertThat(events.get(0).path("overrideId").asString()).isEqualTo("override-audited");
        assertThat(events.get(0).path("overrideTarget").asString()).isEqualTo("gateway");
        assertThat(events.get(0).path("textSha256").asString()).isEqualTo(pl.aiwcorpo.mcp.gateway.audit.AuditEvent.sha256(text));
        assertThat(events.get(0).has("textSha256Before")).as("a create has no text before").isFalse();
        assertThat(events.get(1).path("textSha256").asString()).isEqualTo(pl.aiwcorpo.mcp.gateway.audit.AuditEvent.sha256(replacement));
        assertThat(events.get(1).path("textSha256Before").asString()).isEqualTo(pl.aiwcorpo.mcp.gateway.audit.AuditEvent.sha256(text));
        assertThat(events.get(2).path("overrideId").asString()).isEqualTo("override-bad");
        assertThat(events.get(3).path("textSha256").asString()).as("the hash of what was removed").isEqualTo(pl.aiwcorpo.mcp.gateway.audit.AuditEvent.sha256(replacement));
        for (JsonNode event : events) {
            assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", event)).as(event.toString()).isEmpty();
            assertThat(event.toString()).doesNotContain("never_called");
        }
    }
}
