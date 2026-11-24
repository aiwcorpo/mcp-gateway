package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.system.CapturedOutput;

import pl.aiwcorpo.mcp.gateway.agent.AgentClient;
import pl.aiwcorpo.mcp.gateway.agent.AgentRegistry;
import pl.aiwcorpo.mcp.gateway.agent.AgentStore;
import pl.aiwcorpo.mcp.gateway.jwt.UuidV7;
import pl.aiwcorpo.mcp.gateway.server.Risk;
import pl.aiwcorpo.mcp.gateway.support.Contracts;
import pl.aiwcorpo.mcp.gateway.support.Vectors;
import tools.jackson.databind.JsonNode;

/** The registry of agents of C5 (CC-266): the operations, who may use them, the fresh MFA, the audit events and the revision of the policy data. */
class AgentClientApiTest extends GatewayTestBase {

    private static final String OWNER_SUB = "4c7d1e90-5a2b-4e63-8f14-b2a9d0c6e358";
    private static final String SERVICE_ACCOUNT = "7d0f3c1e-2b64-4a8e-9a0b-5c1f6e2d8a47";
    private static final String AGENTS = "/admin/v1/agent-clients";

    @Autowired
    AgentStore store;

    @Autowired
    AgentRegistry registry;

    @AfterEach
    void removeTheAgents() {
        jdbc.sql("DELETE FROM agent_clients").update();
        registry.refresh();
    }

    private static String body(String clientId, String extra) {
        return "{\"clientId\":\"" + clientId + "\",\"serviceAccountSub\":\"" + SERVICE_ACCOUNT + "\",\"ownerSub\":\"" + OWNER_SUB + "\"" + extra + "}";
    }

    private HttpResponse<String> asOwner(String method, String path, String body) throws Exception {
        return admin(method, path, OWNER_SUB, "o.owner", List.of("mcp-jira-read"), body);
    }

    private HttpResponse<String> asStaleAdmin(String method, String path, String body) throws Exception {
        return admin(env.bffTls, method, path, env.idp.adminToken(ADMIN_SUB, "a.admin", List.of("mcp-platform-admin"), 4000L, List.of("pwd"), null), body);
    }

    private long revision() {
        return jdbc.sql("SELECT revision FROM policy_state WHERE id = 1").query(Long.class).single();
    }

    private HttpResponse<String> create(String clientId, String extra) throws Exception {
        return adminCall("POST", AGENTS, body(clientId, extra));
    }

    private void seed(String clientId, String owner) {
        store.insert(new AgentClient(clientId, UUID.randomUUID().toString(), owner, Risk.READ_ONLY, List.of(), false, ADMIN_SUB, Instant.now(), null, null));
        registry.refresh();
    }

    @Test
    void anAdministratorRegistersLooksUpChangesAndRemovesAnAgent(CapturedOutput output) throws Exception {
        long before = revision();
        String requestId = UuidV7.next();

        HttpResponse<String> created = adminCall("POST", AGENTS, body("agent-reports", ",\"allowedGroups\":[\"mcp-jira-read\"]"),
                Map.of("X-Request-Id", requestId));

        assertThat(created.statusCode()).as(created.body()).isEqualTo(201);
        JsonNode agent = JSON.readTree(created.body());
        assertThat(Contracts.gatewayAdminErrors("AgentClient", agent)).isEmpty();
        assertThat(agent.path("status").asString()).isEqualTo("active");
        assertThat(agent.path("maxRisk").asString()).isEqualTo("READ_ONLY");
        assertThat(agent.path("delegationAllowed").asBoolean()).isFalse();
        assertThat(agent.path("createdBy").asString()).isEqualTo(ADMIN_SUB);
        assertThat(created.headers().firstValue("Location")).contains("/admin/v1/agent-clients/agent-reports");
        assertThat(revision()).as("a new agent raises the revision of the policy data").isGreaterThan(before);
        JsonNode event = auditEvents(output, requestId).stream().filter(e -> "agent_registered".equals(e.path("reason").asString())).findFirst().orElseThrow();
        assertThat(event.path("event").asString()).isEqualTo("admin_change");
        assertThat(event.path("agentOwner").asString()).isEqualTo(OWNER_SUB);
        assertThat(event.path("sub").asString()).isEqualTo(ADMIN_SUB);
        assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", event)).isEmpty();

        assertThat(create("agent-reports", "").statusCode()).as("the same clientId").isEqualTo(409);
        HttpResponse<String> got = adminCall("GET", AGENTS + "/agent-reports", null);
        assertThat(got.statusCode()).isEqualTo(200);
        assertThat(etag(got)).isEqualTo(etag(created));

        assertThat(adminCall("PATCH", AGENTS + "/agent-reports", "{\"maxRisk\":\"UPDATE\"}").statusCode()).as("If-Match is required").isEqualTo(428);
        assertThat(adminCall("PATCH", AGENTS + "/agent-reports", "{\"maxRisk\":\"UPDATE\"}", Map.of("If-Match", "\"AAAAAAAAAAAAAAAAAAAAAA\"")).statusCode())
                .isEqualTo(412);
        HttpResponse<String> patched = adminCall("PATCH", AGENTS + "/agent-reports", "{\"maxRisk\":\"UPDATE\",\"ownerSub\":\"someone-else\"}",
                Map.of("If-Match", etag(got), "X-Request-Id", requestId));
        assertThat(patched.statusCode()).as(patched.body()).isEqualTo(200);
        assertThat(JSON.readTree(patched.body()).path("maxRisk").asString()).isEqualTo("UPDATE");
        assertThat(JSON.readTree(patched.body()).path("allowedGroups").toString()).as("what the body did not name stays").isEqualTo("[\"mcp-jira-read\"]");
        assertThat(etag(patched)).isNotEqualTo(etag(got));
        assertThat(auditEvents(output, requestId).stream().map(e -> e.path("reason").asString())).contains("agent_updated");

        long beforeRotation = revision();
        assertThat(adminCall("POST", AGENTS + "/agent-reports/key-rotated", null, Map.of("X-Request-Id", requestId)).statusCode()).isEqualTo(204);
        assertThat(JSON.readTree(adminCall("GET", AGENTS + "/agent-reports", null).body()).has("keyRotatedAt")).isTrue();
        assertThat(revision()).as("a record of a rotation is no change of the data servers hold").isEqualTo(beforeRotation);
        assertThat(adminCall("POST", AGENTS + "/agent-missing/key-rotated", null).statusCode()).isEqualTo(404);

        assertThat(adminCall("DELETE", AGENTS + "/agent-reports", null, Map.of("X-Request-Id", requestId)).statusCode()).isEqualTo(204);
        assertThat(revision()).as("removing an agent raises the revision").isGreaterThan(beforeRotation);
        assertThat(adminCall("DELETE", AGENTS + "/agent-reports", null).statusCode()).as("idempotent").isEqualTo(204);
        assertThat(adminCall("GET", AGENTS + "/agent-reports", null).statusCode()).isEqualTo(404);
        assertThat(auditEvents(output, requestId).stream().filter(e -> "agent_deleted".equals(e.path("reason").asString()))).as("one event: the second delete found nothing").hasSize(1);
    }

    @Test
    void aBodyThatIsNotAnAgentIs400AndAnAgentThatMayNotExistIs422() throws Exception {
        for (String invalid : List.of("{}", "[]", body("claude-code", ""), body("agent-reports", ",\"unknown\":1"), body("agent-reports", ",\"maxRisk\":\"HUGE\""),
                body("agent-reports", ",\"allowedGroups\":[\"jira-read\"]"), body("agent-reports", ",\"allowedGroups\":[\"mcp-a\",\"mcp-a\"]"),
                body("agent-reports", ",\"delegationAllowed\":\"yes\""),
                "{\"clientId\":\"agent-reports\",\"serviceAccountSub\":\"system:gateway\",\"ownerSub\":\"" + OWNER_SUB + "\"}",
                "{\"clientId\":\"agent-reports\",\"serviceAccountSub\":\"a\\u0000b\",\"ownerSub\":\"" + OWNER_SUB + "\"}")) {
            assertThat(adminCall("POST", AGENTS, invalid).statusCode()).as(invalid).isEqualTo(400);
        }
        HttpResponse<String> destructive = create("agent-reports", ",\"allowedGroups\":[\"mcp-jira-read\",\"mcp-jira-destructive\"]");
        assertThat(destructive.statusCode()).isEqualTo(422);
        assertThat(JSON.readTree(destructive.body()).path("error").asString()).isEqualTo("agent_rejected");
        assertThat(JSON.readTree(destructive.body()).path("reason").asString()).isEqualTo("agent_group_not_allowed");
        assertThat(Contracts.gatewayAdminErrors("AgentRejected", JSON.readTree(destructive.body()))).isEmpty();
        assertThat(JSON.readTree(create("agent-reports", ",\"maxRisk\":\"DESTRUCTIVE\"").body()).path("reason").asString()).isEqualTo("max_risk_not_allowed");
        assertThat(adminCall("GET", AGENTS + "/agent-reports", null).statusCode()).as("nothing was stored").isEqualTo(404);
    }

    @Test
    void everyOperationThatWidensWhatAnAgentCanDoNeedsAFreshMfa(CapturedOutput output) throws Exception {
        assertThat(create("agent-reports", "").statusCode()).isEqualTo(201);
        String etag = etag(adminCall("GET", AGENTS + "/agent-reports", null));
        String requestId = UuidV7.next();
        Map<String, HttpResponse<String>> refused = new java.util.LinkedHashMap<>();
        refused.put("createAgentClient", asStaleAdmin("POST", AGENTS, body("agent-other", "")));
        refused.put("updateAgentClient", admin(env.bffTls, "PATCH", AGENTS + "/agent-reports",
                env.idp.adminToken(ADMIN_SUB, "a.admin", List.of("mcp-platform-admin"), 4000L, List.of("pwd"), null), "{\"maxRisk\":\"UPDATE\"}",
                Map.of("If-Match", etag, "X-Request-Id", requestId)));
        refused.put("recordAgentClientKeyRotation", asStaleAdmin("POST", AGENTS + "/agent-reports/key-rotated", null));
        refused.put("deleteAgentClient", asStaleAdmin("DELETE", AGENTS + "/agent-reports", null));
        refused.put("deleteAgentClientKillSwitch", asStaleAdmin("DELETE", AGENTS + "/agent-reports/kill-switch", null));
        refused.forEach((operation, response) -> {
            assertThat(response.statusCode()).as(operation + " " + response.body()).isEqualTo(401);
            assertThat(JSON.readTree(response.body()).path("error").asString()).isEqualTo("step_up_required");
        });
        assertThat(adminCall("GET", AGENTS + "/agent-reports", null).statusCode()).as("nothing was changed").isEqualTo(200);
        assertThat(JSON.readTree(adminCall("GET", AGENTS + "/agent-reports", null).body()).path("maxRisk").asString()).isEqualTo("READ_ONLY");
        assertThat(asStaleAdmin("PUT", AGENTS + "/agent-reports/kill-switch", "{\"reason\":\"incident\"}").statusCode())
                .as("an incident does not wait for a second factor").isEqualTo(204);
        assertThat(auditEvents(output, requestId).stream().filter(e -> "step_up_required".equals(e.path("reason").asString()))).hasSize(1);
    }

    @Test
    void theOwnerSeesAndSuspendsOnlyTheirOwnAgentsAndAnotherPersonSeesNothing() throws Exception {
        seed("agent-mine", OWNER_SUB);
        seed("agent-theirs", "someone-else");

        assertThat(asOwner("GET", AGENTS + "/agent-mine", null).statusCode()).isEqualTo(200);
        HttpResponse<String> foreign = asOwner("GET", AGENTS + "/agent-theirs", null);
        assertThat(foreign.statusCode()).isEqualTo(404);
        assertThat(JSON.readTree(foreign.body()).path("error").asString()).isEqualTo("not_found_or_denied");
        assertThat(asOwner("GET", AGENTS + "/agent-nobody", null).body()).as("an agent that does not exist looks the same").isEqualTo(foreign.body());
        assertThat(JSON.readTree(asOwner("GET", AGENTS + "?owner=me", null).body()).findValuesAsString("clientId")).containsExactly("agent-mine");
        assertThat(asOwner("GET", AGENTS, null).statusCode()).isEqualTo(403);
        assertThat(asOwner("GET", AGENTS + "?owner=you", null).statusCode()).isEqualTo(400);
        assertThat(JSON.readTree(adminCall("GET", AGENTS, null).body()).findValuesAsString("clientId")).containsExactly("agent-mine", "agent-theirs");
        assertThat(asOwner("POST", AGENTS, body("agent-new", "")).statusCode()).isEqualTo(403);
        assertThat(asOwner("PATCH", AGENTS + "/agent-mine", "{\"maxRisk\":\"UPDATE\"}").statusCode()).isEqualTo(403);
        assertThat(asOwner("DELETE", AGENTS + "/agent-mine", null).statusCode()).isEqualTo(403);

        assertThat(asOwner("PUT", AGENTS + "/agent-theirs/kill-switch", "{\"reason\":\"x\"}").statusCode()).isEqualTo(404);
        assertThat(asOwner("PUT", AGENTS + "/agent-mine/kill-switch", "{\"reason\":\"Unexpected volume of calls\"}").statusCode()).isEqualTo(204);
        JsonNode suspended = JSON.readTree(asOwner("GET", AGENTS + "/agent-mine", null).body());
        assertThat(suspended.path("status").asString()).isEqualTo("suspended");
        assertThat(suspended.path("suspendedBy").asString()).isEqualTo(OWNER_SUB);
        assertThat(suspended.path("suspendReason").asString()).isEqualTo("Unexpected volume of calls");
        assertThat(asOwner("DELETE", AGENTS + "/agent-mine/kill-switch", null).statusCode()).as("the owner cannot lift it").isEqualTo(403);
        assertThat(asOwner("PUT", AGENTS + "/agent-mine/kill-switch", "{\"reason\":\"\"}").statusCode()).isEqualTo(400);
        assertThat(adminCall("DELETE", AGENTS + "/agent-mine/kill-switch", null).statusCode()).isEqualTo(204);
        assertThat(JSON.readTree(adminCall("GET", AGENTS + "/agent-mine", null).body()).path("status").asString()).isEqualTo("active");
        assertThat(adminCall("DELETE", AGENTS + "/agent-mine/kill-switch", null).statusCode()).as("idempotent").isEqualTo(204);
        assertThat(adminCall("DELETE", AGENTS + "/agent-nobody/kill-switch", null).statusCode()).isEqualTo(404);
    }

    @Test
    void suspendingAndResumingRaisesTheRevisionAndTheSuspensionIsListedNextToTheOtherSwitches(CapturedOutput output) throws Exception {
        seed("agent-reports", OWNER_SUB);
        assertThat(JSON.readTree(adminCall("GET", "/admin/v1/kill-switches", null).body()).has("agentSwitches")).as("absent when there is none").isFalse();
        long before = revision();
        String requestId = UuidV7.next();

        assertThat(adminCall("PUT", AGENTS + "/agent-reports/kill-switch", "{\"reason\":\"Unexpected volume of calls\"}", Map.of("X-Request-Id", requestId))
                .statusCode()).isEqualTo(204);
        long suspendedAt = revision();
        assertThat(suspendedAt).isGreaterThan(before);
        JsonNode list = JSON.readTree(adminCall("GET", "/admin/v1/kill-switches", null).body());
        assertThat(Contracts.gatewayAdminErrors("KillSwitchList", list)).isEmpty();
        assertThat(list.path("agentSwitches").get(0).path("clientId").asString()).isEqualTo("agent-reports");
        assertThat(list.path("agentSwitches").get(0).path("reason").asString()).isEqualTo("Unexpected volume of calls");
        assertThat(list.path("switches")).isEmpty();
        assertThat(adminCall("PUT", AGENTS + "/agent-reports/kill-switch", "{\"reason\":\"Another text\"}").statusCode()).isEqualTo(204);
        assertThat(revision()).as("a suspension that is on stays on").isEqualTo(suspendedAt);

        assertThat(adminCall("DELETE", AGENTS + "/agent-reports/kill-switch", null, Map.of("X-Request-Id", requestId)).statusCode()).isEqualTo(204);
        assertThat(revision()).isGreaterThan(suspendedAt);
        List<String> reasons = auditEvents(output, requestId).stream().map(e -> e.path("reason").asString()).toList();
        assertThat(reasons).contains("agent_kill_switch_set", "agent_kill_switch_cleared");
        assertThat(output.getOut()).as("the text of the suspension stays in the registry").doesNotContain("Unexpected volume of calls");
    }

    @Test
    void theVectorsOfTheRegistryOfAgents() throws Exception {
        List<Vectors.Vector> vectors = Vectors.of("agent-clients");
        assertThat(vectors).hasSize(10);
        List<String> failures = new ArrayList<>();
        for (Vectors.Vector vector : vectors) {
            removeTheAgents();
            JsonNode input = vector.document().path("input");
            JsonNode expected = vector.document().path("expected");
            HttpResponse<String> response;
            if (input.has("operation")) {
                if (input.path("existing").size() > 0 || "update".equals(input.path("operation").asString())) {
                    seed(input.path("existing").size() > 0 ? input.path("existing").get(0).asString() : "agent-reports", OWNER_SUB);
                }
                if ("create".equals(input.path("operation").asString())) {
                    response = adminCall("POST", AGENTS, JSON.writeValueAsString(input.path("body")));
                } else {
                    String etag = etag(adminCall("GET", AGENTS + "/agent-reports", null));
                    response = adminCall("PATCH", AGENTS + "/agent-reports", JSON.writeValueAsString(input.path("body")), Map.of("If-Match", etag));
                }
            } else {
                input.path("agents").forEach(a -> seed(a.path("clientId").asString(), a.path("ownerSub").asString()));
                String path = input.has("owner") ? AGENTS + "?owner=" + input.path("owner").asString() : AGENTS;
                String caller = input.path("callerSub").asString();
                response = input.path("isAdmin").asBoolean()
                        ? admin(env.bffTls, "GET", path, env.idp.token(caller, "caller", List.of("mcp-platform-admin"), "mcp-gateway-admin", "mcp-portal-bff"), null)
                        : admin("GET", path, caller, "caller", List.of(), null);
            }
            JsonNode actual = response.body().isEmpty() ? JSON.createObjectNode() : JSON.readTree(response.body());
            if (response.statusCode() != expected.path("status").asInt()
                    || (expected.has("error") && !expected.path("error").asString().equals(actual.path("error").asString()))
                    || (expected.has("reason") && !expected.path("reason").asString().equals(actual.path("reason").asString()))
                    || (expected.has("maxRisk") && !expected.path("maxRisk").asString().equals(actual.path("maxRisk").asString()))
                    || (expected.has("delegationAllowed") && expected.path("delegationAllowed").asBoolean() != actual.path("delegationAllowed").asBoolean())
                    // The vector lists the ids in the order of its input; the contract orders the list by clientId, which the other test checks.
                    || (expected.has("clientIds") && !new java.util.TreeSet<>(JSON.readTree(response.body()).findValuesAsString("clientId"))
                            .equals(new java.util.TreeSet<>(strings(expected.path("clientIds")))))) {
                failures.add(vector.name() + ": " + response.statusCode() + " " + response.body());
            }
        }
        assertThat(failures).isEmpty();
    }

    @Test
    void theVectorsOfTheSuspensionOfAnAgent() throws Exception {
        List<Vectors.Vector> vectors = Vectors.of("kill-switch").stream().filter(v -> "agent-switch".equals(v.document().path("kind").asString())).toList();
        assertThat(vectors).hasSize(5);
        List<String> failures = new ArrayList<>();
        for (Vectors.Vector vector : vectors) {
            removeTheAgents();
            JsonNode input = vector.document().path("input");
            JsonNode expected = vector.document().path("expected");
            seed("agent-reports", input.path("ownerSub").asString());
            long before = revision();
            boolean lift = "lift".equals(input.path("event").asString());
            String path = AGENTS + "/agent-reports/kill-switch";
            String sub = input.path("callerSub").asString();
            List<String> groups = input.path("isAdmin").asBoolean() ? List.of("mcp-platform-admin") : List.of();
            String token = input.path("freshMfa").asBoolean(true) ? env.idp.token(sub, "caller", groups, "mcp-gateway-admin", "mcp-portal-bff")
                    : env.idp.adminToken(sub, "caller", groups, 4000L, List.of("pwd"), null);
            if (lift) {
                adminCall("PUT", path, "{\"reason\":\"incident\"}");
                before = revision();
            }
            HttpResponse<String> response = admin(env.bffTls, lift ? "DELETE" : "PUT", path, token, lift ? null : "{\"reason\":\"incident\"}");
            JsonNode actual = response.body().isEmpty() ? JSON.createObjectNode() : JSON.readTree(response.body());
            boolean raised = revision() > before;
            if (response.statusCode() != expected.path("status").asInt()
                    || (expected.has("error") && !expected.path("error").asString().equals(actual.path("error").asString()))
                    || (expected.path("raisesPolicyDataRevision").asBoolean(false) && !raised)) {
                failures.add(vector.name() + ": " + response.statusCode() + " " + response.body());
            }
        }
        assertThat(failures).isEmpty();
    }

    @Test
    void thePurgeOfAnOwnerSuspendsTheirAgentsAndLeavesAnEventForEach(CapturedOutput output) throws Exception {
        String owner = UUID.randomUUID().toString();
        seed("agent-first", owner);
        seed("agent-second", owner);
        seed("agent-other", OWNER_SUB);
        String requestId = UuidV7.next();

        HttpResponse<String> purge = admin(env.offboardingTls, "POST", "/admin/v1/users/" + owner + "/purge", null, null, Map.of("X-Request-Id", requestId));

        assertThat(purge.statusCode()).isEqualTo(204);
        assertThat(JSON.readTree(adminCall("GET", AGENTS + "/agent-first", null).body()).path("status").asString()).isEqualTo("suspended");
        assertThat(JSON.readTree(adminCall("GET", AGENTS + "/agent-second", null).body()).path("status").asString()).isEqualTo("suspended");
        assertThat(JSON.readTree(adminCall("GET", AGENTS + "/agent-other", null).body()).path("status").asString()).isEqualTo("active");
        List<JsonNode> purged = auditEvents(output, requestId).stream().filter(e -> "agent_owner_purged".equals(e.path("reason").asString())).toList();
        assertThat(purged).hasSize(2).allSatisfy(e -> assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", e)).isEmpty());
        assertThat(admin(env.offboardingTls, "POST", "/admin/v1/users/" + owner + "/purge", null, null).statusCode()).as("repeated").isEqualTo(204);
        assertThat(adminCall("GET", AGENTS + "/agent-first", null).headers().firstValue("ETag")).isPresent();
    }

    private static List<String> strings(JsonNode array) {
        List<String> out = new ArrayList<>();
        array.forEach(n -> out.add(n.asString()));
        return out;
    }
}
