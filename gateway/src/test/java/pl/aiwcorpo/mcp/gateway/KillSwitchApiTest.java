package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.system.CapturedOutput;

import pl.aiwcorpo.mcp.gateway.killswitch.KillSwitchStore;
import pl.aiwcorpo.mcp.gateway.killswitch.KillSwitches;
import pl.aiwcorpo.mcp.gateway.support.Contracts;
import pl.aiwcorpo.mcp.gateway.support.Vectors;
import tools.jackson.databind.JsonNode;

/** The emergency switch (CC-194, CC-206) through the real gateway: the operations of C5, their effect on calls, lists and the catalog. */
class KillSwitchApiTest extends GatewayTestBase {

    private static final List<String> ADMIN = List.of("mcp-platform-admin");
    private static final String ADMIN_SUB = "3b0d6f2e-91c4-4d7a-8a52-6c1e4f7a9d10";
    private static final String JIRA = "/admin/v1/registry/servers/mcp-jira";

    @Autowired
    KillSwitchStore store;

    @Autowired
    KillSwitches switches;

    @AfterEach
    void liftEverything() {
        store.all().forEach(entry -> store.delete(entry.serverId(), entry.tool()));
        switches.refresh();
    }

    private HttpResponse<String> asAdmin(String method, String path, String body) throws Exception {
        return admin(method, path, ADMIN_SUB, "a.admin", ADMIN, body);
    }

    private HttpResponse<String> putSwitch(String path, String reason) throws Exception {
        return asAdmin("PUT", path, "{\"reason\":\"" + reason + "\"}");
    }

    private JsonNode call(String token, String path, String tool, String arguments) throws Exception {
        HttpResponse<String> response = sendModern(token, path, "tools/call", tool, "{\"name\":\"" + tool + "\",\"arguments\":" + arguments + "}");
        assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
        return toolError(response);
    }

    private List<String> listed(String token, String path) throws Exception {
        List<String> names = new ArrayList<>();
        JSON.readTree(sendModern(token, path, "tools/list", null, "{}").body()).path("result").path("tools")
                .forEach(t -> names.add(t.path("name").asString()));
        return names;
    }

    private String writerToken() {
        return env.idp.token(UUID.randomUUID().toString(), "w", List.of("mcp-jira-read", "mcp-jira-write", "mcp-jira-destructive"));
    }

    private static List<JsonNode> events(CapturedOutput output, String event, String reason) {
        List<JsonNode> found = new ArrayList<>();
        for (String line : output.getOut().split("\n")) {
            if (line.startsWith("{") && line.contains("\"event\":\"" + event + "\"") && line.contains("\"reason\":\"" + reason + "\"")) {
                found.add(JSON.readTree(line));
            }
        }
        return found;
    }

    @Test
    void aSwitchedToolIsRefusedAsToolDisabledAndLeavesTheListAndTheCatalog(CapturedOutput output) throws Exception {
        String token = writerToken();
        assertThat(listed(token, "/s/mcp-jira/mcp")).contains("jira__get_issue", "jira__search_issues");

        HttpResponse<String> put = putSwitch(JIRA + "/tools/get_issue/kill-switch", "Vendor incident 9.4");
        assertThat(put.statusCode()).as(put.body()).isEqualTo(204);

        env.jira.clearRequests();
        HttpResponse<String> blocked = sendModern(token, "/mcp", "tools/call", "jira__get_issue",
                "{\"name\":\"jira__get_issue\",\"arguments\":{\"issueKey\":\"ABC-1\"}}");
        assertThat(toolError(blocked).path("error").asString()).isEqualTo("tool_disabled");
        assertThat(env.jira.requests()).noneMatch(r -> "tools/call".equals(r.rpcMethod()));
        assertThat(resolveCount()).as("nothing is asked of the broker").isZero();
        String rid = blocked.headers().firstValue("X-Request-Id").orElseThrow();
        assertThat(auditEvents(output, rid)).isNotEmpty().allSatisfy(e -> {
            assertThat(e.path("reason").asString()).isEqualTo("kill_switch");
            assertThat(e.path("errorCode").asString()).isEqualTo("tool_disabled");
            assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", e)).isEmpty();
        });
        assertThat(listed(token, "/mcp")).doesNotContain("jira__get_issue").contains("jira__search_issues");
        assertThat(call(token, "/mcp", "jira__search_issues", "{\"project\":\"ABC\"}").path("error").asString("")).isEmpty();

        JsonNode catalog = JSON.readTree(admin("GET", "/admin/v1/catalog", ALICE_SUB, "alice", ALICE_GROUPS, null).body());
        assertThat(Contracts.gatewayAdminErrors("Catalog", catalog)).isEmpty();
        for (JsonNode server : catalog.path("servers")) {
            if (!"mcp-jira".equals(server.path("serverId").asString())) {
                continue;
            }
            for (JsonNode tool : server.path("tools")) {
                boolean switched = "jira__get_issue".equals(tool.path("name").asString());
                assertThat(tool.path("disabled").asBoolean()).as(tool.path("name").asString()).isEqualTo(switched);
                assertThat(tool.path("disabledBy").asString("")).as(tool.path("name").asString()).isEqualTo(switched ? "kill_switch" : "");
            }
        }

        JsonNode all = JSON.readTree(asAdmin("GET", "/admin/v1/kill-switches", null).body());
        assertThat(Contracts.gatewayAdminErrors("KillSwitchList", all)).isEmpty();
        assertThat(all.path("switches")).hasSize(1);
        assertThat(all.path("switches").get(0).path("scope").asString()).isEqualTo("tool");
        assertThat(all.path("switches").get(0).path("tool").asString()).isEqualTo("get_issue");
        assertThat(all.path("switches").get(0).path("setBy").asString()).isEqualTo(ADMIN_SUB);
        assertThat(all.path("switches").get(0).path("reason").asString()).isEqualTo("Vendor incident 9.4");

        List<JsonNode> set = events(output, "admin_change", "kill_switch_set");
        assertThat(set).singleElement().satisfies(e -> {
            assertThat(e.path("sub").asString()).isEqualTo(ADMIN_SUB);
            assertThat(e.path("server").asString()).isEqualTo("mcp-jira");
            assertThat(e.path("tool").asString()).isEqualTo("get_issue");
            assertThat(e.path("outcome").asString()).isEqualTo("ok");
            assertThat(e.toString()).as("the text of the administrator is not in the event").doesNotContain("Vendor incident");
            assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", e)).isEmpty();
        });

        assertThat(asAdmin("DELETE", JIRA + "/tools/get_issue/kill-switch", null).statusCode()).isEqualTo(204);
        assertThat(call(token, "/mcp", "jira__get_issue", "{\"issueKey\":\"ABC-1\"}").path("error").asString("")).isEmpty();
        assertThat(listed(token, "/mcp")).contains("jira__get_issue");
        assertThat(events(output, "admin_change", "kill_switch_cleared")).hasSize(1);
        assertThat(asAdmin("DELETE", JIRA + "/tools/get_issue/kill-switch", null).statusCode()).as("idempotent").isEqualTo(204);
    }

    @Test
    void aSwitchOfAServerSwitchesEveryToolAndTheSwitchOfAToolDoesNotLiftIt() throws Exception {
        String token = writerToken();
        assertThat(putSwitch(JIRA + "/kill-switch", "Vendor incident").statusCode()).isEqualTo(204);
        assertThat(putSwitch(JIRA + "/tools/get_issue/kill-switch", "this one too").statusCode()).isEqualTo(204);
        assertThat(listed(token, "/mcp")).noneMatch(n -> n.startsWith("jira__"));
        assertThat(call(token, "/mcp", "jira__search_issues", "{\"project\":\"ABC\"}").path("error").asString()).isEqualTo("tool_disabled");

        assertThat(asAdmin("DELETE", JIRA + "/tools/get_issue/kill-switch", null).statusCode()).isEqualTo(204);
        assertThat(call(token, "/mcp", "jira__search_issues", "{\"project\":\"ABC\"}").path("error").asString()).as("the server switch stays")
                .isEqualTo("tool_disabled");
        assertThat(asAdmin("DELETE", JIRA + "/kill-switch", null).statusCode()).isEqualTo(204);
        assertThat(call(token, "/mcp", "jira__search_issues", "{\"project\":\"ABC\"}").path("error").asString("")).isEmpty();

        assertThat(putSwitch(JIRA + "/kill-switch", "first").statusCode()).isEqualTo(204);
        assertThat(putSwitch(JIRA + "/kill-switch", "second").statusCode()).as("putting again only changes the reason").isEqualTo(204);
        JsonNode all = JSON.readTree(asAdmin("GET", "/admin/v1/kill-switches", null).body());
        assertThat(all.path("switches")).hasSize(1);
        assertThat(all.path("switches").get(0).path("reason").asString()).isEqualTo("second");
        assertThat(all.path("switches").get(0).has("tool")).isFalse();
    }

    @Test
    void aUserWhoMayNotCallTheToolOrWhoseFilterCutsItLearnsNothingFromTheSwitch(CapturedOutput output) throws Exception {
        assertThat(putSwitch(JIRA + "/tools/get_issue/kill-switch", "incident").statusCode()).isEqualTo(204);

        HttpResponse<String> noGrant = sendModern(env.idp.token(UUID.randomUUID().toString(), "n", List.of("mcp-gitlab-read")),
                "/mcp", "tools/call", "jira__get_issue", "{\"name\":\"jira__get_issue\",\"arguments\":{\"issueKey\":\"ABC-1\"}}");
        assertThat(toolError(noGrant).path("error").asString()).isEqualTo("not_found_or_denied");
        String noGrantRid = noGrant.headers().firstValue("X-Request-Id").orElseThrow();
        assertThat(auditEvents(output, noGrantRid)).isNotEmpty().allSatisfy(e -> assertThat(e.path("reason").asString()).isEqualTo("not_granted"));

        HttpResponse<String> cut = sendModern(writerToken(), "/mcp?systems=gitlab", "tools/call", "jira__get_issue",
                "{\"name\":\"jira__get_issue\",\"arguments\":{\"issueKey\":\"ABC-1\"}}");
        assertThat(toolError(cut).path("error").asString()).isEqualTo("not_found_or_denied");
        String cutRid = cut.headers().firstValue("X-Request-Id").orElseThrow();
        assertThat(auditEvents(output, cutRid)).isNotEmpty().allSatisfy(e -> assertThat(e.path("reason").asString()).isEqualTo("filter_scope"));
    }

    @Test
    void whoMayPutAndLiftASwitchAndWhatIsAValidRequest() throws Exception {
        String path = JIRA + "/tools/get_issue/kill-switch";
        assertThat(admin("PUT", path, UUID.randomUUID().toString(), "bob", List.of("mcp-jira-read"), "{\"reason\":\"x\"}").statusCode())
                .as("not an administrator").isEqualTo(403);
        assertThat(admin("DELETE", path, UUID.randomUUID().toString(), "bob", List.of("mcp-jira-read"), null).statusCode()).isEqualTo(403);
        assertThat(admin("GET", "/admin/v1/kill-switches", UUID.randomUUID().toString(), "bob", List.of("mcp-jira-read"), null).statusCode())
                .isEqualTo(403);
        assertThat(admin(env.otherComponentTls, "PUT", path, env.idp.token(ADMIN_SUB, "a.admin", ADMIN, "mcp-gateway-admin", "mcp-portal-bff"),
                "{\"reason\":\"x\"}").statusCode()).as("another component of the CA").isEqualTo(403);
        assertThat(admin(env.bffTls, "PUT", path, null, "{\"reason\":\"x\"}").statusCode()).as("no user token").isEqualTo(401);

        for (String body : List.of("{}", "{\"reason\":\"\"}", "{\"reason\":\"" + "x".repeat(201) + "\"}", "{\"reason\":\"a\",\"other\":1}",
                "{\"reason\":5}", "{\"reason\":\"line\\u0000break\"}", "{\"reason\":\"bidi\\u202Eflip\"}", "not json", "[]")) {
            assertThat(asAdmin("PUT", path, body).statusCode()).as(body).isEqualTo(400);
        }
        assertThat(putSwitch(path, "x".repeat(200)).statusCode()).as("200 characters is the longest").isEqualTo(204);
        assertThat(asAdmin("PUT", "/admin/v1/registry/servers/mcp-nosuch/kill-switch", "{\"reason\":\"x\"}").statusCode()).isEqualTo(404);
        assertThat(asAdmin("DELETE", "/admin/v1/registry/servers/mcp-nosuch/kill-switch", null).statusCode()).isEqualTo(404);
        assertThat(putSwitch(JIRA + "/tools/not_a_tool/kill-switch", "x").statusCode()).as("the registry does not know the tool").isEqualTo(404);
        assertThat(asAdmin("DELETE", JIRA + "/tools/removed_long_ago/kill-switch", null).statusCode())
                .as("the switch of a tool that left the manifest can be lifted").isEqualTo(204);
    }

    @Test
    void aSwitchSurvivesTheRegistrationOfAManifest() throws Exception {
        env.gitlab.describeAsApproved();
        String manifest = JSON.writeValueAsString(env.gitlab.manifest());
        await().atMost(Duration.ofSeconds(10)).until(() -> admin(env.ciGitlabTls, "PUT", "/admin/v1/registry/servers/mcp-gitlab", null, manifest)
                .statusCode() == 200);
        String path = "/admin/v1/registry/servers/mcp-gitlab/tools/get_issue/kill-switch";
        assertThat(putSwitch(path, "incident").statusCode()).isEqualTo(204);

        assertThat(admin(env.ciGitlabTls, "PUT", "/admin/v1/registry/servers/mcp-gitlab", null, manifest).statusCode()).isEqualTo(200);

        JsonNode all = JSON.readTree(asAdmin("GET", "/admin/v1/kill-switches", null).body());
        assertThat(all.path("switches")).hasSize(1);
        String token = env.idp.token(UUID.randomUUID().toString(), "gl", List.of("mcp-gitlab-read"));
        assertThat(listed(token, "/s/mcp-gitlab/mcp")).doesNotContain("gitlab__get_issue");
    }

    @Test
    void theVectorsThatLiftASwitchOrLeaveItAlone() {
        Set<String> events = new TreeSet<>();
        for (Vectors.Vector vector : Vectors.of("kill-switch")) {
            JsonNode input = vector.document().path("input");
            String event = input.path("event").asString();
            events.add(event);
            if (!event.startsWith("lift-")) {
                continue;
            }
            liftEverything();
            input.path("switches").forEach(s -> store.put(s.path("serverId").asString(),
                    "tool".equals(s.path("scope").asString()) ? s.path("tool").asString() : null, "admin", "from the vector"));
            String qualified = input.path("tool").asString();
            String serverId = "mcp-" + qualified.substring(0, qualified.indexOf("__"));
            store.delete(serverId, "lift-tool".equals(event) ? qualified.substring(qualified.indexOf("__") + 2) : null);
            Set<String> left = new TreeSet<>();
            store.all().forEach(e -> left.add(e.scope() + " " + e.serverId() + " " + e.tool()));
            Set<String> want = new TreeSet<>();
            vector.document().path("expected").path("switches").forEach(s -> want.add(s.path("scope").asString() + " "
                    + s.path("serverId").asString() + " " + ("tool".equals(s.path("scope").asString()) ? s.path("tool").asString() : "null")));
            assertThat(left).as(vector.name()).isEqualTo(want);
        }
        assertThat(events).contains("lift-tool", "lift-server", "approve", "register");
    }
}
