package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.http.HttpResponse;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.system.CapturedOutput;

import pl.aiwcorpo.mcp.gateway.killswitch.KillSwitchStore;
import pl.aiwcorpo.mcp.gateway.killswitch.KillSwitches;
import pl.aiwcorpo.mcp.gateway.registry.PrimitiveKind;
import pl.aiwcorpo.mcp.gateway.registry.RegisteredEntry;
import pl.aiwcorpo.mcp.gateway.registry.RegistryService;
import pl.aiwcorpo.mcp.gateway.registry.RegistryStore;
import pl.aiwcorpo.mcp.gateway.support.Contracts;
import pl.aiwcorpo.mcp.gateway.support.Manifests;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * Approval and emergency switches of resources, resource templates and prompts (CC-265) through the real admin port. The entries are
 * written to the registry of mcp-jira directly: what a pull makes of a manifest is the business of RegistryEntriesTest.
 */
class PrimitiveAdminApiTest extends GatewayTestBase {

    private static final List<String> ADMIN = List.of("mcp-platform-admin");
    private static final String JIRA = "/admin/v1/registry/servers/mcp-jira";

    @Autowired
    RegistryStore store;

    @Autowired
    RegistryService registry;

    @Autowired
    KillSwitchStore switchStore;

    @Autowired
    KillSwitches switches;

    private ObjectNode scratch;

    @BeforeEach
    void seed() {
        scratch = Manifests.jira("1.0.0");
        Manifests.addResource(scratch, "escalation_guide", "How a ticket is escalated.");
        Manifests.addProjectTemplate(scratch, "project_page", "One page of a project.");
        Manifests.addPrompt(scratch, "summarize_ticket", "Summarize the ticket below.");
        store.locked("mcp-jira", tx -> {
            tx.saveEntry(pending(PrimitiveKind.RESOURCE, "escalation_guide", "resources"));
            tx.saveEntry(pending(PrimitiveKind.RESOURCE_TEMPLATE, "project_page", "resourceTemplates"));
            tx.saveEntry(pending(PrimitiveKind.PROMPT, "summarize_ticket", "prompts"));
            return null;
        });
        registry.reloadChanged();
    }

    @AfterEach
    void remove() {
        store.locked("mcp-jira", tx -> {
            for (PrimitiveKind kind : PrimitiveKind.values()) {
                tx.entries().get(kind).keySet().forEach(name -> tx.deleteEntry(kind, name));
            }
            return null;
        });
        switchStore.all().forEach(e -> {
            if (e.resource() != null) {
                switchStore.deleteNamed(e.serverId(), "resource", e.resource());
            } else if (e.prompt() != null) {
                switchStore.deleteNamed(e.serverId(), "prompt", e.prompt());
            } else {
                switchStore.delete(e.serverId(), e.tool());
            }
        });
        switches.refresh();
        registry.reloadChanged();
    }

    private RegisteredEntry pending(PrimitiveKind kind, String name, String field) {
        for (JsonNode entry : scratch.path(field)) {
            if (name.equals(entry.path("name").asString())) {
                return new RegisteredEntry(kind, name, null, new RegisteredEntry.Pending(entry, entry.path("definitionHash").asString(), "1.0.0",
                        "new", "manifest"));
            }
        }
        throw new AssertionError(name);
    }

    private HttpResponse<String> asAdmin(String method, String path, String body) throws Exception {
        return admin(method, path, ADMIN_SUB, "a.admin", ADMIN, body);
    }

    private String hash(String field, String name) {
        return Manifests.entryHash(scratch, field, name);
    }

    @Test
    void thePendingEntryOfEachKindIsShownForADiff() throws Exception {
        for (String[] each : new String[][] {{"resources", "escalation_guide"}, {"resource-templates", "project_page"},
                {"prompts", "summarize_ticket"}}) {
            HttpResponse<String> response = asAdmin("GET", JIRA + "/" + each[0] + "/" + each[1] + "/pending", null);

            assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
            JsonNode body = JSON.readTree(response.body());
            assertThat(Contracts.gatewayAdminErrors("PendingEntry", body)).isEmpty();
            assertThat(body.path("approvedEntry").isNull()).isTrue();
            assertThat(body.path("source").asString()).isEqualTo("manifest");
            assertThat(body.path("pendingEntry").path("name").asString()).isEqualTo(each[1]);
        }
        assertThat(asAdmin("GET", JIRA + "/prompts/no_such_prompt/pending", null).statusCode()).isEqualTo(404);
        assertThat(asAdmin("GET", JIRA + "/resources/summarize_ticket/pending", null).statusCode()).as("a prompt is no resource").isEqualTo(404);
    }

    @Test
    void theRegistryListsThemWithTheirStatus() throws Exception {
        JsonNode servers = JSON.readTree(asAdmin("GET", "/admin/v1/registry/servers", null).body());
        for (JsonNode server : servers) {
            assertThat(Contracts.gatewayAdminErrors("RegistryServer", server)).isEmpty();
            if ("mcp-jira".equals(server.path("serverId").asString())) {
                assertThat(server.path("resources").get(0).path("status").asString()).isEqualTo("pending_approval");
                assertThat(server.path("resourceTemplates")).hasSize(1);
                assertThat(server.path("prompts").get(0).path("change").asString()).isEqualTo("new");
            } else {
                assertThat(server.has("prompts")).isFalse();
            }
        }
    }

    @Test
    void anApprovalNeedsTheCurrentHashAndNoClassification(CapturedOutput output) throws Exception {
        String path = JIRA + "/prompts/summarize_ticket/approve";

        assertThat(asAdmin("POST", path, "{\"definitionHash\":\"sha256:" + "0".repeat(64) + "\"}").statusCode()).isEqualTo(409);
        String current = "\"definitionHash\":\"" + hash("prompts", "summarize_ticket") + "\"";
        for (String extra : List.of("\"risk\":\"READ_ONLY\",\"action\":\"read\"", "\"acceptRiskLowering\":true", "\"acceptRiskLowering\":false", "\"risk\":\"READ_ONLY\"")) {
            HttpResponse<String> refused = asAdmin("POST", path, "{" + current + "," + extra + "}");
            assertThat(refused.statusCode()).as(refused.body()).isEqualTo(422);
            JsonNode error = JSON.readTree(refused.body());
            assertThat(Contracts.gatewayAdminErrors("ManifestRejected", error)).isEmpty();
            assertThat(error.path("reason").asString()).isEqualTo("classification_not_allowed");
        }
        assertThat(asAdmin("POST", path, "{}").statusCode()).as("no hash").isEqualTo(400);
        assertThat(asAdmin("POST", path, "{\"definitionHash\":\"x\"}").statusCode()).isEqualTo(400);
        assertThat(admin("POST", path, UUID.randomUUID().toString(), "bob", List.of("mcp-jira-read"),
                "{\"definitionHash\":\"" + hash("prompts", "summarize_ticket") + "\"}").statusCode()).isEqualTo(403);
        assertThat(registry.registered("mcp-jira").orElseThrow().entries(PrimitiveKind.PROMPT).get("summarize_ticket").approved()).isNull();

        HttpResponse<String> approved = asAdmin("POST", path, "{\"definitionHash\":\"" + hash("prompts", "summarize_ticket") + "\"}");
        assertThat(approved.statusCode()).as(approved.body()).isEqualTo(204);
        assertThat(registry.registered("mcp-jira").orElseThrow().entries(PrimitiveKind.PROMPT).get("summarize_ticket").approved()).isNotNull();
        assertThat(asAdmin("GET", JIRA + "/prompts/summarize_ticket/pending", null).statusCode()).as("nothing pending any more").isEqualTo(404);
        assertThat(output.getOut()).contains("\"reason\":\"definition_approved\"").contains("\"prompt\":\"summarize_ticket\"");
    }

    @Test
    void approvedEntriesAreInTheCatalogAsDeniedForEveryoneBecauseNothingServesThemYet() throws Exception {
        assertThat(asAdmin("POST", JIRA + "/resources/escalation_guide/approve",
                "{\"definitionHash\":\"" + hash("resources", "escalation_guide") + "\"}").statusCode()).isEqualTo(204);
        assertThat(asAdmin("POST", JIRA + "/prompts/summarize_ticket/approve",
                "{\"definitionHash\":\"" + hash("prompts", "summarize_ticket") + "\"}").statusCode()).isEqualTo(204);

        JsonNode catalog = JSON.readTree(admin("GET", "/admin/v1/catalog", ALICE_SUB, "alice", ALICE_GROUPS, null).body());

        assertThat(Contracts.gatewayAdminErrors("Catalog", catalog)).isEmpty();
        for (JsonNode server : catalog.path("servers")) {
            if ("mcp-jira".equals(server.path("serverId").asString())) {
                assertThat(server.path("resources")).hasSize(1);
                assertThat(server.path("resources").get(0).path("access").asString()).isEqualTo("denied");
                assertThat(server.path("resources").get(0).path("uri").asString()).isEqualTo("jira://docs/escalation_guide");
                assertThat(server.path("prompts").get(0).path("name").asString()).isEqualTo("jira__summarize_ticket");
                assertThat(server.has("resourceTemplates")).as("the template is still pending").isFalse();
            } else {
                assertThat(server.has("resources") || server.has("prompts")).isFalse();
            }
        }
    }

    @Test
    void aSwitchOfAResourceOrAPromptIsStoredListedAuditedAndLifted(CapturedOutput output) throws Exception {
        assertThat(asAdmin("PUT", JIRA + "/resources/project_page/kill-switch", "{\"reason\":\"Content is wrong\"}").statusCode())
                .as("a template is covered by the switch of its name").isEqualTo(204);
        assertThat(asAdmin("PUT", JIRA + "/prompts/summarize_ticket/kill-switch", "{\"reason\":\"Text under review\"}").statusCode()).isEqualTo(204);
        assertThat(asAdmin("PUT", JIRA + "/prompts/summarize_ticket/kill-switch", "{\"reason\":\"Text still under review\"}").statusCode())
                .as("putting again only changes the reason").isEqualTo(204);

        JsonNode all = JSON.readTree(asAdmin("GET", "/admin/v1/kill-switches", null).body());
        assertThat(Contracts.gatewayAdminErrors("KillSwitchList", all)).isEmpty();
        assertThat(all.path("switches")).extracting(s -> s.path("scope").asString() + ":" + s.path("resource").asString(s.path("prompt").asString()))
                .containsExactlyInAnyOrder("resource:project_page", "prompt:summarize_ticket");
        assertThat(switches.statusOfResource("mcp-jira", "project_page")).isEqualTo(KillSwitches.Status.ON);
        assertThat(switches.statusOfPrompt("mcp-jira", "project_page")).as("a resource switch does not hide a prompt").isEqualTo(KillSwitches.Status.OFF);
        assertThat(switches.status("mcp-jira", "project_page")).as("nor a tool").isEqualTo(KillSwitches.Status.OFF);
        assertThat(output.getOut()).contains("\"reason\":\"kill_switch_set\"").contains("\"resourceTemplate\":\"project_page\"");

        assertThat(asAdmin("DELETE", JIRA + "/resources/project_page/kill-switch", null).statusCode()).isEqualTo(204);
        assertThat(asAdmin("DELETE", JIRA + "/resources/project_page/kill-switch", null).statusCode()).as("idempotent").isEqualTo(204);
        assertThat(switches.statusOfResource("mcp-jira", "project_page")).isEqualTo(KillSwitches.Status.OFF);
        assertThat(switches.statusOfPrompt("mcp-jira", "summarize_ticket")).isEqualTo(KillSwitches.Status.ON);
    }

    @Test
    void whoMayPutASwitchAndWhatTheRegistryMustKnow() throws Exception {
        String path = JIRA + "/prompts/summarize_ticket/kill-switch";

        assertThat(admin("PUT", path, UUID.randomUUID().toString(), "bob", List.of("mcp-jira-read"), "{\"reason\":\"x\"}").statusCode()).isEqualTo(403);
        assertThat(asAdmin("PUT", path, "{}").statusCode()).isEqualTo(400);
        assertThat(asAdmin("PUT", JIRA + "/prompts/not_a_prompt/kill-switch", "{\"reason\":\"x\"}").statusCode()).isEqualTo(404);
        assertThat(asAdmin("PUT", JIRA + "/resources/summarize_ticket/kill-switch", "{\"reason\":\"x\"}").statusCode())
                .as("a prompt is no resource").isEqualTo(404);
        assertThat(asAdmin("PUT", "/admin/v1/registry/servers/mcp-nosuch/prompts/summarize_ticket/kill-switch", "{\"reason\":\"x\"}").statusCode())
                .isEqualTo(404);
        assertThat(asAdmin("DELETE", JIRA + "/prompts/left_long_ago/kill-switch", null).statusCode())
                .as("the switch of an entry that left the manifest can be lifted").isEqualTo(204);
    }
}
