package pl.aiwcorpo.mcp.gateway.registry;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import pl.aiwcorpo.mcp.gateway.registry.RegistryPlanner.Change;
import pl.aiwcorpo.mcp.gateway.support.Manifests;
import pl.aiwcorpo.mcp.gateway.support.Manifests.Tool;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/** What a registration does to the registry (CC-133, CC-162): approve READ_ONLY, hold UPDATE and DESTRUCTIVE, remove, refuse a lowered risk. */
class RegistryPlannerTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final String CREDENTIAL = "{\"required\":true,\"acceptedTypes\":[\"user-secret\"]}";

    private static RegistryPlanner.Plan plan(ObjectNode manifest, Map<String, RegisteredTool> existing) {
        return RegistryPlanner.plan(manifest, CREDENTIAL, existing, Map.of(), false);
    }

    private static Map<String, RegisteredTool> registered(ObjectNode manifest) {
        return new LinkedHashMap<>(plan(manifest, Map.of()).tools());
    }

    private static String hash(ObjectNode manifest, String tool) {
        return Manifests.tool(manifest, tool).path("definitionHash").asString();
    }

    @Test
    void theFirstRegistrationApprovesReadOnlyToolsAndHoldsTheOthers() {
        ObjectNode manifest = Manifests.jira("1.4.0", Tool.readOnly("get_issue"), Tool.update("update_issue"), Tool.destructive("delete_issue"));

        RegistryPlanner.Plan plan = plan(manifest, Map.of());

        assertThat(plan.lowered()).isEmpty();
        RegisteredTool read = plan.tools().get("get_issue");
        assertThat(read.approved().version()).isEqualTo("1.4.0");
        assertThat(read.approved().hash()).isEqualTo(hash(manifest, "get_issue"));
        assertThat(read.pending()).isNull();
        for (String held : List.of("update_issue", "delete_issue")) {
            RegisteredTool tool = plan.tools().get(held);
            assertThat(tool.approved()).as(held).isNull();
            assertThat(tool.pending().change()).isEqualTo("new");
            assertThat(tool.pending().source()).isEqualTo("ci");
            assertThat(tool.pending().version()).isEqualTo("1.4.0");
            assertThat(tool.pending().hash()).isEqualTo(hash(manifest, held));
        }
        assertThat(plan.changes()).containsExactly(new Change("definition_registered", "get_issue", hash(manifest, "get_issue")),
                new Change("definition_submitted", "update_issue", hash(manifest, "update_issue")),
                new Change("definition_submitted", "delete_issue", hash(manifest, "delete_issue")));
        assertThat(plan.risks()).containsExactly(Map.entry("get_issue", 0));
    }

    @Test
    void anUnchangedToolIsLeftAloneAndLeavesNoEvent() {
        ObjectNode manifest = Manifests.jira("1.4.0", Tool.readOnly("get_issue"));
        Map<String, RegisteredTool> before = registered(manifest);

        RegistryPlanner.Plan again = plan(Manifests.jira("1.5.0", Tool.readOnly("get_issue")), before);

        assertThat(again.changes()).isEmpty();
        assertThat(again.tools().get("get_issue").approved().version()).as("approved in the version that approved it").isEqualTo("1.4.0");
    }

    @Test
    void aChangedReadOnlyDefinitionIsApprovedByTheReviewAndAChangedUpdateDefinitionWaits() {
        Map<String, RegisteredTool> before = registered(Manifests.jira("1.4.0", Tool.readOnly("get_issue"), Tool.update("update_issue")));
        // The update tool was held as new; an administrator approved it, which the test puts in directly.
        RegisteredTool held = before.get("update_issue");
        before.put("update_issue", new RegisteredTool("update_issue", new RegisteredTool.Approved(held.pending().entry(), held.pending().hash(),
                held.pending().version(), CREDENTIAL), null));

        ObjectNode next = Manifests.jira("1.5.0", Tool.readOnly("get_issue").described("Reads it, better."),
                Tool.update("update_issue").described("Changes it, differently."));
        RegistryPlanner.Plan plan = plan(next, before);

        RegisteredTool read = plan.tools().get("get_issue");
        assertThat(read.approved().version()).isEqualTo("1.5.0");
        assertThat(read.approved().hash()).isEqualTo(hash(next, "get_issue"));
        RegisteredTool update = plan.tools().get("update_issue");
        assertThat(update.approved().hash()).as("the approved definition stays in force").isEqualTo(held.pending().hash());
        assertThat(update.pending().change()).isEqualTo("changed");
        assertThat(update.pending().version()).isEqualTo("1.5.0");
        assertThat(plan.changes()).extracting(Change::kind).containsExactly("definition_registered", "definition_submitted");
    }

    @Test
    void aToolTheManifestNoLongerHasIsRemovedAndAudited() {
        ObjectNode first = Manifests.jira("1.4.0", Tool.readOnly("get_issue"), Tool.update("update_issue"));
        Map<String, RegisteredTool> before = registered(first);

        RegistryPlanner.Plan plan = plan(Manifests.jira("1.5.0", Tool.readOnly("get_issue")), before);

        assertThat(plan.tools()).containsOnlyKeys("get_issue");
        assertThat(plan.changes()).containsExactly(new Change("tool_removed", "update_issue", hash(first, "update_issue")));
    }

    @Test
    void aLoweredRiskStopsTheWholeRegistration() {
        Map<String, RegisteredTool> before = registered(Manifests.jira("1.4.0", Tool.readOnly("get_issue")));
        RegisteredTool approvedUpdate = new RegisteredTool("update_issue", new RegisteredTool.Approved(
                Manifests.tool(Manifests.jira("1", Tool.update("update_issue")), "update_issue"), "sha256:" + "a".repeat(64), "1.4.0",
                CREDENTIAL), null);
        before.put("update_issue", approvedUpdate);

        RegistryPlanner.Plan plan = plan(Manifests.jira("1.5.0", Tool.readOnly("get_issue"), Tool.readOnly("update_issue")), before);

        assertThat(plan.lowered()).containsExactly("update_issue");
    }

    @Test
    void aRiskBelowTheFloorOrTheConfiguredMinimumIsLoweredEvenWithoutAnApprovedEntry() {
        ObjectNode manifest = Manifests.jira("1.4.0", Tool.readOnly("delete_issue"));

        assertThat(RegistryPlanner.plan(manifest, CREDENTIAL, Map.of(), Map.of("delete_issue", 2), false).lowered())
                .as("a tool that was DESTRUCTIVE once and was removed").containsExactly("delete_issue");
        assertThat(RegistryPlanner.plan(manifest, CREDENTIAL, Map.of(), Map.of("delete_issue", 0), false).lowered()).isEmpty();
    }

    @Test
    void aPendingEntryOfThePipelineIsKeptWhenTheSameCommitIsRegisteredAgain() {
        ObjectNode manifest = Manifests.jira("1.4.0", Tool.update("update_issue"));
        Map<String, RegisteredTool> before = registered(manifest);

        RegistryPlanner.Plan again = plan(Manifests.jira("1.4.1", Tool.update("update_issue")), before);

        assertThat(again.changes()).as("nothing new to approve").isEmpty();
        assertThat(again.tools().get("update_issue").pending().version()).isEqualTo("1.4.0");
    }

    @Test
    void aPendingEntryIsDroppedWhenTheManifestCarriesTheApprovedDefinitionAgain() {
        ObjectNode approvedManifest = Manifests.jira("1.4.0", Tool.readOnly("get_issue"));
        Map<String, RegisteredTool> before = registered(approvedManifest);
        JsonNode changed = Manifests.tool(Manifests.jira("1.5.0", Tool.readOnly("get_issue").described("Changed.")), "get_issue");
        before.put("get_issue", before.get("get_issue").withPending(new RegisteredTool.Pending(changed, hash(approvedManifest, "get_issue"),
                "0.9.0", "changed", "server", CREDENTIAL)));

        RegistryPlanner.Plan plan = plan(Manifests.jira("1.6.0", Tool.readOnly("get_issue")), before);

        assertThat(plan.tools().get("get_issue").pending()).as("the server entry goes, the reviewed commit says the approved definition").isNull();
    }

    @Test
    void theDevBootstrapApprovesEverythingTheServerServes() {
        ObjectNode manifest = Manifests.jira("1.4.0", Tool.update("update_issue"), Tool.destructive("delete_issue"));

        RegistryPlanner.Plan plan = RegistryPlanner.plan(manifest, CREDENTIAL, Map.of(), Map.of(), true);

        assertThat(plan.tools().values()).allSatisfy(tool -> {
            assertThat(tool.approved()).isNotNull();
            assertThat(tool.pending()).isNull();
        });
        assertThat(plan.risks()).containsEntry("update_issue", 1).containsEntry("delete_issue", 2);
    }
}
