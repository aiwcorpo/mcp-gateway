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
        return RegistryPlanner.plan(manifest, CREDENTIAL, existing, floorsOf(existing), Map.of(), false);
    }

    /** The floors of a registry whose tools were approved: the approved risk of each. */
    private static Map<String, Integer> floorsOf(Map<String, RegisteredTool> existing) {
        Map<String, Integer> floors = new LinkedHashMap<>();
        existing.forEach((name, tool) -> floors.put(name, tool.approvedRisk()));
        return floors;
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
        assertThat(plan.risks()).as("approved and submitted risks both count for the floors")
                .containsOnly(Map.entry("get_issue", 0), Map.entry("update_issue", 1), Map.entry("delete_issue", 2));
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
    void aLoweredRiskDoesNotRejectTheManifestItHoldsThatOneToolForAnAdministrator() {
        Map<String, RegisteredTool> before = registered(Manifests.jira("1.4.0", Tool.readOnly("get_issue")));
        RegisteredTool approvedUpdate = new RegisteredTool("update_issue", new RegisteredTool.Approved(
                Manifests.tool(Manifests.jira("1", Tool.update("update_issue")), "update_issue"), "sha256:" + "a".repeat(64), "1.4.0",
                CREDENTIAL), null);
        before.put("update_issue", approvedUpdate);
        ObjectNode next = Manifests.jira("1.5.0", Tool.readOnly("get_issue").described("Better."), Tool.readOnly("update_issue"));

        RegistryPlanner.Plan plan = plan(next, before);

        assertThat(plan.lowered()).isEmpty();
        assertThat(plan.tools().get("get_issue").approved().version()).as("the rest of the manifest goes through").isEqualTo("1.5.0");
        RegisteredTool held = plan.tools().get("update_issue");
        assertThat(held.approved()).as("the approved definition stays in force").isEqualTo(approvedUpdate.approved());
        assertThat(held.pending().riskLowered()).isTrue();
        assertThat(held.pending().change()).isEqualTo("changed");
        assertThat(held.pending().source()).isEqualTo("ci");
        assertThat(plan.risks()).as("a lowered risk raises nothing").doesNotContainKey("update_issue");
    }

    @Test
    void aToolRemovedAndAddedAgainBelowItsFloorIsNewAndHeld() {
        ObjectNode first = Manifests.jira("1.4.0", Tool.update("update_issue"));

        RegistryPlanner.Plan plan = RegistryPlanner.plan(Manifests.jira("1.5.0", Tool.readOnly("update_issue")), CREDENTIAL, Map.of(),
                Map.of("update_issue", 1), Map.of(), false);

        RegisteredTool tool = plan.tools().get("update_issue");
        assertThat(tool.approved()).isNull();
        assertThat(tool.pending().change()).isEqualTo("new");
        assertThat(tool.pending().riskLowered()).isTrue();
        assertThat(first).isNotNull();
    }

    @Test
    void aReturnToTheApprovedDefinitionBelowTheFloorWaitsToo() {
        ObjectNode approvedManifest = Manifests.jira("1.4.0", Tool.readOnly("get_issue"));
        Map<String, RegisteredTool> before = registered(approvedManifest);

        // A DESTRUCTIVE version was submitted since and raised the floor; the commit goes back to the approved read-only definition.
        RegistryPlanner.Plan plan = RegistryPlanner.plan(Manifests.jira("1.6.0", Tool.readOnly("get_issue")), CREDENTIAL, before,
                Map.of("get_issue", 2), Map.of(), false);

        assertThat(plan.tools().get("get_issue").pending().riskLowered()).isTrue();
        assertThat(plan.tools().get("get_issue").approved().version()).isEqualTo("1.4.0");
    }

    @Test
    void theRiskOfTheConfigurationIsNeverLoweredNotEvenForAnAdministrator() {
        ObjectNode manifest = Manifests.jira("1.4.0", Tool.readOnly("delete_issue"));

        assertThat(RegistryPlanner.plan(manifest, CREDENTIAL, Map.of(), Map.of(), Map.of("delete_issue", 2), false).lowered())
                .containsExactly("delete_issue");
        assertThat(RegistryPlanner.plan(manifest, CREDENTIAL, Map.of(), Map.of(), Map.of("delete_issue", 0), false).lowered()).isEmpty();
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

        RegistryPlanner.Plan plan = RegistryPlanner.plan(manifest, CREDENTIAL, Map.of(), Map.of(), Map.of(), true);

        assertThat(plan.tools().values()).allSatisfy(tool -> {
            assertThat(tool.approved()).isNotNull();
            assertThat(tool.pending()).isNull();
        });
        assertThat(plan.risks()).containsEntry("update_issue", 1).containsEntry("delete_issue", 2);
    }

    @Test
    void aSubmittedRiskIsRememberedForTheFloorsToo() {
        RegistryPlanner.Plan plan = plan(Manifests.jira("1.4.0", Tool.destructive("delete_issue")), Map.of());

        assertThat(plan.risks()).containsEntry("delete_issue", 2);
        // The next registration, with the same pending entry, lowers it to UPDATE: held as a lowering against the floor submission raised.
        RegistryPlanner.Plan next = RegistryPlanner.plan(Manifests.jira("1.5.0", Tool.update("delete_issue")), CREDENTIAL,
                new LinkedHashMap<>(plan.tools()), plan.risks(), Map.of(), false);
        assertThat(next.tools().get("delete_issue").pending().riskLowered()).isTrue();
    }

    private static JsonNode entryOf(JsonNode described) {
        ObjectNode entry = JSON.createObjectNode();
        entry.put("name", "get_thing");
        entry.put("risk", described.path("risk").asString());
        entry.put("action", "READ_ONLY".equals(described.path("risk").asString()) ? "read" : "update");
        entry.putArray("resourceRefs");
        entry.set("definition", Manifests.definition(Tool.readOnly("get_thing")));
        entry.put("definitionHash", described.path("definitionHash").asString());
        if (described.has("additionalGroup")) {
            entry.put("additionalGroup", described.path("additionalGroup").asString());
        }
        return entry;
    }

    /** The registration vectors of registry-approval/ (CC-245): what a registration does to an additionalGroup, whatever the risk. */
    @org.junit.jupiter.api.TestFactory
    List<org.junit.jupiter.api.DynamicTest> theRegistrationVectors() {
        List<org.junit.jupiter.api.DynamicTest> tests = new java.util.ArrayList<>();
        for (pl.aiwcorpo.mcp.gateway.support.Vectors.Vector vector : pl.aiwcorpo.mcp.gateway.support.Vectors.of("registry-approval")) {
            if (!vector.name().startsWith("registration-")) {
                continue;
            }
            tests.add(org.junit.jupiter.api.DynamicTest.dynamicTest(vector.name(), () -> {
                JsonNode input = vector.document().path("input");
                JsonNode expected = vector.document().path("expected");
                Map<String, RegisteredTool> existing = new LinkedHashMap<>();
                if (!input.path("approved").isNull()) {
                    JsonNode entry = entryOf(input.path("approved"));
                    existing.put("get_thing", new RegisteredTool("get_thing", new RegisteredTool.Approved(entry,
                            entry.path("definitionHash").asString(), "1.0.0", CREDENTIAL), null));
                }
                ObjectNode manifest = JSON.createObjectNode();
                manifest.put("version", "1.1.0");
                manifest.putArray("tools").add(entryOf(input.path("submitted")));

                RegisteredTool next = plan(manifest, existing).tools().get("get_thing");

                boolean approved = next.pending() == null;
                assertThat(approved ? "approved" : "pending_approval").as(vector.document().path("description").asString())
                        .isEqualTo(expected.path("state").asString());
                if (approved) {
                    assertThat(next.approved().hash()).isEqualTo(input.path("submitted").path("definitionHash").asString());
                } else {
                    assertThat(next.pending().change()).isEqualTo(expected.path("change").asString());
                    if (!existing.isEmpty()) {
                        assertThat(next.approved().entry().path("additionalGroup").asString(null))
                                .as("what was approved stays in force").isEqualTo(input.path("approved").path("additionalGroup").asString(null));
                    }
                }
            }));
        }
        assertThat(tests).hasSize(8);
        return tests;
    }
}
