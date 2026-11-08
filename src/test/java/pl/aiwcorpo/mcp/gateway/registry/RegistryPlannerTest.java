package pl.aiwcorpo.mcp.gateway.registry;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import pl.aiwcorpo.mcp.gateway.registry.RegistryPlanner.Change;
import pl.aiwcorpo.mcp.gateway.support.Manifests;
import pl.aiwcorpo.mcp.gateway.support.Manifests.Tool;
import pl.aiwcorpo.mcp.gateway.support.Vectors;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/** What a pulled manifest does to the registry (CC-133, CC-162, CC-249): nothing is approved, a tool that is gone is removed, a lowered risk is marked. */
class RegistryPlannerTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final String CREDENTIAL = "{\"required\":true,\"acceptedTypes\":[\"user-secret\"]}";

    private static RegistryPlanner.Plan plan(ObjectNode manifest, Map<String, RegisteredTool> existing) {
        return RegistryPlanner.plan(manifest, CREDENTIAL, existing, floorsOf(existing), false);
    }

    /** The floors of a registry whose tools were approved: the approved risk of each. */
    private static Map<String, Integer> floorsOf(Map<String, RegisteredTool> existing) {
        Map<String, Integer> floors = new LinkedHashMap<>();
        existing.forEach((name, tool) -> floors.put(name, tool.approvedRisk()));
        return floors;
    }

    /** The registry after an administrator approved every entry of a first pull. */
    private static Map<String, RegisteredTool> approved(ObjectNode manifest) {
        Map<String, RegisteredTool> out = new LinkedHashMap<>();
        plan(manifest, Map.of()).tools().forEach((name, tool) -> out.put(name, new RegisteredTool(name,
                new RegisteredTool.Approved(tool.pending().entry(), tool.pending().hash(), tool.pending().version(), CREDENTIAL), null)));
        return out;
    }

    private static String hash(ObjectNode manifest, String tool) {
        return Manifests.tool(manifest, tool).path("definitionHash").asString();
    }

    @Test
    void theFirstPullApprovesNothingNotEvenAReadOnlyTool() {
        ObjectNode manifest = Manifests.jira("1.4.0", Tool.readOnly("get_issue"), Tool.update("update_issue"), Tool.destructive("delete_issue"));

        RegistryPlanner.Plan plan = plan(manifest, Map.of());

        for (String name : List.of("get_issue", "update_issue", "delete_issue")) {
            RegisteredTool tool = plan.tools().get(name);
            assertThat(tool.approved()).as(name).isNull();
            assertThat(tool.pending().change()).isEqualTo("new");
            assertThat(tool.pending().source()).isEqualTo("manifest");
            assertThat(tool.pending().version()).isEqualTo("1.4.0");
            assertThat(tool.pending().hash()).isEqualTo(hash(manifest, name));
            assertThat(tool.pending().riskLowered()).isFalse();
        }
        assertThat(plan.changes()).containsExactly(new Change("definition_submitted", "get_issue", hash(manifest, "get_issue")),
                new Change("definition_submitted", "update_issue", hash(manifest, "update_issue")),
                new Change("definition_submitted", "delete_issue", hash(manifest, "delete_issue")));
        assertThat(plan.risks()).as("submitted risks count for the floors").containsOnly(Map.entry("get_issue", 0), Map.entry("update_issue", 1),
                Map.entry("delete_issue", 2));
    }

    @Test
    void anUnchangedToolIsLeftAloneAndLeavesNoEvent() {
        ObjectNode manifest = Manifests.jira("1.4.0", Tool.readOnly("get_issue"));
        Map<String, RegisteredTool> before = approved(manifest);

        RegistryPlanner.Plan again = plan(Manifests.jira("1.5.0", Tool.readOnly("get_issue")), before);

        assertThat(again.changes()).isEmpty();
        assertThat(again.tools()).isEqualTo(before);
        assertThat(again.tools().get("get_issue").approved().version()).as("approved in the version that approved it").isEqualTo("1.4.0");
    }

    @Test
    void aChangedToolWaitsWhateverItsRiskAndTheApprovedOneStaysInForce() {
        Map<String, RegisteredTool> before = approved(Manifests.jira("1.4.0", Tool.readOnly("get_issue"), Tool.update("update_issue")));

        ObjectNode next = Manifests.jira("1.5.0", Tool.readOnly("get_issue").described("Reads it, better."),
                Tool.update("update_issue").described("Changes it, differently."));
        RegistryPlanner.Plan plan = plan(next, before);

        for (String name : List.of("get_issue", "update_issue")) {
            RegisteredTool tool = plan.tools().get(name);
            assertThat(tool.approved().version()).as(name + ": what was approved stays in force").isEqualTo("1.4.0");
            assertThat(tool.pending().change()).isEqualTo("changed");
            assertThat(tool.pending().version()).isEqualTo("1.5.0");
            assertThat(tool.pending().hash()).isEqualTo(hash(next, name));
            assertThat(tool.pending().riskLowered()).isFalse();
        }
        assertThat(plan.changes()).extracting(Change::kind).containsExactly("definition_submitted", "definition_submitted");
    }

    @Test
    void aToolTheManifestNoLongerHasIsRemovedAndAudited() {
        ObjectNode first = Manifests.jira("1.4.0", Tool.readOnly("get_issue"), Tool.update("update_issue"));
        Map<String, RegisteredTool> before = approved(first);

        RegistryPlanner.Plan plan = plan(Manifests.jira("1.5.0", Tool.readOnly("get_issue")), before);

        assertThat(plan.tools()).containsOnlyKeys("get_issue");
        assertThat(plan.changes()).containsExactly(new Change("tool_removed", "update_issue", hash(first, "update_issue")));
    }

    @Test
    void aLoweredRiskIsNoRejectionItMarksThatOneToolForAnAdministrator() {
        Map<String, RegisteredTool> before = approved(Manifests.jira("1.4.0", Tool.update("update_issue"), Tool.readOnly("get_issue")));

        ObjectNode next = Manifests.jira("1.5.0", Tool.readOnly("update_issue"), Tool.readOnly("get_issue").described("Better."));
        RegistryPlanner.Plan plan = plan(next, before);

        RegisteredTool held = plan.tools().get("update_issue");
        assertThat(held.approved().version()).as("the approved definition stays in force").isEqualTo("1.4.0");
        assertThat(held.pending().riskLowered()).isTrue();
        assertThat(held.pending().change()).isEqualTo("changed");
        assertThat(held.pending().source()).isEqualTo("manifest");
        assertThat(plan.tools().get("get_issue").pending().riskLowered()).isFalse();
        assertThat(plan.risks()).as("a lowered risk raises nothing").doesNotContainKey("update_issue");
    }

    @Test
    void aToolRemovedAndAddedAgainBelowItsFloorIsNewAndMarked() {
        RegistryPlanner.Plan plan = RegistryPlanner.plan(Manifests.jira("1.5.0", Tool.readOnly("update_issue")), CREDENTIAL, Map.of(),
                Map.of("update_issue", 1), false);

        RegisteredTool tool = plan.tools().get("update_issue");
        assertThat(tool.approved()).isNull();
        assertThat(tool.pending().change()).isEqualTo("new");
        assertThat(tool.pending().riskLowered()).isTrue();
    }

    @Test
    void aReturnToTheApprovedDefinitionBelowTheFloorStaysApprovedBecauseItIsTheApprovedOne() {
        ObjectNode approvedManifest = Manifests.jira("1.4.0", Tool.readOnly("get_issue"));
        Map<String, RegisteredTool> before = approved(approvedManifest);

        // A DESTRUCTIVE version was reported since and raised the floor; the manifest goes back to the approved read-only definition.
        RegistryPlanner.Plan plan = RegistryPlanner.plan(Manifests.jira("1.6.0", Tool.readOnly("get_issue")), CREDENTIAL, before,
                Map.of("get_issue", 2), false);

        assertThat(plan.tools().get("get_issue").pending()).as("the hash is the approved one: it stays").isNull();
        assertThat(plan.tools().get("get_issue").approved().version()).isEqualTo("1.4.0");
    }

    @Test
    void aPendingEntryOfAPullIsKeptWhenTheSameDefinitionIsPulledAgain() {
        ObjectNode manifest = Manifests.jira("1.4.0", Tool.update("update_issue"));
        Map<String, RegisteredTool> before = plan(manifest, Map.of()).tools();

        RegistryPlanner.Plan again = plan(Manifests.jira("1.4.1", Tool.update("update_issue")), new LinkedHashMap<>(before));

        assertThat(again.changes()).as("nothing new to approve").isEmpty();
        assertThat(again.tools().get("update_issue").pending().version()).isEqualTo("1.4.0");
    }

    @Test
    void aPendingEntryIsDroppedWhenTheManifestCarriesTheApprovedDefinitionAgain() {
        ObjectNode approvedManifest = Manifests.jira("1.4.0", Tool.readOnly("get_issue"));
        Map<String, RegisteredTool> before = approved(approvedManifest);
        JsonNode changed = Manifests.tool(Manifests.jira("1.5.0", Tool.readOnly("get_issue").described("Changed.")), "get_issue");
        before.put("get_issue", before.get("get_issue").withPending(new RegisteredTool.Pending(changed, "sha256:" + "a".repeat(64),
                "0.9.0", "changed", "server", CREDENTIAL)));

        RegistryPlanner.Plan plan = plan(Manifests.jira("1.6.0", Tool.readOnly("get_issue")), before);

        assertThat(plan.tools().get("get_issue").pending()).as("the server's entry goes: the manifest says the approved definition").isNull();
    }

    @Test
    void aSubmittedRiskIsRememberedForTheFloorsToo() {
        RegistryPlanner.Plan plan = plan(Manifests.jira("1.4.0", Tool.destructive("delete_issue")), Map.of());

        assertThat(plan.risks()).containsEntry("delete_issue", 2);
        // The next pull, with the same pending entry, lowers it to UPDATE: marked as a lowering against the floor that the submission raised.
        RegistryPlanner.Plan next = RegistryPlanner.plan(Manifests.jira("1.5.0", Tool.update("delete_issue")), CREDENTIAL,
                new LinkedHashMap<>(plan.tools()), plan.risks(), false);
        assertThat(next.tools().get("delete_issue").pending().riskLowered()).isTrue();
    }

    @Test
    void anAdapterManifestMakesEveryNewOrChangedToolPendingWithTheSourceAdapterAndNoRisk() {
        ObjectNode manifest = Manifests.adapter("mcp-jira", "jira", "0.3.0", Tool.readOnly("get_issue"), Tool.readOnly("update_issue"));

        RegistryPlanner.Plan plan = RegistryPlanner.plan(manifest, CREDENTIAL, Map.of(), Map.of(), true);

        for (String name : List.of("get_issue", "update_issue")) {
            assertThat(plan.tools().get(name).approved()).isNull();
            assertThat(plan.tools().get(name).pending().source()).isEqualTo("adapter");
            assertThat(plan.tools().get(name).pending().entry().has("risk")).isFalse();
        }
        assertThat(plan.risks()).as("there is no risk to remember for the floors").isEmpty();
    }

    // --- the vectors -----------------------------------------------------------------------------------------

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

    /** The {@code pull-*} vectors of registry-approval/ (CC-249, CC-245, CC-246, CC-167): what a pull does to one tool. */
    @TestFactory
    List<DynamicTest> thePullVectors() {
        List<DynamicTest> tests = new java.util.ArrayList<>();
        for (Vectors.Vector vector : Vectors.of("registry-approval")) {
            if (!vector.name().startsWith("pull-")) {
                continue;
            }
            tests.add(DynamicTest.dynamicTest(vector.name(), () -> {
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
                Map<String, Integer> floors = floorsOf(existing);
                if (input.hasNonNull("riskFloor")) {
                    floors.put("get_thing", switch (input.path("riskFloor").asString()) {
                        case "READ_ONLY" -> 0;
                        case "UPDATE" -> 1;
                        default -> 2;
                    });
                }

                RegisteredTool next = RegistryPlanner.plan(manifest, CREDENTIAL, existing, floors, false).tools().get("get_thing");

                boolean unchanged = next.pending() == null;
                assertThat(unchanged ? "approved" : "pending_approval").as(vector.document().path("description").asString())
                        .isEqualTo(expected.path("state").asString());
                if (unchanged) {
                    assertThat(expected.path("change").asString()).isEqualTo("unchanged");
                    assertThat(next.approved().hash()).isEqualTo(input.path("submitted").path("definitionHash").asString());
                } else {
                    assertThat(next.pending().change()).isEqualTo(expected.path("change").asString());
                    assertThat(next.pending().source()).isEqualTo(expected.path("source").asString());
                    assertThat(next.pending().riskLowered()).isEqualTo(expected.path("riskLowered").asBoolean(false));
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
