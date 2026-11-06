package pl.aiwcorpo.mcp.gateway.registry;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.system.CapturedOutput;

import pl.aiwcorpo.mcp.gateway.GatewayTestBase;
import pl.aiwcorpo.mcp.gateway.audit.AuditLog;
import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.registry.RegistryService.Approval;
import pl.aiwcorpo.mcp.gateway.registry.RegistryService.Classification;
import pl.aiwcorpo.mcp.gateway.registry.RegistryService.Result;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.server.ServerRegistry;
import pl.aiwcorpo.mcp.gateway.support.Contracts;
import pl.aiwcorpo.mcp.gateway.support.Manifests;
import pl.aiwcorpo.mcp.gateway.support.Manifests.Tool;
import pl.aiwcorpo.mcp.gateway.support.Vectors;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * Servers behind an adapter in the registry (CC-193, CC-206, CC-207), on a real PostgreSQL with registries of their own for mcp-regad (a server that no other test uses), once
 * in adapter mode and once as a server on the starter: what a submission stores, how an administrator classifies and approves, what a
 * removal and a changed definition do to the classification. The vectors {@code adapter-registry/} and {@code registry-approval/} run here.
 */
class RegistryAdapterTest extends GatewayTestBase {

    private static final String SERVER = "mcp-regad";
    private static final String SYSTEM = "regad";
    private static final String ADMIN_SUB = "3b0d6f2e-91c4-4d7a-8a52-6c1e4f7a9d10";

    @Autowired
    RegistryStore store;

    @Autowired
    AuditLog audit;

    @Autowired
    pl.aiwcorpo.mcp.gateway.policy.PolicyService policies;

    private final ManifestFetcher fetcher = mock(ManifestFetcher.class);
    private ServerRegistry adapterServers;
    private ServerRegistry starterServers;
    private RegistryService adapterService;
    private RegistryService starterService;
    private String requestId;

    @BeforeEach
    void clean() {
        requestId = pl.aiwcorpo.mcp.gateway.jwt.UuidV7.next();
        wipe();
        store.locked(SERVER, tx -> {
            tx.saveConfig(adapterConfig(true), true);
            return null;
        });
        adapterServers = registry(true);
        starterServers = registry(false);
        adapterService = service(adapterServers);
        starterService = service(starterServers);
    }

    @AfterEach
    void wipe() {
        for (String table : List.of("registry_tools", "registry_servers", "registry_risk_floor", "registry_policies", "registry_namespaces",
                "kill_switches", "servers")) {
            jdbc.sql("DELETE FROM " + table + " WHERE server_id = ?").param(SERVER).update();
        }
    }

    /** The same server as seen by two gateways: one that serves it through an adapter and one that does not. */
    private static ServerRegistry registry(boolean adapter) {
        ServerRegistry registry = new ServerRegistry();
        registry.replaceConfigs(List.of(adapterConfig(adapter)));
        return registry;
    }

    private static ServerConfig adapterConfig(boolean adapter) {
        return new ServerConfig(SERVER, SYSTEM, URI.create("https://mcp-regad.internal:8443/mcp"), "mcp-regad.internal",
                new ServerConfig.Credential(true, List.of("user-secret"), "user-secret"), true, adapter);
    }

    private RegistryService service(ServerRegistry on) {
        return new RegistryService(on, store, new ManifestValidator(JSON, false), fetcher,
                new DefinitionGuard(Clock.systemUTC(), Duration.ofSeconds(30)), new DefinitionCheck(JSON), audit, "mcp-gateway", JSON, policies);
    }

    /** A manifest of a server that is no adapter, registered as the pipeline does; its policies are approved the way an administrator does. */
    private Result registerNative(ObjectNode manifest) {
        Result result = starterService.register(requestId, SERVER, manifest, "ci");
        if (result instanceof Result.Accepted && starterService.policiesOf(SERVER).filter(p -> p.pending()).isPresent()) {
            starterService.approvePolicies(requestId, SERVER, manifest.path("policiesHash").asString(), admin());
        }
        return result;
    }

    private static ObjectNode nativeManifest(String version, Tool... tools) {
        return Manifests.manifest(SERVER, SYSTEM, version, List.of(Manifests.USER_SECRET), tools);
    }

    private static GatewayUser admin() {
        return new GatewayUser(ADMIN_SUB, "a.admin", "mcp-portal-bff", List.of("mcp-platform-admin"), "unused");
    }

    private Result.Accepted submit(ObjectNode manifest) {
        Result result = adapterService.submitAdapter(requestId, SERVER, manifest);
        assertThat(result).as(result.toString()).isInstanceOf(Result.Accepted.class);
        return (Result.Accepted) result;
    }

    private RegisteredTool tool(String name) {
        return adapterService.registered(SERVER).orElseThrow().tools().get(name);
    }

    private static String hash(ObjectNode manifest, String tool) {
        return Manifests.tool(manifest, tool).path("definitionHash").asString();
    }

    private ObjectNode adapterManifest(String version, Tool... tools) {
        return Manifests.adapter(SERVER, SYSTEM, version, tools);
    }

    @Test
    void aSubmissionApprovesNothingNotEvenAToolThatLooksLikeARead(CapturedOutput output) {
        ObjectNode manifest = adapterManifest("0.3.0", Tool.readOnly("get_issue"), Tool.readOnly("update_issue"));

        Result.Accepted accepted = submit(manifest);

        assertThat(adapterServers.find(SERVER).orElseThrow().tools()).isEmpty();
        for (String name : List.of("get_issue", "update_issue")) {
            RegisteredTool.Pending pending = tool(name).pending();
            assertThat(pending.source()).isEqualTo("adapter");
            assertThat(pending.change()).isEqualTo("new");
            assertThat(pending.entry().has("risk")).isFalse();
            assertThat(tool(name).approved()).isNull();
        }
        assertThat(Contracts.gatewayAdminErrors("RegistryServer", pl.aiwcorpo.mcp.gateway.admin.RegistryViews.server(JSON, accepted.server(), false, java.util.Map.of()))).isEmpty();
        assertThat(auditReasons(output, requestId)).containsExactlyInAnyOrder("definition_submitted", "definition_submitted");
        assertThat(adapterServers.resolveForCall("regad__get_issue")).as("known, disabled, judged as the most dangerous kind").isPresent();
        assertThat(adapterServers.resolveForCall("regad__get_issue").orElseThrow().tool().disabled()).isTrue();
        assertThat(adapterServers.resolveForCall("regad__get_issue").orElseThrow().tool().risk().name()).isEqualTo("DESTRUCTIVE");
    }

    @Test
    void theAdministratorClassifiesWhenApprovingAndTheHashDoesNotCoverTheClassification(CapturedOutput output) {
        ObjectNode manifest = adapterManifest("0.3.0", Tool.readOnly("update_issue"));
        submit(manifest);
        String hash = hash(manifest, "update_issue");

        assertThat(adapterService.approve(requestId, SERVER, "update_issue", hash, false, admin()))
                .isEqualTo(new Approval.Rejected("classification_required", "update_issue comes from an adapter and needs risk and action"));
        assertThat(adapterService.approve(requestId, SERVER, "update_issue", hash, false, new Classification("UPDATE", null), admin()))
                .as("half a classification").isInstanceOfSatisfying(Approval.Rejected.class, r -> assertThat(r.reason()).isEqualTo("classification_required"));
        assertThat(adapterService.approve(requestId, SERVER, "update_issue", hash, false, new Classification("READ_ONLY", "delete"), admin()))
                .isInstanceOfSatisfying(Approval.Rejected.class, r -> assertThat(r.reason()).isEqualTo("classification_inconsistent"));

        for (Classification writes : List.of(new Classification("UPDATE", "update"), new Classification("UPDATE", "admin"),
                new Classification("DESTRUCTIVE", "delete"))) {
            assertThat(adapterService.approve(requestId, SERVER, "update_issue", hash, false, writes, admin()))
                    .as("a tool of an adapter is read only (CC-227)")
                    .isInstanceOfSatisfying(Approval.Rejected.class, r -> assertThat(r.reason()).isEqualTo("classification_not_allowed"));
        }

        assertThat(adapterService.approve(requestId, SERVER, "update_issue", hash, false, new Classification("READ_ONLY", "read"), admin()))
                .isEqualTo(new Approval.Approved(-1));

        RegisteredTool.Approved approved = tool("update_issue").approved();
        assertThat(approved.entry().path("risk").asString()).isEqualTo("READ_ONLY");
        assertThat(approved.entry().path("action").asString()).isEqualTo("read");
        assertThat(approved.classifiedBy()).isEqualTo(ADMIN_SUB);
        assertThat(approved.classifiedAt()).isNotNull();
        assertThat(approved.hash()).as("the classification is outside the hash").isEqualTo(hash);
        McpServer server = adapterServers.find(SERVER).orElseThrow();
        assertThat(server.tools().get("update_issue").risk().name()).isEqualTo("READ_ONLY");
        JsonNode event = auditEvents(output, requestId).stream().filter(e -> "definition_approved".equals(e.path("reason").asString())).findFirst().orElseThrow();
        assertThat(event.path("risk").asString()).isEqualTo("READ_ONLY");
        assertThat(event.path("action").asString()).isEqualTo("read");
        assertThat(event.path("sub").asString()).isEqualTo(ADMIN_SUB);
        assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", event)).isEmpty();
        assertThat(new DefinitionCheck(JSON).intact(server, server.tools().get("update_issue"), Manifests.definition(Tool.readOnly("update_issue"))))
                .as("the live definition is compared with a hash that has no risk and no action").isTrue();
    }

    @Test
    void aClassifiedToolKeepsItsClassificationWhenTheSameManifestComesAgain() {
        ObjectNode manifest = adapterManifest("0.3.0", Tool.readOnly("update_issue"));
        submit(manifest);
        adapterService.approve(requestId, SERVER, "update_issue", hash(manifest, "update_issue"), false, new Classification("READ_ONLY", "read"), admin());

        submit(adapterManifest("0.3.1", Tool.readOnly("update_issue")));

        assertThat(tool("update_issue").pending()).isNull();
        assertThat(tool("update_issue").approved().classifiedBy()).isEqualTo(ADMIN_SUB);
        assertThat(adapterServers.find(SERVER).orElseThrow().tools()).containsKey("update_issue");
    }

    @Test
    void aChangedDefinitionIsPendingAgainAndTheEarlierClassificationIsOnlyASuggestion() {
        ObjectNode first = adapterManifest("0.3.0", Tool.readOnly("update_issue"));
        submit(first);
        adapterService.approve(requestId, SERVER, "update_issue", hash(first, "update_issue"), false, new Classification("READ_ONLY", "read"), admin());

        ObjectNode changed = adapterManifest("0.4.0", Tool.readOnly("update_issue").described("Changes the issue and more."));
        submit(changed);

        RegisteredTool current = tool("update_issue");
        assertThat(current.pending().change()).isEqualTo("changed");
        assertThat(current.pending().entry().has("risk")).as("the suggestion is in the approved entry, not applied").isFalse();
        assertThat(current.approved().entry().path("risk").asString()).isEqualTo("READ_ONLY");
        assertThat(adapterService.approve(requestId, SERVER, "update_issue", hash(changed, "update_issue"), false, admin()))
                .isInstanceOfSatisfying(Approval.Rejected.class, r -> assertThat(r.reason()).isEqualTo("classification_required"));
    }

    /** What the migration V10 leaves for a classification UPDATE of an earlier version: the floor of the risk (ordinal 1). */
    private void voidedUpdateClassification(String tool) {
        jdbc.sql("INSERT INTO registry_risk_floor (server_id, tool, risk) VALUES (?, ?, 1) ON CONFLICT (server_id, tool) DO UPDATE SET risk = 1")
                .params(SERVER, tool).update();
    }

    @Test
    void aVoidedClassificationStaysTheFloorSoReadOnlyIsALowering(CapturedOutput output) {
        ObjectNode manifest = adapterManifest("0.3.0", Tool.readOnly("update_issue"));
        submit(manifest);
        voidedUpdateClassification("update_issue");
        String hash = hash(manifest, "update_issue");

        assertThat(adapterService.approve(requestId, SERVER, "update_issue", hash, false, new Classification("READ_ONLY", "read"), admin()))
                .isInstanceOf(Approval.RiskLowered.class);
        assertThat(adapterService.approve(requestId, SERVER, "update_issue", hash, true, new Classification("READ_ONLY", "read"), admin()))
                .isEqualTo(new Approval.Approved(0));

        JsonNode event = auditEvents(output, requestId).stream().filter(e -> "risk_lowered_by_admin".equals(e.path("reason").asString())).findFirst().orElseThrow();
        assertThat(event.path("risk").asString()).isEqualTo("READ_ONLY");
        assertThat(event.path("action").asString()).isEqualTo("read");
    }

    @Test
    void theMigrationVoidsStoredWriteClassificationsAndMakesTheFloorOutOfThem(@Autowired javax.sql.DataSource dataSource) throws Exception {
        ObjectNode manifest = adapterManifest("0.3.0", Tool.readOnly("update_issue"), Tool.readOnly("get_issue"), Tool.readOnly("delete_issue"),
                Tool.readOnly("waiting_issue"));
        submit(manifest);
        // The state an earlier version could leave: classifications of an adapter, approved, with no floor written by anyone but the approval.
        for (String name : List.of("update_issue", "get_issue", "delete_issue", "waiting_issue")) {
            ObjectNode entry = ((ObjectNode) Manifests.tool(manifest, name)).deepCopy();
            String risk = switch (name) {
                case "update_issue", "waiting_issue" -> "UPDATE";
                case "delete_issue" -> "DESTRUCTIVE";
                default -> "READ_ONLY";
            };
            entry.put("risk", risk);
            entry.put("action", "UPDATE".equals(risk) ? "update" : "DESTRUCTIVE".equals(risk) ? "delete" : "read");
            RegisteredTool.Pending newer = "waiting_issue".equals(name) ? tool(name).pending() : null;
            store.locked(SERVER, tx -> {
                tx.saveTool(new RegisteredTool(name, new RegisteredTool.Approved(entry, hash(manifest, name), "0.2.0", tool(name).pending().credentialJson(),
                        "old-admin", java.time.Instant.now()), newer == null ? null : new RegisteredTool.Pending(newer.entry(), "sha256:" + "a".repeat(64),
                        "0.3.0", "changed", "adapter", newer.credentialJson())));
                return null;
            });
        }
        long counter = changeCounter();

        try (java.sql.Connection connection = dataSource.getConnection()) {
            org.springframework.jdbc.datasource.init.ScriptUtils.executeSqlScript(connection,
                    new org.springframework.core.io.ClassPathResource("db/migration/V10__adapter_read_only.sql"));
        }
        adapterService.reloadChanged();

        assertThat(changeCounter()).as("the instances that run read the registry again").isGreaterThan(counter);
        RegisteredTool voided = tool("update_issue");
        assertThat(voided.approved()).isNull();
        assertThat(voided.pending().source()).isEqualTo("adapter");
        assertThat(voided.pending().change()).isEqualTo("new");
        assertThat(voided.pending().riskLowered()).isTrue();
        assertThat(voided.pending().hash()).isEqualTo(hash(manifest, "update_issue"));
        assertThat(voided.pending().entry().has("risk")).isFalse();
        assertThat(store.floors(SERVER)).containsEntry("update_issue", 1).containsEntry("delete_issue", 2).doesNotContainKey("get_issue");
        assertThat(tool("get_issue").approved().entry().path("risk").asString()).as("a read stays classified").isEqualTo("READ_ONLY");
        assertThat(tool("waiting_issue").pending().hash()).as("a waiting entry stays as it is").isEqualTo("sha256:" + "a".repeat(64));
        assertThat(tool("waiting_issue").pending().change()).as("there is no approved entry any more").isEqualTo("new");
        assertThat(adapterServers.find(SERVER).orElseThrow().tools()).containsOnlyKeys("get_issue");
        assertThat(adapterService.approve(requestId, SERVER, "update_issue", hash(manifest, "update_issue"), false,
                new Classification("READ_ONLY", "read"), admin())).isInstanceOf(Approval.RiskLowered.class);
    }

    @Test
    void anEntryWithAWriteClassificationThatAnotherInstanceStoredIsNotServed() {
        ObjectNode manifest = adapterManifest("0.3.0", Tool.readOnly("update_issue"));
        submit(manifest);
        io.micrometer.core.instrument.simple.SimpleMeterRegistry meters = new io.micrometer.core.instrument.simple.SimpleMeterRegistry();
        adapterServers.bindTo(meters);
        ObjectNode entry = ((ObjectNode) Manifests.tool(manifest, "update_issue")).deepCopy();
        entry.put("risk", "UPDATE");
        entry.put("action", "update");
        store.locked(SERVER, tx -> {
            tx.saveTool(new RegisteredTool("update_issue", new RegisteredTool.Approved(entry, hash(manifest, "update_issue"), "0.3.0",
                    tool("update_issue").pending().credentialJson(), "old-admin", java.time.Instant.now()), null));
            return null;
        });

        adapterService.reloadChanged();

        assertThat(adapterServers.find(SERVER).orElseThrow().tools()).as("fail-closed: not served whatever the registry holds").isEmpty();
        assertThat(adapterServers.resolveForCall("regad__update_issue").orElseThrow().tool().disabled()).isTrue();
        assertThat(meters.get("mcp_gateway_registry_entries_refused_total").counter().count()).isEqualTo(1.0);
    }

    private long changeCounter() {
        return jdbc.sql("SELECT version FROM registry_changes WHERE id = 1").query(Long.class).single();
    }

    @Test
    void aToolThatLeavesTheManifestLosesItsClassificationAndComesBackNewAndUnclassified() {
        ObjectNode both = adapterManifest("0.3.0", Tool.readOnly("update_issue"), Tool.readOnly("get_issue"));
        submit(both);
        adapterService.approve(requestId, SERVER, "update_issue", hash(both, "update_issue"), false, new Classification("READ_ONLY", "read"), admin());

        submit(adapterManifest("0.4.0", Tool.readOnly("get_issue")));
        assertThat(tool("update_issue")).isNull();
        assertThat(store.floors(SERVER)).as("the floor of the risk stays").containsKey("update_issue");

        submit(both);
        RegisteredTool back = tool("update_issue");
        assertThat(back.approved()).isNull();
        assertThat(back.pending().change()).isEqualTo("new");
        assertThat(adapterServers.find(SERVER).orElseThrow().tools()).doesNotContainKey("update_issue");
    }

    @Test
    void aToolRemovedAndReturnedKeepsTheFloorOfItsVoidedClassification() {
        ObjectNode both = adapterManifest("0.3.0", Tool.readOnly("update_issue"), Tool.readOnly("get_issue"));
        submit(both);
        voidedUpdateClassification("update_issue");
        submit(adapterManifest("0.4.0", Tool.readOnly("get_issue")));
        submit(both);
        String hash = hash(both, "update_issue");

        assertThat(adapterService.approve(requestId, SERVER, "update_issue", hash, false, new Classification("READ_ONLY", "read"), admin()))
                .as("the floor of the risk outlives the tool (CC-167)").isInstanceOf(Approval.RiskLowered.class);
        assertThat(adapterService.approve(requestId, SERVER, "update_issue", hash, true, new Classification("READ_ONLY", "read"), admin()))
                .isEqualTo(new Approval.Approved(0));
    }

    @Test
    void aServerThatIsNotAnAdapterTakesNoClassification() {
        ObjectNode manifest = nativeManifest("1.4.0", Tool.update("update_issue"));
        assertThat(registerNative(manifest)).isInstanceOf(Result.Accepted.class);

        Approval refused = starterService.approve(requestId, SERVER, "update_issue", hash(manifest, "update_issue"), false,
                new Classification("UPDATE", "update"), admin());

        assertThat(refused).isInstanceOfSatisfying(Approval.Rejected.class, r -> assertThat(r.reason()).isEqualTo("classification_not_allowed"));
        assertThat(starterService.approve(requestId, SERVER, "update_issue", hash(manifest, "update_issue"), false, admin()))
                .isEqualTo(new Approval.Approved(-1));
    }

    @Test
    void aRunningServerInAdapterModeLeavesAnEntryOfTheAdapter() {
        ObjectNode manifest = adapterManifest("0.3.0", Tool.readOnly("update_issue"));
        submit(manifest);
        adapterService.approve(requestId, SERVER, "update_issue", hash(manifest, "update_issue"), false, new Classification("READ_ONLY", "read"), admin());
        McpServer server = adapterServers.find(SERVER).orElseThrow();

        Map<String, pl.aiwcorpo.mcp.gateway.registry.DefinitionGuard.Verdict> verdicts = adapterService.observe(server,
                Map.of("update_issue", Manifests.definition(Tool.readOnly("update_issue").described("Drifted."))), "9.9.9");

        assertThat(verdicts.get("update_issue")).isEqualTo(DefinitionGuard.Verdict.CHANGED);
        RegisteredTool.Pending pending = tool("update_issue").pending();
        assertThat(pending.source()).as("never server for an adapter").isEqualTo("adapter");
        assertThat(pending.entry().has("risk")).isFalse();
        assertThat(tool("update_issue").approved().entry().path("risk").asString()).as("the old classification stays as it was").isEqualTo("READ_ONLY");
    }

    // --- the vectors -----------------------------------------------------------------------------------------

    @TestFactory
    List<DynamicTest> theSubmissionsOfTheVectors() {
        List<Vectors.Vector> vectors = Vectors.of("adapter-registry");
        assertThat(vectors).hasSize(13);
        List<DynamicTest> tests = new ArrayList<>();
        for (Vectors.Vector vector : vectors) {
            JsonNode input = vector.document().path("input");
            // The certificate and the body against the path are answered before the service, in the tests of the channel over HTTP.
            if (input.has("cn") && !input.path("cn").asString().equals(("adapter".equals(input.path("channel").asString())
                    ? "mcp-adapter-" : "mcp-registry-ci-") + input.path("serverId").asString())
                    || input.has("bodyServerId")) {
                continue;
            }
            tests.add(DynamicTest.dynamicTest(vector.name(), () -> {
                clean();
                submission(vector.document());
            }));
        }
        assertThat(tests).hasSize(9);
        return tests;
    }

    private void submission(JsonNode vector) {
        JsonNode input = vector.path("input");
        JsonNode expected = vector.path("expected");
        boolean adapterMode = "adapter".equals(input.path("serverMode").asString());
        RegistryService service = adapterMode ? adapterService : starterService;
        List<Tool> before = new ArrayList<>();
        List<Tool> after = new ArrayList<>();
        List<String> removed = new ArrayList<>();
        for (JsonNode t : input.path("tools")) {
            Tool tool = new Tool(t.path("name").asString(), t.path("risk").asString(), "Does " + t.path("name").asString() + ".");
            String state = t.path("state").asString();
            if (!"new".equals(state)) {
                before.add(tool);
            }
            if ("changed".equals(state)) {
                after.add(tool.described("Changed, " + tool.name() + "."));
            } else if ("removed".equals(state)) {
                removed.add(tool.name());
            } else {
                after.add(tool);
            }
        }
        if (input.path("runtimeRead").asBoolean(false)) {
            runtimeRead(service, adapterMode, input, expected, before);
            return;
        }
        if (!before.isEmpty()) {
            if (adapterMode) {
                ObjectNode baseline = Manifests.adapter(SERVER, SYSTEM, "0.1.0", before.toArray(new Tool[0]));
                assertThat(adapterService.submitAdapter(requestId, SERVER, baseline)).isInstanceOf(Result.Accepted.class);
                for (Tool tool : before) {
                    if (!"READ_ONLY".equals(tool.risk())) {
                        continue; // an adapter has no write classification (CC-227): such a tool stays pending
                    }
                    assertThat(adapterService.approve(requestId, SERVER, tool.name(), hash(baseline, tool.name()), false,
                            new Classification("READ_ONLY", "read"), admin())).isInstanceOf(Approval.Approved.class);
                }
            } else {
                ObjectNode baseline = nativeManifest("0.1.0", before.toArray(new Tool[0]));
                assertThat(registerNative(baseline)).isInstanceOf(Result.Accepted.class);
                for (Tool tool : before) {
                    if (!"READ_ONLY".equals(tool.risk())) {
                        starterService.approve(requestId, SERVER, tool.name(), hash(baseline, tool.name()), false, admin());
                    }
                }
            }
        }
        ObjectNode manifest;
        boolean manifestFromAdapter = "adapter".equals(input.path("manifestSource").asString(null));
        Tool[] tools = after.toArray(new Tool[0]);
        manifest = manifestFromAdapter ? Manifests.adapter(SERVER, SYSTEM, "0.2.0", tools) : nativeManifest("0.2.0", tools);
        boolean adapterChannel = "adapter".equals(input.path("channel").asString());
        Result result = adapterChannel ? service.submitAdapter(requestId, SERVER, manifest) : service.register(requestId, SERVER, manifest, "ci");
        if (expected.path("status").asInt() == 422) {
            assertThat(result).isInstanceOf(Result.Rejected.class);
            assertThat(((Result.Rejected) result).reason()).isEqualTo(expected.path("reason").asString());
            assertThat(store.findServer(SERVER).map(s -> s.manifest().path("version").asString())).as("nothing is stored")
                    .isEqualTo(before.isEmpty() ? java.util.Optional.empty() : java.util.Optional.of("0.1.0"));
            return;
        }
        assertThat(result).isInstanceOf(Result.Accepted.class);
        TreeSet<String> approvedByCall = new TreeSet<>();
        TreeSet<String> pending = new TreeSet<>();
        for (Tool tool : after) {
            RegisteredTool registered = service.registered(SERVER).orElseThrow().tools().get(tool.name());
            boolean unchanged = before.stream().anyMatch(b -> b.equals(tool));
            if (registered.pending() != null) {
                pending.add(tool.name());
                assertThat(registered.pending().source()).isEqualTo(expected.path("pendingSource").asString());
            } else if (!unchanged) {
                approvedByCall.add(tool.name());
            }
        }
        assertThat(approvedByCall).isEqualTo(strings(expected.path("approvedByCall")));
        assertThat(pending).isEqualTo(strings(expected.path("pending")));
        TreeSet<String> gone = new TreeSet<>();
        removed.stream().filter(name -> service.registered(SERVER).orElseThrow().tools().get(name) == null).forEach(gone::add);
        assertThat(gone).isEqualTo(strings(expected.path("removed")));
        if (expected.has("classificationLost")) {
            TreeSet<String> lost = new TreeSet<>();
            removed.stream().filter(name -> service.registered(SERVER).orElseThrow().tools().get(name) == null).forEach(lost::add);
            assertThat(lost).isEqualTo(strings(expected.path("classificationLost")));
        }
    }

    private void runtimeRead(RegistryService service, boolean adapterMode, JsonNode input, JsonNode expected, List<Tool> approvedBefore) {
        Tool tool = approvedBefore.getFirst();
        Tool changed = tool.described("Drifted.");
        if (adapterMode) {
            ObjectNode baseline = Manifests.adapter(SERVER, SYSTEM, "0.1.0", tool);
            adapterService.submitAdapter(requestId, SERVER, baseline);
            adapterService.approve(requestId, SERVER, tool.name(), hash(baseline, tool.name()), false, new Classification("READ_ONLY", "read"), admin());
        } else {
            ObjectNode baseline = nativeManifest("0.1.0", tool);
            registerNative(baseline);
            starterService.approve(requestId, SERVER, tool.name(), hash(baseline, tool.name()), false, admin());
        }
        McpServer server = (adapterMode ? adapterServers : starterServers).find(SERVER).orElseThrow();
        service.observe(server, Map.of(tool.name(), Manifests.definition(changed)), "9.9.9");
        RegisteredTool registered = service.registered(SERVER).orElseThrow().tools().get(tool.name());
        assertThat(registered.pending()).isNotNull();
        assertThat(registered.pending().source()).isEqualTo(expected.path("pendingSource").asString());
        assertThat(expected.path("approvedByCall")).isEmpty();
    }

    private static TreeSet<String> strings(JsonNode array) {
        TreeSet<String> out = new TreeSet<>();
        array.forEach(n -> out.add(n.asString()));
        return out;
    }

    @TestFactory
    List<DynamicTest> theApprovalsOfTheVectors() {
        List<Vectors.Vector> vectors = Vectors.of("registry-approval");
        assertThat(vectors).hasSize(20);
        List<DynamicTest> tests = new ArrayList<>();
        for (Vectors.Vector vector : vectors) {
            if (vector.document().path("input").has("entry")) {
                tests.add(DynamicTest.dynamicTest(vector.name(), () -> {
                    clean();
                    approval(vector.document());
                }));
            }
        }
        assertThat(tests).hasSize(17);
        return tests;
    }

    private void approval(JsonNode vector) {
        JsonNode input = vector.path("input");
        JsonNode expected = vector.path("expected");
        String source = input.path("entry").path("source").asString();
        JsonNode body = input.path("body");
        Classification classification = body.has("risk") || body.has("action")
                ? new Classification(body.path("risk").asString(null), body.path("action").asString(null)) : null;
        boolean accept = body.path("acceptRiskLowering").asBoolean(false);
        Approval answer;
        String hash;
        if ("adapter".equals(source)) {
            // A classification given earlier is the floor: classified once, then the definition changes and is pending again.
            String floor = input.path("floor").asString(null);
            ObjectNode manifest = adapterManifest("0.1.0", Tool.readOnly("update_issue"));
            submit(manifest);
            if (floor != null) {
                // The classification of the floor was stored by an earlier version and voided (CC-227): what is left is the floor.
                int ordinal = switch (floor) {
                    case "READ_ONLY" -> 0;
                    case "UPDATE" -> 1;
                    default -> 2;
                };
                jdbc.sql("INSERT INTO registry_risk_floor (server_id, tool, risk) VALUES (?, ?, ?) ON CONFLICT (server_id, tool) DO UPDATE SET risk = EXCLUDED.risk")
                        .params(SERVER, "update_issue", ordinal).update();
            }
            hash = hash(manifest, "update_issue");
            answer = adapterService.approve(requestId, SERVER, "update_issue", hash, accept, classification, admin());
        } else {
            ObjectNode manifest = nativeManifest("0.1.0", Tool.update("update_issue"));
            if (input.path("entry").path("riskLowered").asBoolean(false)) {
                ObjectNode destructive = nativeManifest("0.1.0", Tool.destructive("update_issue"));
                registerNative(destructive);
                starterService.approve(requestId, SERVER, "update_issue", hash(destructive, "update_issue"), false, admin());
                manifest = nativeManifest("0.2.0", Tool.update("update_issue"));
            }
            registerNative(manifest);
            hash = hash(manifest, "update_issue");
            answer = starterService.approve(requestId, SERVER, "update_issue", hash, accept, classification, admin());
        }
        int status = expected.path("status").asInt();
        if (status == 204) {
            assertThat(answer).isInstanceOf(Approval.Approved.class);
            if (expected.has("classification")) {
                RegisteredTool.Approved approved = registeredTool().approved();
                assertThat(approved.entry().path("risk").asString()).isEqualTo(expected.path("classification").path("risk").asString());
                assertThat(approved.entry().path("action").asString()).isEqualTo(expected.path("classification").path("action").asString());
            }
            assertThat(((Approval.Approved) answer).loweredTo() >= 0).isEqualTo("risk_lowered_by_admin".equals(expected.path("auditReason").asString()));
        } else {
            String reason = switch (answer) {
                case Approval.Rejected rejected -> rejected.reason();
                case Approval.RiskLowered lowered -> "risk_lowered";
                default -> answer.toString();
            };
            assertThat(reason).isEqualTo(expected.path("reason").asString());
        }
    }

    private static List<String> auditReasons(CapturedOutput output, String requestId) {
        return auditEvents(output, requestId).stream().filter(e -> "admin_change".equals(e.path("event").asString()))
                .map(e -> e.path("reason").asString()).toList();
    }

    private RegisteredTool registeredTool() {
        return store.tools(SERVER).get("update_issue");
    }
}
