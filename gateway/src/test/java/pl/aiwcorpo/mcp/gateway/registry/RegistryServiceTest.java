package pl.aiwcorpo.mcp.gateway.registry;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import pl.aiwcorpo.mcp.gateway.config.GatewayProperties;
import pl.aiwcorpo.mcp.gateway.server.ServerRegistry;
import pl.aiwcorpo.mcp.gateway.support.Vectors;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** The decisions of the registry service around a store that is mocked: drift of the stored state and the bootstrap. */
class RegistryServiceTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    private final RegistryStore store = mock(RegistryStore.class);
    private final ManifestFetcher fetcher = mock(ManifestFetcher.class);
    private final ServerRegistry servers = new ServerRegistry(Map.of("mcp-jira", new GatewayProperties.Server("jira",
            URI.create("https://mcp-jira.internal:8443/mcp"), "1.0.0", true, "required",
            new GatewayProperties.Credential(true, List.of("user-secret"), List.of(), false),
            Map.of("delete_issue", new GatewayProperties.Tool("DESTRUCTIVE", "Deletes.", null, null, false, List.of())))), "static");
    private final RegistryService service = new RegistryService(servers, store, new ManifestValidator(JSON), fetcher,
            new DefinitionGuard(Clock.systemUTC(), Duration.ofSeconds(30)));

    private static JsonNode junk() {
        return JSON.createObjectNode().put("serverId", "mcp-jira").put("system", "jira");
    }

    @Test
    void aStoredManifestThatIsNoLongerAcceptableLeavesTheServerWithoutToolsAndWithoutABootstrap() {
        when(store.all()).thenReturn(List.of(new RegistryStore.Stored("mcp-jira", junk(), "ci")));
        when(store.find("mcp-jira")).thenReturn(Optional.of(new RegistryStore.Stored("mcp-jira", junk(), "ci")));

        service.load();
        service.bootstrapMissing();

        assertThat(servers.find("mcp-jira").orElseThrow().tools()).isEmpty();
        assertThat(service.approved("mcp-jira")).isEmpty();
        verify(fetcher, never()).fetch(any());
        verify(store, never()).write(any(), any(), any(), any(), any(), org.mockito.ArgumentMatchers.anyBoolean());
    }

    @Test
    void theRisksOfAnUnacceptableStoredManifestStillRaiseTheFloors() {
        JsonNode stored = JSON.createObjectNode().put("serverId", "mcp-jira");
        ((tools.jackson.databind.node.ObjectNode) stored).putArray("tools").addObject().put("name", "delete_issue").put("risk", "DESTRUCTIVE");
        when(store.all()).thenReturn(List.of(new RegistryStore.Stored("mcp-jira", stored, "ci")));

        service.load();

        verify(store).raiseFloors("mcp-jira", Map.of("delete_issue", 2));
    }

    @Test
    void theBootstrapOfAServerWithoutAnyRowIsInsertOnlyAndAnExistingApprovalWins() {
        when(store.find("mcp-jira")).thenReturn(Optional.empty());
        when(fetcher.fetch(any())).thenReturn(Optional.of(JSON.createObjectNode()));

        service.bootstrapMissing();

        // The manifest is refused before the store (not a manifest); the store is not asked to write.
        verify(store, never()).write(any(), any(), any(), any(), any(), org.mockito.ArgumentMatchers.anyBoolean());
        assertThat(service.approved("mcp-jira")).isEmpty();
    }

    @Test
    void aStoredManifestBelowTheConfiguredMinimumRiskDoesNotServeTheTool() {
        // The configuration (a later change by the operator) says get_issue is DESTRUCTIVE; the stored approval says READ_ONLY.
        ServerRegistry raised = new ServerRegistry(Map.of("mcp-jira", new GatewayProperties.Server("jira",
                URI.create("https://mcp-jira.internal:8443/mcp"), "1.0.0", true, "required",
                new GatewayProperties.Credential(true, List.of("user-secret"), List.of(), false),
                Map.of("get_issue", new GatewayProperties.Tool("DESTRUCTIVE", "Gets.", null, null, false, List.of())))), "static");
        RegistryService restarted = new RegistryService(raised, store, new ManifestValidator(JSON), fetcher,
                new DefinitionGuard(Clock.systemUTC(), Duration.ofSeconds(30)));
        JsonNode manifest = Vectors.of("manifests").stream().filter(v -> v.name().equals("valid-jira.json")).findFirst().orElseThrow()
                .document().path("manifest");
        when(store.all()).thenReturn(List.of(new RegistryStore.Stored("mcp-jira", manifest, "ci")));
        when(store.floors("mcp-jira")).thenReturn(Map.of());

        restarted.load();

        assertThat(raised.find("mcp-jira").orElseThrow().tools()).doesNotContainKey("get_issue").containsKey("search_issues");
    }

    @Test
    void aStoredManifestBelowTheHighestApprovedRiskDoesNotServeTheTool() {
        JsonNode manifest = Vectors.of("manifests").stream().filter(v -> v.name().equals("valid-jira.json")).findFirst().orElseThrow()
                .document().path("manifest");
        when(store.all()).thenReturn(List.of(new RegistryStore.Stored("mcp-jira", manifest, "ci")));
        when(store.floors("mcp-jira")).thenReturn(Map.of("update_issue", 2));

        service.load();

        assertThat(servers.find("mcp-jira").orElseThrow().tools()).doesNotContainKey("update_issue").containsKey("get_issue");
    }

    @Test
    void theConfigurationNamesTheMinimumRiskOfItsTools() {
        assertThat(servers.configuredMinimumRisks("mcp-jira")).isEqualTo(Map.of("delete_issue", 2));
    }
}
