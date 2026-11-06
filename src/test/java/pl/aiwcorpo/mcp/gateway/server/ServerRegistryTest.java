package pl.aiwcorpo.mcp.gateway.server;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import pl.aiwcorpo.mcp.gateway.registry.RegisteredTool;
import pl.aiwcorpo.mcp.gateway.registry.ServerConfig;
import pl.aiwcorpo.mcp.gateway.support.Manifests;
import tools.jackson.databind.JsonNode;

class ServerRegistryTest {

    private static final ServerConfig JIRA = config("mcp-jira", "jira", "user-secret", true, false);

    private static ServerConfig config(String serverId, String system, String type, boolean enabled, boolean adapter) {
        return new ServerConfig(serverId, system, URI.create("https://" + serverId + ".internal:8443/mcp"), serverId + ".internal",
                new ServerConfig.Credential(true, List.of(type), type), enabled, adapter);
    }

    private static Map<String, RegisteredTool> approved(Manifests.Tool... tools) {
        Map<String, RegisteredTool> registered = new java.util.LinkedHashMap<>();
        for (JsonNode entry : Manifests.jira("1.2.3", tools).path("tools")) {
            registered.put(entry.path("name").asString(), new RegisteredTool(entry.path("name").asString(),
                    new RegisteredTool.Approved(entry, entry.path("definitionHash").asString(), "1.2.3", "{}"), null));
        }
        return registered;
    }

    private static ServerRegistry registry(boolean policiesApproved, Manifests.Tool... tools) {
        ServerRegistry registry = new ServerRegistry();
        registry.replaceConfigs(List.of(JIRA));
        registry.apply("mcp-jira", new ServerRegistry.Applied("1.2.3", approved(tools), Map.of(), true, policiesApproved));
        return registry;
    }

    @Test
    void aServerWithoutAManifestIsKnownButHasNoTools() {
        ServerRegistry registry = new ServerRegistry();
        registry.replaceConfigs(List.of(JIRA));
        assertThat(registry.find("mcp-jira")).hasValueSatisfying(server -> {
            assertThat(server.tools()).isEmpty();
            assertThat(server.tlsName()).isEqualTo("mcp-jira.internal");
        });
        assertThat(registry.resolve("jira__get_issue")).isEmpty();
    }

    @Test
    void resolvesClientNamesToServerAndTool() {
        ServerRegistry registry = registry(true, Manifests.Tool.readOnly("get_issue"));
        ServerRegistry.Resolved resolved = registry.resolve("jira__get_issue").orElseThrow();
        assertThat(resolved.server().serverId()).isEqualTo("mcp-jira");
        assertThat(resolved.tool().action()).isEqualTo("read");
        for (String name : new String[] {null, "", "get_issue", "__get_issue", "jira_get_issue", "jira__nope", "gitlab__get_issue",
                "jira__get_issue__x", "Jira__get_issue"}) {
            assertThat(registry.resolve(name)).as(String.valueOf(name)).isEmpty();
        }
    }

    @Test
    void theActionComesFromTheApprovedEntry() {
        assertThat(registry(true, Manifests.Tool.update("t")).resolve("jira__t").orElseThrow().tool().action()).isEqualTo("update");
        assertThat(registry(true, Manifests.Tool.destructive("t")).resolve("jira__t").orElseThrow().tool().action()).isEqualTo("delete");
    }

    @Test
    void whilePoliciesWaitForApprovalEveryToolIsKnownAsDisabledAndListedNowhere() {
        ServerRegistry registry = registry(false, Manifests.Tool.readOnly("get_issue"));
        assertThat(registry.find("mcp-jira").orElseThrow().tools()).isEmpty();
        assertThat(registry.resolve("jira__get_issue")).isEmpty();
        assertThat(registry.resolveForCall("jira__get_issue")).hasValueSatisfying(found -> assertThat(found.tool().disabled()).isTrue());
    }

    @Test
    void aToolBelowAnEarlierApprovalIsNotServed() {
        ServerRegistry registry = new ServerRegistry();
        registry.replaceConfigs(List.of(JIRA));
        registry.apply("mcp-jira", new ServerRegistry.Applied("1.2.3", approved(Manifests.Tool.readOnly("t")), Map.of("t", 1), true, true));
        assertThat(registry.resolveForCall("jira__t")).isEmpty();
    }

    @Test
    void theCredentialTypeOfTheContextIsTheTypeOfTheServer() {
        assertThat(credentialType(new ServerConfig.Credential(true, List.of("user-secret"), "user-secret"))).isEqualTo("user-secret");
        assertThat(credentialType(new ServerConfig.Credential(true, List.of("user-oauth", "user-secret"), "user-oauth"))).isEqualTo("user-oauth");
        assertThat(credentialType(new ServerConfig.Credential(false, List.of("user-secret"), "user-secret"))).as("no credential, no type").isNull();
        ServerRegistry registry = new ServerRegistry();
        registry.replaceConfigs(List.of(new ServerConfig("mcp-opensearch", "opensearch", URI.create("https://mcp-opensearch.internal:8443/mcp"),
                "mcp-opensearch.internal", new ServerConfig.Credential(true, List.of("token-exchange"), "token-exchange"), true, false)));
        assertThat(registry.find("mcp-opensearch").orElseThrow().credential().tokenExchange()).isTrue();
    }

    private static String credentialType(ServerConfig.Credential credential) {
        ServerRegistry registry = new ServerRegistry();
        registry.replaceConfigs(List.of(new ServerConfig("mcp-jira", "jira", URI.create("https://mcp-jira.internal:8443/mcp"),
                "mcp-jira.internal", credential, true, false)));
        return registry.find("mcp-jira").orElseThrow().credential().type();
    }

    @Test
    void aServerThatLeavesTheListLeavesWithItsTools() {
        ServerRegistry registry = registry(true, Manifests.Tool.readOnly("get_issue"));
        registry.replaceConfigs(List.of());
        assertThat(registry.find("mcp-jira")).isEmpty();
        assertThat(registry.resolveForCall("jira__get_issue")).isEmpty();
        registry.replaceConfigs(List.of(JIRA));
        assertThat(registry.find("mcp-jira").orElseThrow().tools()).as("a server added again starts without what the old one had").isEmpty();
    }

    @Test
    void aChangeOfSettingsKeepsTheApprovedTools() {
        ServerRegistry registry = registry(true, Manifests.Tool.readOnly("get_issue"));
        registry.replaceConfigs(List.of(config("mcp-jira", "jira", "user-secret", false, false)));
        McpServer server = registry.find("mcp-jira").orElseThrow();
        assertThat(server.enabled()).isFalse();
        assertThat(server.tools()).containsKey("get_issue");
    }

    @Test
    void aManifestThatFailsTheChecksDisablesTheServer() {
        ServerRegistry registry = new ServerRegistry();
        registry.replaceConfigs(List.of(JIRA));
        registry.apply("mcp-jira", new ServerRegistry.Applied("1.2.3", approved(Manifests.Tool.readOnly("t")), Map.of(), false, true));
        assertThat(registry.find("mcp-jira").orElseThrow().enabled()).isFalse();
    }

    @Test
    void aToolOfAnAdapterIsReadOnly() {
        ServerRegistry registry = new ServerRegistry();
        registry.replaceConfigs(List.of(config("mcp-jira", "jira", "user-secret", true, true)));
        registry.apply("mcp-jira", new ServerRegistry.Applied("1.2.3", approved(Manifests.Tool.update("t")), Map.of(), true, true));
        assertThat(registry.resolve("jira__t")).as("approved as UPDATE behind an adapter: not served").isEmpty();
    }
}
