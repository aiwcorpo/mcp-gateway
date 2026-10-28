package pl.aiwcorpo.mcp.gateway.server;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import pl.aiwcorpo.mcp.gateway.config.GatewayProperties;

class ServerRegistryTest {

    @Test
    void resolvesClientNamesToServerAndTool() {
        ServerRegistry registry = registry("1.2.3", "get_issue", "READ_ONLY", null);
        ServerRegistry.Resolved resolved = registry.resolve("jira__get_issue").orElseThrow();
        assertThat(resolved.server().serverId()).isEqualTo("mcp-jira");
        assertThat(resolved.tool().action()).isEqualTo("read");
        assertThat(resolved.tool().title()).isNull();
        for (String name : new String[] {null, "", "get_issue", "__get_issue", "jira_get_issue", "jira__nope", "gitlab__get_issue",
                "jira__get_issue__x", "Jira__get_issue"}) {
            assertThat(registry.resolve(name)).as(String.valueOf(name)).isEmpty();
        }
    }

    @Test
    void actionDefaultsFromTheRiskAndCanBeSetExplicitly() {
        assertThat(registry("1.0.0", "t", "UPDATE", null).resolve("jira__t").orElseThrow().tool().action()).isEqualTo("update");
        assertThat(registry("1.0.0", "t", "DESTRUCTIVE", null).resolve("jira__t").orElseThrow().tool().action()).isEqualTo("delete");
        assertThat(registry("1.0.0", "t", "READ_ONLY", "admin").resolve("jira__t").orElseThrow().tool().action()).isEqualTo("admin");
    }

    @Test
    void invalidConfigurationStopsStart() {
        assertThatThrownBy(() -> registry("1.0", "t", "READ_ONLY", null)).hasMessageContaining("SemVer");
        assertThatThrownBy(() -> registry("1.0.0", "t", "READ_ONLY", "own")).hasMessageContaining("action");
        assertThatThrownBy(() -> registry("1.0.0", "T", "READ_ONLY", null)).hasMessageContaining("invalid tool name");
        assertThatThrownBy(() -> registry("1.0.0", "t", "SAFE", null)).hasMessageContaining("risk");
    }

    private static ServerRegistry registry(String version, String tool, String risk, String action) {
        return new ServerRegistry(Map.of("mcp-jira", new GatewayProperties.Server("jira",
                URI.create("https://mcp-jira.internal:8443/mcp"), version, true, "static",
                new GatewayProperties.Credential(true, List.of("user-secret"), List.of(), false),
                Map.of(tool, new GatewayProperties.Tool(risk, "Description.", null, action, false, List.of())))), "static");
    }
}
