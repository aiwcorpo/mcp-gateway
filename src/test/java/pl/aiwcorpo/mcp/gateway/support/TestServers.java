package pl.aiwcorpo.mcp.gateway.support;

import java.util.List;

import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;

import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.jwt.UuidV7;
import pl.aiwcorpo.mcp.gateway.registry.DevBootstrap;
import pl.aiwcorpo.mcp.gateway.registry.RegistryService;
import pl.aiwcorpo.mcp.gateway.registry.RegistryStore;
import pl.aiwcorpo.mcp.gateway.registry.ServerAdmin;
import pl.aiwcorpo.mcp.gateway.registry.ServerChecks;
import pl.aiwcorpo.mcp.gateway.server.ServerRegistry;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * The tools of the servers a test gateway starts with, taken as soon as the gateway serves (the servers fetch its keys from the internal
 * port). The servers themselves are rows of the registry ({@link GatewayTestEnvironment#servers()}). Two kinds:
 *
 * <ul>
 * <li>the servers that can be reached are looked at (the connection, the manifest) and everything is approved, as the dev stack does
 *     ({@link DevBootstrap}): connection, policies and tools;</li>
 * <li>mcp-confluence (it presents another certificate than the one its approved connection pins) and the disabled mcp-servicedesk cannot
 *     be read, so their one read-only tool is handed to the registry as a pulled manifest and approved by an administrator.</li>
 * </ul>
 */
@TestConfiguration
public class TestServers {

    private static final GatewayUser ADMINISTRATOR = new GatewayUser("0d6a7e2c-9c1b-4a0e-8f55-3b2d1c0e9f33", "test-seed", "mcp-portal-bff",
            List.of("mcp-platform-admin"), "unused");

    @Bean
    ApplicationListener<ApplicationReadyEvent> testServerTools(RegistryService registry, ServerChecks checks, ServerAdmin admin,
                                                               ServerRegistry servers, RegistryStore store, JsonMapper json) {
        return event -> {
            DevBootstrap bootstrap = new DevBootstrap(servers, registry, admin, store, json);
            for (int attempt = 0; attempt < 80 && !approved(registry, "mcp-jira", "mcp-gitlab"); attempt++) {
                checks.check(UuidV7.next(), "mcp-jira");
                checks.check(UuidV7.next(), "mcp-gitlab");
                bootstrap.run();
                if (!approved(registry, "mcp-jira", "mcp-gitlab")) {
                    try {
                        Thread.sleep(250);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                }
            }
            // The tool is in the manifest the gateway took; the server serves it only while a test turns it on, as the static tool of 1.x.
            GatewayTestEnvironment.get().jira.updateTool(false);
            register(registry, "mcp-confluence", "confluence", "1.0.0", Manifests.Tool.readOnly("search_issues"));
            register(registry, "mcp-servicedesk", "servicedesk", "2.1.0", Manifests.Tool.readOnly("get_ticket"));
        };
    }

    private static boolean approved(RegistryService registry, String... serverIds) {
        for (String serverId : serverIds) {
            if (registry.registered(serverId).map(state -> state.policies().approved()).orElse(false) == false) {
                return false;
            }
        }
        return true;
    }

    private static void register(RegistryService registry, String serverId, String system, String version, Manifests.Tool tool) {
        if (approved(registry, serverId)) {
            return;
        }
        ObjectNode manifest = Manifests.manifest(serverId, system, version, List.of(Manifests.USER_SECRET), tool);
        registry.applyPulled(UuidV7.next(), serverId, manifest);
        registry.approvePolicies(UuidV7.next(), serverId, manifest.path("policiesHash").asString(), ADMINISTRATOR);
        registry.approve(UuidV7.next(), serverId, tool.name(), Manifests.tool(manifest, tool.name()).path("definitionHash").asString(), false,
                ADMINISTRATOR);
    }
}
