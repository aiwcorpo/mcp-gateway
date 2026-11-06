package pl.aiwcorpo.mcp.gateway.support;

import java.util.List;

import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;

import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.jwt.UuidV7;
import pl.aiwcorpo.mcp.gateway.registry.RegistryService;
import tools.jackson.databind.node.ObjectNode;

/**
 * The tools of the servers a test gateway starts with, taken as soon as the gateway serves (the servers fetch its keys from the internal port). The servers themselves are rows of the registry
 * ({@link GatewayTestEnvironment#servers()}). Two kinds of tools:
 *
 * <ul>
 * <li>the servers that can be reached take the manifest they serve, as the dev stack does ({@code RegistryService#bootstrapMissing}):
 *     tools and policies are approved on first use;</li>
 * <li>mcp-confluence (a certificate of the wrong name) and the disabled mcp-servicedesk cannot be read, so their one read-only tool is
 *     registered as a pipeline would and their policies are approved by an administrator.</li>
 * </ul>
 */
@TestConfiguration
public class TestServers {

    @Bean
    ApplicationListener<ApplicationReadyEvent> testServerTools(RegistryService registry) {
        return event -> {
            for (int attempt = 0; attempt < 80 && !(registry.registered("mcp-jira").isPresent() && registry.registered("mcp-gitlab").isPresent()); attempt++) {
                registry.bootstrapMissing();
                if (registry.registered("mcp-jira").isEmpty() || registry.registered("mcp-gitlab").isEmpty()) {
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
            register(registry, "mcp-confluence", "confluence", "1.0.0", 0, Manifests.Tool.readOnly("search_issues"));
            register(registry, "mcp-servicedesk", "servicedesk", "2.1.0", 9, Manifests.Tool.readOnly("get_ticket"));
        };
    }

    private static void register(RegistryService registry, String serverId, String system, String version, int port,
                                 Manifests.Tool... tools) {
        if (registry.registered(serverId).isPresent()) {
            return;
        }
        GatewayTestEnvironment env = GatewayTestEnvironment.get();
        ObjectNode manifest = Manifests.manifest(serverId, system, version, List.of(Manifests.USER_SECRET), tools);
        int actual = port == 0 ? env.wrongName.port() : port;
        manifest.put("internalUrl", "https://" + serverId + ".internal:" + actual + "/mcp");
        registry.register(UuidV7.next(), serverId, manifest, "ci");
        GatewayUser administrator = new GatewayUser("0d6a7e2c-9c1b-4a0e-8f55-3b2d1c0e9f33", "test-seed", "mcp-portal-bff",
                List.of("mcp-platform-admin"), "unused");
        registry.approvePolicies(UuidV7.next(), serverId, manifest.path("policiesHash").asString(), administrator);
    }
}
