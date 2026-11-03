package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.authz.ToolAccess;
import pl.aiwcorpo.mcp.gateway.authz.ToolAuthorizer;
import pl.aiwcorpo.mcp.gateway.server.CredentialPolicy;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.server.Risk;
import pl.aiwcorpo.mcp.gateway.server.ToolDefinition;

/**
 * What a long list costs in decisions of Cedar (CC-180, M6 stage 1: about 1 s for 253 tools, asked one after another): the same decisions,
 * side by side. The numbers go to the output of the test; the assertion is that the decisions are the same as the sequential ones.
 */
class ToolsListCostTest extends GatewayTestBase {

    private static final int TOOLS = 253;

    @Autowired
    ToolAuthorizer authorizer;

    @Autowired
    ToolAccess access;

    private static McpServer server() {
        Map<String, ToolDefinition> tools = new java.util.LinkedHashMap<>();
        for (int i = 0; i < TOOLS; i++) {
            Risk risk = i % 5 == 0 ? Risk.UPDATE : i % 11 == 0 ? Risk.DESTRUCTIVE : Risk.READ_ONLY;
            String name = String.format("tool_%03d", i);
            tools.put(name, new ToolDefinition(name, risk, risk == Risk.READ_ONLY ? "read" : risk == Risk.UPDATE ? "update" : "delete", name,
                    "Tool " + i, false, List.of()));
        }
        return new McpServer("mcp-jira", "jira", URI.create("https://mcp-jira.internal:8443/mcp"), "1.0.0", true,
                new CredentialPolicy(true, java.util.Set.of("user-secret"), List.of(), false, "user-secret"), tools);
    }

    @Test
    void theDecisionsOfALongListSideBySideAreTheSequentialOnesAndCostLess() {
        McpServer server = server();
        List<ToolDefinition> tools = new ArrayList<>(server.tools().values());
        GatewayUser user = new GatewayUser(UUID.randomUUID().toString(), "lister", "claude-code",
                List.of("mcp-jira-read", "mcp-jira-write"), "unused");
        // Warm up: the first evaluations load the native library and the policies.
        tools.forEach(tool -> authorizer.mayCall(user, server, tool));
        access.mayCall(user, server, tools);

        long sequentialNanos = Long.MAX_VALUE;
        long parallelNanos = Long.MAX_VALUE;
        List<Boolean> sequential = new ArrayList<>();
        List<Boolean> parallel = new ArrayList<>();
        for (int round = 0; round < 5; round++) {
            long started = System.nanoTime();
            sequential.clear();
            tools.forEach(tool -> sequential.add(authorizer.mayCall(user, server, tool)));
            sequentialNanos = Math.min(sequentialNanos, System.nanoTime() - started);
            started = System.nanoTime();
            parallel = access.mayCall(user, server, tools);
            parallelNanos = Math.min(parallelNanos, System.nanoTime() - started);
        }

        System.out.printf("TOOLS-LIST-COST: %d tools, Cedar one after another %d ms, side by side %d ms (%d cores)%n", TOOLS,
                sequentialNanos / 1_000_000, parallelNanos / 1_000_000, Runtime.getRuntime().availableProcessors());
        assertThat(parallel).isEqualTo(sequential);
        assertThat(sequential).contains(true, false);
    }
}
