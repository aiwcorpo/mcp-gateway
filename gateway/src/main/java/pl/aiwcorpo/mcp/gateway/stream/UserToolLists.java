package pl.aiwcorpo.mcp.gateway.stream;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.authz.ToolAccess;
import pl.aiwcorpo.mcp.gateway.killswitch.KillSwitches;
import pl.aiwcorpo.mcp.gateway.registry.DefinitionGuard;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.server.ServerRegistry;
import pl.aiwcorpo.mcp.gateway.server.ToolDefinition;

/**
 * The list of tools of a user as the gateway knows it without asking any server: what is approved, switched on, not switched off by an
 * emergency switch, still the approved definition on the last reading of its server, and allowed by Cedar at the level of the tool. It is
 * the snapshot a stream compares (CC-192); the {@code tools/list} of a client reads the servers and is the truth, this is what lets the
 * gateway notice that it changed. The order is the one of the list: by server, then by tool name.
 */
public final class UserToolLists {

    private final ServerRegistry servers;
    private final ToolAccess access;
    private final KillSwitches killSwitches;
    private final DefinitionGuard guard;

    public UserToolLists(ServerRegistry servers, ToolAccess access, KillSwitches killSwitches, DefinitionGuard guard) {
        this.servers = servers;
        this.access = access;
        this.killSwitches = killSwitches;
        this.guard = guard;
    }

    public List<ListChangeTracker.Tool> of(GatewayUser user) {
        List<ListChangeTracker.Tool> out = new ArrayList<>();
        for (McpServer server : servers.all().stream().sorted(Comparator.comparing(McpServer::serverId)).toList()) {
            List<ToolDefinition> candidates = server.tools().values().stream()
                    .filter(tool -> server.enabled() && !tool.disabled())
                    .filter(tool -> killSwitches.status(server.serverId(), tool.name()) == KillSwitches.Status.OFF)
                    .filter(tool -> !server.approvalRequired() || guard.lastKnownIntact(server.serverId(), tool.name()))
                    .sorted(Comparator.comparing(ToolDefinition::name)).toList();
            List<Boolean> allowed = access.mayCall(user, server, candidates);
            for (int i = 0; i < candidates.size(); i++) {
                if (allowed.get(i)) {
                    ToolDefinition tool = candidates.get(i);
                    out.add(new ListChangeTracker.Tool(server.qualifiedName(tool), tool.risk().name(), tool.definitionHash()));
                }
            }
        }
        return out;
    }
}
