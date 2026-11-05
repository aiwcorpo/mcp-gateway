package pl.aiwcorpo.mcp.gateway.stream;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

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
 *
 * <p>The decisions of Cedar are what a list costs. They are kept per identity (sub, name, client, groups) for as long as the policies are
 * the same ({@link #policiesChanged}), each under the fingerprint of the tool it was made for. A change of a switch, of the readings of a
 * server or of the tools of one server then costs no decision of Cedar for the tools that did not change, and the streams of one identity
 * share what the first of them computed. The identity includes the sub: a policy may name a principal, so users with the same groups do not
 * share decisions. Lists use the background lane of {@link ToolAccess}, apart from the slots clients wait for.
 */
public final class UserToolLists {

    private static final int MAX_IDENTITIES = 10_000;

    private record Identity(String sub, String username, String client, List<String> groups) {
    }

    /** The decisions made for one identity; {@code policies} is the generation of the policies they were made under. */
    private static final class Decisions {
        long policies = -1;
        final Map<String, Boolean> byFingerprint = new HashMap<>();
    }

    private final ServerRegistry servers;
    private final ToolAccess access;
    private final KillSwitches killSwitches;
    private final DefinitionGuard guard;
    private final AtomicLong policyGeneration = new AtomicLong();
    private final Map<Identity, Decisions> identities = new LinkedHashMap<>(256, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<Identity, Decisions> eldest) {
            return size() > MAX_IDENTITIES;
        }
    };

    public UserToolLists(ServerRegistry servers, ToolAccess access, KillSwitches killSwitches, DefinitionGuard guard) {
        this.servers = servers;
        this.access = access;
        this.killSwitches = killSwitches;
        this.guard = guard;
    }

    /** A new bundle of policies was accepted: no decision made before it counts any more. */
    public void policiesChanged() {
        policyGeneration.incrementAndGet();
    }

    public List<ListChangeTracker.Tool> of(GatewayUser user) {
        Decisions decisions;
        synchronized (identities) {
            decisions = identities.computeIfAbsent(new Identity(user.sub(), user.username(), user.client(), user.mcpGroups()), k -> new Decisions());
        }
        List<ListChangeTracker.Tool> out = new ArrayList<>();
        // One computation per identity at a time: the second stream of an identity waits for the first and finds its decisions.
        synchronized (decisions) {
            long generation = policyGeneration.get();
            if (decisions.policies != generation) {
                decisions.byFingerprint.clear();
                decisions.policies = generation;
            }
            for (McpServer server : servers.all().stream().sorted(Comparator.comparing(McpServer::serverId)).toList()) {
                List<ToolDefinition> candidates = server.tools().values().stream()
                        .filter(tool -> server.enabled() && !tool.disabled())
                        .filter(tool -> killSwitches.status(server.serverId(), tool.name()) == KillSwitches.Status.OFF)
                        .filter(tool -> !server.approvalRequired() || guard.lastKnownIntact(server.serverId(), tool.name()))
                        .sorted(Comparator.comparing(ToolDefinition::name)).toList();
                List<ToolDefinition> unknown = candidates.stream()
                        .filter(tool -> !decisions.byFingerprint.containsKey(fingerprint(server, tool))).toList();
                if (!unknown.isEmpty()) {
                    List<Boolean> made = access.mayCall(user, server, unknown, ToolAccess.Lane.BACKGROUND);
                    for (int i = 0; i < unknown.size(); i++) {
                        decisions.byFingerprint.put(fingerprint(server, unknown.get(i)), made.get(i));
                    }
                }
                for (ToolDefinition tool : candidates) {
                    if (decisions.byFingerprint.get(fingerprint(server, tool))) {
                        out.add(new ListChangeTracker.Tool(server.qualifiedName(tool), tool.risk().name(), tool.definitionHash()));
                    }
                }
            }
        }
        return out;
    }

    /** Everything the decision of Cedar at the level of the tool depends on besides the identity and the policies. */
    private static String fingerprint(McpServer server, ToolDefinition tool) {
        return server.serverId() + "|" + tool.name() + "|" + tool.risk() + "|" + tool.action() + "|" + server.credential().type() + "|"
                + tool.resourceRefs();
    }
}
