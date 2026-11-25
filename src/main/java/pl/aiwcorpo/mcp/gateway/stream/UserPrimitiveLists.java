package pl.aiwcorpo.mcp.gateway.stream;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BiPredicate;

import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.authz.ToolAuthorizer;
import pl.aiwcorpo.mcp.gateway.killswitch.KillSwitches;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.server.PromptDefinition;
import pl.aiwcorpo.mcp.gateway.server.ResourceDefinition;
import pl.aiwcorpo.mcp.gateway.server.ServerRegistry;

/**
 * The lists of resources (templates included) and of prompts of a user as the gateway knows them without asking any server, for the streams that
 * announce a change (CC-259): what is approved, in a server whose state serves it, not switched off, and allowed by Cedar at the level of the entry;
 * a resource also still the approved definition on the last reading of its server, if there was one. The entries carry their hash, so a changed
 * definition is a change. Like {@link UserToolLists} it keeps the decisions per identity for as long as the policies are the same.
 */
public final class UserPrimitiveLists {

    public enum Kind { RESOURCES, PROMPTS }

    private static final int MAX_IDENTITIES = 10_000;

    private record Identity(String sub, String username, String client, String principalType, List<String> groups, Kind kind) {
    }

    private static final class Decisions {
        long policies = -1;
        final Map<String, Boolean> byFingerprint = new HashMap<>();
    }

    private final ServerRegistry servers;
    private final ToolAuthorizer authorizer;
    private final KillSwitches killSwitches;
    private final BiPredicate<McpServer, ResourceDefinition> lastKnownIntact;
    private final AtomicLong policyGeneration = new AtomicLong();
    private final Map<Identity, Decisions> identities = new LinkedHashMap<>(256, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<Identity, Decisions> eldest) {
            return size() > MAX_IDENTITIES;
        }
    };

    /** @param lastKnownIntact false only when the last reading of the server found the resource other than approved (true when there was none) */
    public UserPrimitiveLists(ServerRegistry servers, ToolAuthorizer authorizer, KillSwitches killSwitches,
                              BiPredicate<McpServer, ResourceDefinition> lastKnownIntact) {
        this.servers = servers;
        this.authorizer = authorizer;
        this.killSwitches = killSwitches;
        this.lastKnownIntact = lastKnownIntact;
    }

    /** A new bundle of policies was accepted: no decision made before it counts any more. */
    public void policiesChanged() {
        policyGeneration.incrementAndGet();
    }

    public List<ListChangeTracker.Tool> of(GatewayUser user, Kind kind) {
        Decisions decisions;
        synchronized (identities) {
            decisions = identities.computeIfAbsent(new Identity(user.sub(), user.username(), user.client(), user.principalType(), user.mcpGroups(), kind),
                    k -> new Decisions());
        }
        List<ListChangeTracker.Tool> out = new ArrayList<>();
        synchronized (decisions) {
            long generation = policyGeneration.get();
            if (decisions.policies != generation) {
                decisions.byFingerprint.clear();
                decisions.policies = generation;
            }
            for (McpServer server : servers.all().stream().sorted(Comparator.comparing(McpServer::serverId)).toList()) {
                if (!server.primitivesServed()) {
                    continue;
                }
                if (kind == Kind.PROMPTS) {
                    server.primitives().prompts().values().stream().sorted(Comparator.comparing(PromptDefinition::name))
                            .filter(prompt -> !prompt.changedSinceApproval()
                                    && killSwitches.statusOfPrompt(server.serverId(), prompt.name()) == KillSwitches.Status.OFF)
                            .filter(prompt -> decisions.byFingerprint.computeIfAbsent(server.serverId() + "|p|" + prompt.name() + "|" + prompt.definitionHash()
                                    + "|" + server.credential().type(), key -> authorizer.mayGet(user, server, prompt).allowed()))
                            .forEach(prompt -> out.add(new ListChangeTracker.Tool(server.qualifiedName(prompt), "", prompt.definitionHash())));
                } else {
                    server.primitives().resources().values().stream().sorted(Comparator.comparing(ResourceDefinition::name))
                            .filter(resource -> killSwitches.statusOfResource(server.serverId(), resource.name()) == KillSwitches.Status.OFF)
                            .filter(resource -> lastKnownIntact.test(server, resource))
                            .filter(resource -> decisions.byFingerprint.computeIfAbsent(server.serverId() + "|r|" + resource.name() + "|"
                                    + resource.definitionHash() + "|" + server.credential().type(),
                                    key -> authorizer.mayRead(user, server, resource, Map.of()).allowed()))
                            .forEach(resource -> out.add(new ListChangeTracker.Tool(server.qualifiedName(resource), "", resource.definitionHash())));
                }
            }
        }
        return out;
    }
}
