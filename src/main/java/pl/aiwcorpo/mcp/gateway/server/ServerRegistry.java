package pl.aiwcorpo.mcp.gateway.server;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import pl.aiwcorpo.mcp.gateway.registry.RegisteredTool;
import pl.aiwcorpo.mcp.gateway.registry.ServerConfig;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * The servers behind the gateway as this instance holds them. The list of servers is data of the database ({@code servers}, changed
 * through the admin API and read again by every instance when the change counter moves); the tools of a server come from its approved
 * manifest (C6). Until a manifest is approved, and while the policies of the server wait for approval, a server has no tools: they are
 * known, answered with tool_disabled, and listed nowhere (CC-178).
 */
public final class ServerRegistry {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(ServerRegistry.class);

    /**
     * What the registry holds of one server's manifest: the tools with their approvals, the highest risks ever approved, whether the
     * held manifest passes the checks of this instance and whether the policies of the server are the approved ones.
     */
    public record Applied(String version, Map<String, RegisteredTool> tools, Map<String, Integer> floors, boolean manifestAccepted,
                          boolean policiesApproved) {
    }

    private Map<String, ServerConfig> configs = Map.of();
    private final Map<String, Applied> applied = new LinkedHashMap<>();
    private volatile Map<String, McpServer> servers = Map.of();
    /** Tools that have only a pending entry (never approved): known to the registry, answered with tool_disabled (CC-178). */
    private volatile Map<String, Map<String, ToolDefinition>> unapproved = Map.of();
    private volatile io.micrometer.core.instrument.MeterRegistry meters;

    /** Entries that are not served for a reason of their own are counted here (fail-closed, with a log line). */
    public void bindTo(io.micrometer.core.instrument.MeterRegistry registry) {
        this.meters = registry;
    }

    public Optional<McpServer> find(String serverId) {
        return Optional.ofNullable(servers.get(serverId));
    }

    public List<McpServer> all() {
        return List.copyOf(servers.values());
    }

    /** The server list this instance serves after a change in the database; a server that is not in it is gone, tools and all. */
    public synchronized void replaceConfigs(Collection<ServerConfig> next) {
        Map<String, ServerConfig> byId = new LinkedHashMap<>();
        next.forEach(config -> byId.put(config.serverId(), config));
        this.configs = Map.copyOf(byId);
        applied.keySet().removeIf(serverId -> !byId.containsKey(serverId));
        rebuild(null);
    }

    /**
     * Takes the approved definitions of a server as its tools: metadata (risk, action, references, texts), the approved definition
     * the client is shown and the hash each live definition must keep. A tool whose approved risk is below an earlier approval
     * ({@code floors}) is not served. {@code manifestAccepted} false (the held manifest fails the checks of the start, CC-159)
     * disables the server without removing anything; {@code policiesApproved} false (the policies or the resource types of the
     * server are not the approved ones) leaves all its tools waiting.
     */
    public synchronized void apply(String serverId, Applied state) {
        if (!configs.containsKey(serverId)) {
            throw new IllegalStateException("server " + serverId + " is not registered");
        }
        applied.put(serverId, state);
        rebuild(serverId);
    }

    /** Forgets the manifest state of a server, as after the removal of its stored rows; its settings stay. */
    public synchronized void forgetState(String serverId) {
        if (applied.remove(serverId) != null) {
            rebuild(null);
        }
    }

    /** @param applying the server whose new state is taken now: entries refused in it are counted once, not on every later rebuild */
    private void rebuild(String applying) {
        Map<String, McpServer> built = new LinkedHashMap<>();
        Map<String, Map<String, ToolDefinition>> waitingByServer = new LinkedHashMap<>();
        configs.values().stream().sorted(java.util.Comparator.comparing(ServerConfig::serverId)).forEach(config -> {
            Applied state = applied.get(config.serverId());
            Map<String, ToolDefinition> tools = new LinkedHashMap<>();
            Map<String, ToolDefinition> waiting = new LinkedHashMap<>();
            if (state != null) {
                tools(config, state, tools, waiting, config.serverId().equals(applying));
            }
            waitingByServer.put(config.serverId(), Map.copyOf(waiting));
            built.put(config.serverId(), new McpServer(config.serverId(), config.system(), config.internalUrl(),
                    state == null ? "0.0.0" : state.version(), config.enabled() && (state == null || state.manifestAccepted()),
                    credential(config), Map.copyOf(tools), config.adapter()));
        });
        this.servers = Map.copyOf(built);
        this.unapproved = Map.copyOf(waitingByServer);
    }

    private void tools(ServerConfig config, Applied state, Map<String, ToolDefinition> tools, Map<String, ToolDefinition> waiting,
                       boolean count) {
        String serverId = config.serverId();
        state.tools().forEach((name, registeredTool) -> {
            RegisteredTool.Approved approved = registeredTool.approved();
            if (approved == null) {
                waiting.put(name, waitingTool(name, registeredTool.pending().entry()));
                return;
            }
            JsonNode entry = approved.entry();
            if (!state.policiesApproved()) {
                waiting.put(name, waitingTool(name, entry));
                return;
            }
            if (!entry.path("risk").isString()) {
                // An approved entry of an adapter always carries the classification of the administrator; one that does not is not served.
                log.error("{}: tool {} is approved without a classification; it is not served", serverId, name);
                waiting.put(name, waitingTool(name, entry));
                return;
            }
            Risk risk = Risk.valueOf(entry.path("risk").asString());
            if (config.adapter() && risk != Risk.READ_ONLY) {
                // A tool of an adapter is read only (CC-227). An entry stored with a write classification (by an instance that still takes it)
                // is not served, whatever the registry holds: it waits as unclassified.
                log.error("{}: tool {} of an adapter is approved as {}; adapters are read only, it is not served", serverId, name, risk);
                if (meters != null && count) {
                    meters.counter("mcp_gateway_registry_entries_refused_total", "reason", "adapter_not_read_only").increment();
                }
                ObjectNode unclassified = ((ObjectNode) entry).deepCopy();
                unclassified.remove("risk");
                unclassified.remove("action");
                waiting.put(name, waitingTool(name, unclassified));
                return;
            }
            if (risk.ordinal() < state.floors().getOrDefault(name, 0)) {
                // The manifest says less than an earlier approval: the tool is left out until it says enough.
                log.error("{}: tool {} is approved with a risk below the minimum; it is not served", serverId, name);
                return;
            }
            List<pl.aiwcorpo.mcp.cedar.entities.ResourceRef> refs = refs(entry);
            JsonNode definition = entry.path("definition");
            tools.put(name, new ToolDefinition(name, risk, entry.path("action").asString(), definition.path("title").asString(null),
                    definition.path("description").asString(""), false, refs, approved.hash(), definition, approved.credentialJson()));
        });
    }

    private static List<pl.aiwcorpo.mcp.cedar.entities.ResourceRef> refs(JsonNode entry) {
        List<pl.aiwcorpo.mcp.cedar.entities.ResourceRef> refs = new ArrayList<>();
        entry.path("resourceRefs").forEach(ref -> refs.add(
                new pl.aiwcorpo.mcp.cedar.entities.ResourceRef(ref.path("argument").asString(), ref.path("type").asString())));
        return List.copyOf(refs);
    }

    /**
     * A tool that waits for its first approval. One of an adapter has no risk and no action yet: it is judged as the most dangerous kind
     * (DESTRUCTIVE, admin), so that only a user who may call such tools learns it is there (tool_disabled) and everyone else gets
     * not_found_or_denied (invariant 8). It is disabled whatever it is judged as.
     */
    private static ToolDefinition waitingTool(String name, JsonNode entry) {
        boolean classified = entry.path("risk").isString();
        return new ToolDefinition(name, classified ? Risk.valueOf(entry.path("risk").asString()) : Risk.DESTRUCTIVE,
                classified ? entry.path("action").asString() : "admin",
                entry.path("definition").path("title").asString(null), entry.path("definition").path("description").asString(""), true,
                refs(entry));
    }

    private static CredentialPolicy credential(ServerConfig config) {
        ServerConfig.Credential credential = config.credential();
        Set<String> accepted = new LinkedHashSet<>(credential.acceptedTypes());
        return new CredentialPolicy(credential.required(), Set.copyOf(accepted), List.of(), "token-exchange".equals(credential.type()),
                credential.required() ? credential.type() : null);
    }

    /** A tool as the client names it ({@code <system>__<tool>}) together with its server. */
    public record Resolved(McpServer server, ToolDefinition tool) {
    }

    /**
     * Like {@link #resolve} but a tool that waits for its first approval is found too, as a disabled tool: for the call, which
     * answers tool_disabled to a user who may call it (CC-178). Such a tool is in no list and in no catalog.
     */
    public Optional<Resolved> resolveForCall(String qualifiedName) {
        Optional<Resolved> approved = resolve(qualifiedName);
        if (approved.isPresent()) {
            return approved;
        }
        return route(qualifiedName).flatMap(route -> find(route.serverId()).flatMap(server ->
                Optional.ofNullable(unapproved.getOrDefault(route.serverId(), Map.of()).get(route.tool()))
                        .map(tool -> new Resolved(server, tool))));
    }

    /** Empty for a name outside the registry; the approved manifest is the only source of tools. */
    public Optional<Resolved> resolve(String qualifiedName) {
        return route(qualifiedName).flatMap(route -> find(route.serverId())
                .flatMap(server -> server.tool(route.tool()).map(tool -> new Resolved(server, tool))));
    }

    private Optional<ToolRoute> route(String qualifiedName) {
        return ToolRoute.of(qualifiedName, servers.values().stream().map(McpServer::system).toList());
    }
}
