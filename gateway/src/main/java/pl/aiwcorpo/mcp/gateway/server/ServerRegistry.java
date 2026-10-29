package pl.aiwcorpo.mcp.gateway.server;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

import pl.aiwcorpo.mcp.gateway.config.GatewayProperties;
import pl.aiwcorpo.mcp.gateway.registry.RegisteredTool;
import tools.jackson.databind.JsonNode;

/**
 * The servers behind the gateway. {@code serverId -> system, internalUrl}, the credential policy and the enabled switch come
 * from the configuration only (C5). The tools come from the approved manifest of the server (C6, registry) when the server is
 * in mode {@code required}, which is the default: until a manifest is approved the server has no tools. In mode {@code static}
 * they come from the configuration (development without manifests).
 */
public final class ServerRegistry {

    private static final Set<String> SYSTEMS = Set.of("jira", "confluence", "gitlab", "servicedesk", "opensearch");
    private static final Set<String> CREDENTIAL_TYPES = Set.of("user-oauth", "user-secret", "token-exchange", "service-account");
    private static final Pattern TOOL_NAME = Pattern.compile("^[a-z][a-z0-9]*(_[a-z0-9]+)*$");
    private static final Pattern SEMVER = Pattern.compile(
            "^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\\+[0-9A-Za-z.-]+)?$");
    private static final Set<String> ACTIONS = Set.of("read", "update", "delete", "admin");

    public static final String MODE_REQUIRED = "required";
    public static final String MODE_STATIC = "static";

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(ServerRegistry.class);

    private final Map<String, GatewayProperties.Server> config;
    private volatile Map<String, McpServer> servers;

    public ServerRegistry(Map<String, GatewayProperties.Server> config, String defaultMode) {
        if (!Set.of(MODE_REQUIRED, MODE_STATIC).contains(defaultMode)) {
            throw new IllegalStateException("gateway.registry.mode must be required or static");
        }
        this.config = Map.copyOf(config);
        Map<String, McpServer> built = new LinkedHashMap<>();
        config.forEach((serverId, server) -> {
            String mode = server.manifest() == null || server.manifest().isBlank() ? defaultMode : server.manifest();
            if (!Set.of(MODE_REQUIRED, MODE_STATIC).contains(mode)) {
                throw new IllegalStateException("gateway.servers." + serverId + ".manifest must be required or static");
            }
            McpServer fromConfig = build(serverId, server);
            built.put(serverId, MODE_REQUIRED.equals(mode)
                    ? new McpServer(fromConfig.serverId(), fromConfig.system(), fromConfig.internalUrl(), fromConfig.version(),
                            fromConfig.enabled(), fromConfig.credential(), Map.of(), true)
                    : fromConfig);
        });
        this.servers = Map.copyOf(built);
    }

    public Optional<McpServer> find(String serverId) {
        return Optional.ofNullable(servers.get(serverId));
    }

    public List<McpServer> all() {
        return List.copyOf(servers.values());
    }

    /** Risk ordinal per tool that the configuration names: a manifest may not go below it (fail-closed on a lower risk). */
    public Map<String, Integer> configuredMinimumRisks(String serverId) {
        GatewayProperties.Server configured = config.get(serverId);
        Map<String, Integer> minimum = new LinkedHashMap<>();
        if (configured != null) {
            configured.tools().forEach((name, tool) -> {
                try {
                    minimum.put(name, Risk.valueOf(tool.risk()).ordinal());
                } catch (IllegalArgumentException e) {
                    throw new IllegalStateException("gateway.servers." + serverId + ".tools." + name + ".risk: " + tool.risk());
                }
            });
        }
        return minimum;
    }

    /** Servers whose tools wait for an approved manifest, or have one. */
    public List<McpServer> requiringApproval() {
        return servers.values().stream().filter(McpServer::approvalRequired).toList();
    }

    /**
     * Takes the approved definitions of a server as its tools: metadata (risk, action, references, texts), the approved definition
     * the client is shown and the hash each live definition must keep. A tool whose approved risk is below the configured minimum or
     * an earlier approval ({@code approvedFloors}) is not served. The switches of the configuration stay: a disabled server or tool
     * is disabled whatever the manifest says. {@code manifestAccepted} false (the held manifest fails the checks of the start,
     * CC-159) disables the server without removing anything.
     */
    public synchronized void apply(String serverId, String version, Map<String, RegisteredTool> registered,
                                   Map<String, Integer> approvedFloors, boolean manifestAccepted) {
        McpServer current = servers.get(serverId);
        GatewayProperties.Server configured = config.get(serverId);
        if (current == null || configured == null || !current.approvalRequired()) {
            throw new IllegalStateException("server " + serverId + " takes no manifest");
        }
        Map<String, Integer> minimum = new LinkedHashMap<>(configuredMinimumRisks(serverId));
        approvedFloors.forEach((name, risk) -> minimum.merge(name, risk, Math::max));
        Map<String, ToolDefinition> tools = new LinkedHashMap<>();
        registered.forEach((name, registeredTool) -> {
            RegisteredTool.Approved approved = registeredTool.approved();
            if (approved == null) {
                return;
            }
            JsonNode entry = approved.entry();
            Risk risk = Risk.valueOf(entry.path("risk").asString());
            if (risk.ordinal() < minimum.getOrDefault(name, 0)) {
                // The manifest says less than the configuration or an earlier approval: the tool is left out until it says enough.
                log.error("{}: tool {} is approved with a risk below the minimum; it is not served", serverId, name);
                return;
            }
            GatewayProperties.Tool switches = configured.tools().get(name);
            java.util.List<pl.aiwcorpo.mcp.cedar.entities.ResourceRef> refs = new java.util.ArrayList<>();
            entry.path("resourceRefs").forEach(ref -> refs.add(
                    new pl.aiwcorpo.mcp.cedar.entities.ResourceRef(ref.path("argument").asString(), ref.path("type").asString())));
            JsonNode definition = entry.path("definition");
            tools.put(name, new ToolDefinition(name, risk, entry.path("action").asString(), definition.path("title").asString(null),
                    definition.path("description").asString(""), switches != null && switches.disabled(), List.copyOf(refs),
                    approved.hash(), definition, approved.credentialJson()));
        });
        Map<String, McpServer> next = new LinkedHashMap<>(servers);
        next.put(serverId, new McpServer(current.serverId(), current.system(), current.internalUrl(), version,
                config.get(serverId).enabled() && manifestAccepted, current.credential(), Map.copyOf(tools), true));
        this.servers = Map.copyOf(next);
    }

    /** A tool as the client names it ({@code <system>__<tool>}) together with its server. */
    public record Resolved(McpServer server, ToolDefinition tool) {
    }

    /** Empty for a name outside the configuration; the server's own tool list is the only source. */
    public Optional<Resolved> resolve(String qualifiedName) {
        if (qualifiedName == null) {
            return Optional.empty();
        }
        int separator = qualifiedName.indexOf("__");
        if (separator <= 0) {
            return Optional.empty();
        }
        return find("mcp-" + qualifiedName.substring(0, separator))
                .flatMap(server -> server.tool(qualifiedName.substring(separator + 2))
                        .map(tool -> new Resolved(server, tool)));
    }

    private static McpServer build(String serverId, GatewayProperties.Server server) {
        if (!SYSTEMS.contains(server.system())) {
            throw new IllegalStateException("gateway.servers." + serverId + ".system: unknown system " + server.system());
        }
        if (!serverId.equals("mcp-" + server.system())) {
            throw new IllegalStateException("gateway.servers." + serverId + ": serverId must be mcp-<system> (C5)");
        }
        if (!"https".equals(server.internalUrl().getScheme()) || server.internalUrl().getHost() == null) {
            throw new IllegalStateException("gateway.servers." + serverId + ".internal-url must be an https URL (mTLS)");
        }
        GatewayProperties.Credential credential = server.credential();
        Set<String> accepted = new LinkedHashSet<>(credential.acceptedTypes());
        if (credential.required() && accepted.isEmpty()) {
            throw new IllegalStateException("gateway.servers." + serverId + ".credential.accepted-types is empty");
        }
        if (!CREDENTIAL_TYPES.containsAll(accepted)) {
            throw new IllegalStateException("gateway.servers." + serverId + ".credential.accepted-types: unknown type");
        }
        if (accepted.contains("service-account") && accepted.size() > 1) {
            // context.credentialType is one default type: a mixed set would hide a service account from the rules about it (CC-168).
            throw new IllegalStateException("gateway.servers." + serverId + ".credential.accepted-types mixes service-account with user types (CC-168)");
        }
        if (!SEMVER.matcher(server.version()).matches()) {
            throw new IllegalStateException("gateway.servers." + serverId + ".version must be a SemVer");
        }
        Map<String, ToolDefinition> tools = new LinkedHashMap<>();
        server.tools().forEach((name, tool) -> {
            if (!TOOL_NAME.matcher(name).matches() || name.length() > 64) {
                throw new IllegalStateException("gateway.servers." + serverId + ".tools: invalid tool name " + name);
            }
            Risk risk;
            try {
                risk = Risk.valueOf(tool.risk());
            } catch (IllegalArgumentException e) {
                throw new IllegalStateException("gateway.servers." + serverId + ".tools." + name + ".risk: " + tool.risk());
            }
            String action = tool.action() == null || tool.action().isBlank() ? defaultAction(risk) : tool.action();
            if (!ACTIONS.contains(action)) {
                throw new IllegalStateException("gateway.servers." + serverId + ".tools." + name + ".action: " + action);
            }
            String title = tool.title() == null || tool.title().isBlank() ? null : tool.title();
            java.util.List<pl.aiwcorpo.mcp.cedar.entities.ResourceRef> refs = tool.resourceRefs().stream()
                    .map(ref -> new pl.aiwcorpo.mcp.cedar.entities.ResourceRef(ref.argument(), ref.type())).toList();
            tools.put(name, new ToolDefinition(name, risk, action, title, tool.description(), tool.disabled(), refs));
        });
        return new McpServer(serverId, server.system(), server.internalUrl(), server.version(), server.enabled(),
                new CredentialPolicy(credential.required(), Set.copyOf(accepted), List.copyOf(credential.scopes()),
                        credential.tokenExchange(), credentialType(serverId, credential, accepted)),
                Map.copyOf(tools));
    }

    /** The one type of the system for context.credentialType; ambiguous configuration is an error (fail-closed at start). */
    private static String credentialType(String serverId, GatewayProperties.Credential credential, Set<String> accepted) {
        if (!credential.required()) {
            return null;
        }
        String explicit = credential.type() == null || credential.type().isBlank() ? null : credential.type();
        if (explicit != null) {
            if (!accepted.contains(explicit)) {
                throw new IllegalStateException("gateway.servers." + serverId + ".credential.type must be one of accepted-types");
            }
            return explicit;
        }
        if (credential.tokenExchange()) {
            if (!accepted.contains("token-exchange")) {
                throw new IllegalStateException("gateway.servers." + serverId + ".credential.token-exchange needs token-exchange in accepted-types");
            }
            return "token-exchange";
        }
        if (accepted.size() == 1) {
            return accepted.iterator().next();
        }
        throw new IllegalStateException("gateway.servers." + serverId + ".credential.type is required when several types are accepted");
    }

    private static String defaultAction(Risk risk) {
        return switch (risk) {
            case READ_ONLY -> "read";
            case UPDATE -> "update";
            case DESTRUCTIVE -> "delete";
        };
    }
}
