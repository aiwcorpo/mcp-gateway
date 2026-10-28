package pl.aiwcorpo.mcp.gateway.server;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

import pl.aiwcorpo.mcp.gateway.config.GatewayProperties;
import pl.aiwcorpo.mcp.gateway.registry.ApprovedServer;

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
                            fromConfig.enabled(), fromConfig.credential(), Map.of(), true, null)
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

    /** Servers whose tools wait for an approved manifest, or have one. */
    public List<McpServer> requiringApproval() {
        return servers.values().stream().filter(McpServer::approvalRequired).toList();
    }

    /**
     * Takes the approved manifest of a server as its tools: metadata (risk, action, references, texts) and the hash each
     * live definition must keep. The switches of the configuration stay: a disabled server or tool is disabled whatever the
     * manifest says.
     */
    public synchronized void apply(ApprovedServer approved) {
        McpServer current = servers.get(approved.serverId());
        GatewayProperties.Server configured = config.get(approved.serverId());
        if (current == null || configured == null || !current.approvalRequired()) {
            throw new IllegalStateException("server " + approved.serverId() + " takes no manifest");
        }
        Map<String, ToolDefinition> tools = new LinkedHashMap<>();
        approved.tools().forEach((name, tool) -> {
            GatewayProperties.Tool switches = configured.tools().get(name);
            tools.put(name, new ToolDefinition(name, Risk.valueOf(tool.risk()), tool.action(), tool.title(), tool.description(),
                    switches != null && switches.disabled(), tool.resourceRefs(), tool.definitionHash()));
        });
        Map<String, McpServer> next = new LinkedHashMap<>(servers);
        next.put(approved.serverId(), new McpServer(current.serverId(), current.system(), current.internalUrl(), approved.version(),
                current.enabled(), current.credential(), Map.copyOf(tools), true, approved.credentialJson()));
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
                        credential.tokenExchange()),
                Map.copyOf(tools));
    }

    private static String defaultAction(Risk risk) {
        return switch (risk) {
            case READ_ONLY -> "read";
            case UPDATE -> "update";
            case DESTRUCTIVE -> "delete";
        };
    }
}
