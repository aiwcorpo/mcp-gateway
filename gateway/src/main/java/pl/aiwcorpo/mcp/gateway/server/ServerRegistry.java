package pl.aiwcorpo.mcp.gateway.server;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

import pl.aiwcorpo.mcp.gateway.config.GatewayProperties;

/**
 * Servers from the static configuration (M1). In M2 the registry (C5/C6) replaces the tool lists; the
 * {@code serverId -> system, internalUrl} binding stays configuration.
 */
public final class ServerRegistry {

    private static final Set<String> SYSTEMS = Set.of("jira", "confluence", "gitlab", "servicedesk", "opensearch");
    private static final Set<String> CREDENTIAL_TYPES = Set.of("user-oauth", "user-secret", "token-exchange", "service-account");
    private static final Pattern TOOL_NAME = Pattern.compile("^[a-z][a-z0-9]*(_[a-z0-9]+)*$");

    private final Map<String, McpServer> servers;

    public ServerRegistry(Map<String, GatewayProperties.Server> config) {
        Map<String, McpServer> built = new LinkedHashMap<>();
        config.forEach((serverId, server) -> built.put(serverId, build(serverId, server)));
        this.servers = Map.copyOf(built);
    }

    public Optional<McpServer> find(String serverId) {
        return Optional.ofNullable(servers.get(serverId));
    }

    public List<McpServer> all() {
        return List.copyOf(servers.values());
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
            tools.put(name, new ToolDefinition(name, risk));
        });
        return new McpServer(serverId, server.system(), server.internalUrl(),
                new CredentialPolicy(credential.required(), Set.copyOf(accepted), List.copyOf(credential.scopes()),
                        credential.tokenExchange()),
                Map.copyOf(tools));
    }
}
