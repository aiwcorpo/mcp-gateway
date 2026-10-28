package pl.aiwcorpo.mcp.gateway.server;

import java.net.URI;
import java.util.Map;
import java.util.Optional;

/**
 * One MCP server behind the gateway. {@code serverId -> system, internalUrl} comes only from configuration
 * (C5); the TLS name the server certificate must carry is always {@code <serverId>.internal}. A disabled server
 * keeps its tools in the catalog but none of them can be listed or called.
 */
public record McpServer(String serverId, String system, URI internalUrl, String version, boolean enabled,
                        CredentialPolicy credential, Map<String, ToolDefinition> tools, boolean approvalRequired,
                        String manifestCredentialJson) {

    /** A server whose tools come from the static configuration. */
    public McpServer(String serverId, String system, URI internalUrl, String version, boolean enabled, CredentialPolicy credential,
                     Map<String, ToolDefinition> tools) {
        this(serverId, system, internalUrl, version, enabled, credential, tools, false, null);
    }

    public String tlsName() {
        return serverId + ".internal";
    }

    public String toolPrefix() {
        return system + "__";
    }

    public String qualifiedName(ToolDefinition tool) {
        return toolPrefix() + tool.name();
    }

    public Optional<ToolDefinition> tool(String serverSideName) {
        return Optional.ofNullable(tools.get(serverSideName));
    }
}
