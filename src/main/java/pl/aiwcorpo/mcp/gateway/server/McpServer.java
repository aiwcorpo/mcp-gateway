package pl.aiwcorpo.mcp.gateway.server;

import java.net.URI;
import java.util.Map;
import java.util.Optional;

/**
 * One MCP server behind the gateway: the settings an administrator gave it (C5 {@code /admin/v1/servers}) and the tools of its
 * approved manifest. A disabled server keeps its tools in the catalog but none of them can be listed or called; a server that has
 * no approved manifest, or whose policies wait for approval, has no tools.
 */
public record McpServer(String serverId, String system, URI internalUrl, String tlsName, String version, boolean enabled,
                        CredentialPolicy credential, Map<String, ToolDefinition> tools, boolean adapter) {

    /** A server whose TLS name is {@code <serverId>.internal}, not behind an adapter. */
    public McpServer(String serverId, String system, URI internalUrl, String version, boolean enabled, CredentialPolicy credential,
                     Map<String, ToolDefinition> tools) {
        this(serverId, system, internalUrl, serverId + ".internal", version, enabled, credential, tools, false);
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
