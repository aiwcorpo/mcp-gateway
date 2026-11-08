package pl.aiwcorpo.mcp.gateway.server;

import java.net.URI;
import java.util.Map;
import java.util.Optional;

/**
 * One MCP server behind the gateway: the settings an administrator gave it (C5 {@code /admin/v1/servers}), the trust the gateway applies
 * to its connection and the tools of its approved manifest. A disabled server keeps its tools in the catalog but none of them can be
 * listed or called; a server that has no approved manifest, or whose connection or policies wait for approval, has no tools.
 *
 * @param connection the approved trust (tlsMode and fingerprint), null while none is approved
 */
public record McpServer(String serverId, String system, URI internalUrl, String version, boolean enabled,
                        CredentialPolicy credential, Map<String, ToolDefinition> tools, boolean adapter,
                        pl.aiwcorpo.mcp.gateway.registry.ServerConfig.Connection connection) {

    /** A server not behind an adapter, with its connection approved as {@code ca}. */
    public McpServer(String serverId, String system, URI internalUrl, String version, boolean enabled, CredentialPolicy credential,
                     Map<String, ToolDefinition> tools) {
        this(serverId, system, internalUrl, version, enabled, credential, tools, false);
    }

    public McpServer(String serverId, String system, URI internalUrl, String version, boolean enabled, CredentialPolicy credential,
                     Map<String, ToolDefinition> tools, boolean adapter) {
        this(serverId, system, internalUrl, version, enabled, credential, tools, adapter,
                new pl.aiwcorpo.mcp.gateway.registry.ServerConfig.Connection("ca", null, null, null, java.util.List.of(), null, null, null));
    }

    public boolean connectionApproved() {
        return connection != null;
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
