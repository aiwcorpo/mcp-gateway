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
 * @param primitives the approved resources, templates and prompts next to the tools
 */
public record McpServer(String serverId, String system, URI internalUrl, String version, boolean enabled,
                        CredentialPolicy credential, Map<String, ToolDefinition> tools, boolean adapter,
                        pl.aiwcorpo.mcp.gateway.registry.ServerConfig.Connection connection, Primitives primitives) {

    public McpServer(String serverId, String system, URI internalUrl, String version, boolean enabled, CredentialPolicy credential,
                     Map<String, ToolDefinition> tools, boolean adapter, pl.aiwcorpo.mcp.gateway.registry.ServerConfig.Connection connection) {
        this(serverId, system, internalUrl, version, enabled, credential, tools, adapter, connection, Primitives.NONE);
    }

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

    /**
     * Whether the state of the server lets its resources, templates and prompts be listed and used: it is enabled, no manifest check
     * disabled it, and its connection and policies are approved (CC-249). A server behind a switch is judged by the caller.
     */
    public boolean primitivesServed() {
        return enabled && connectionApproved() && primitives.policiesApproved();
    }

    public String qualifiedName(ResourceDefinition resource) {
        return toolPrefix() + resource.name();
    }

    public String qualifiedName(PromptDefinition prompt) {
        return toolPrefix() + prompt.name();
    }

    public Optional<ToolDefinition> tool(String serverSideName) {
        return Optional.ofNullable(tools.get(serverSideName));
    }
}
