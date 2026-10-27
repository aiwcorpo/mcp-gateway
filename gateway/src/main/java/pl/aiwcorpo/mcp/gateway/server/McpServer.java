package pl.aiwcorpo.mcp.gateway.server;

import java.net.URI;
import java.util.Map;
import java.util.Optional;

/**
 * One MCP server behind the gateway. {@code serverId -> system, internalUrl} comes only from configuration
 * (C5); the TLS name the server certificate must carry is always {@code <serverId>.internal}.
 */
public record McpServer(String serverId, String system, URI internalUrl, CredentialPolicy credential,
                        Map<String, ToolDefinition> tools) {

    public String tlsName() {
        return serverId + ".internal";
    }

    public String toolPrefix() {
        return system + "__";
    }

    public Optional<ToolDefinition> tool(String serverSideName) {
        return Optional.ofNullable(tools.get(serverSideName));
    }
}
