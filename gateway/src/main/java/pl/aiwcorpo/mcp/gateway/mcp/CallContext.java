package pl.aiwcorpo.mcp.gateway.mcp;

import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.server.McpServer;

/**
 * One client HTTP request: its requestId (UUIDv7, C2 {@code rid}), the user, the target server and the key of
 * the conversation whose upstream session it uses (always contains the user's sub).
 */
public record CallContext(String requestId, String clientRequestId, GatewayUser user, McpServer server,
                          String protocolVersion, String conversationKey) {

    public boolean modern() {
        return ProtocolVersions.isModern(protocolVersion);
    }
}
