package pl.aiwcorpo.mcp.gateway.mcp;

import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;

/**
 * One client HTTP request: its requestId (UUIDv7, C2 {@code rid}), the user, the endpoint addressed and the key
 * of the conversation whose upstream sessions it uses (always contains the user's sub).
 */
public record CallContext(String requestId, String clientRequestId, GatewayUser user, Target target,
                          String protocolVersion, String conversationKey) {

    public boolean modern() {
        return ProtocolVersions.isModern(protocolVersion);
    }
}
