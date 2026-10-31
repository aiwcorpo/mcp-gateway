package pl.aiwcorpo.mcp.gateway.mcp;

import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.manifest.EndpointFilter;

/**
 * One client HTTP request: its requestId (UUIDv7, C2 {@code rid}), the user, the endpoint addressed with the filter of its query
 * and the key of the conversation whose upstream sessions it uses (always contains the user's sub).
 */
public record CallContext(String requestId, String clientRequestId, GatewayUser user, Target target, EndpointFilter filter,
                          String protocolVersion, String conversationKey) {

    public boolean modern() {
        return ProtocolVersions.isModern(protocolVersion);
    }

    /** The canonical filter for the audit field {@code filter}; null when the request had none. */
    public String auditFilter() {
        return filter.isEmpty() ? null : filter.canonical();
    }
}
