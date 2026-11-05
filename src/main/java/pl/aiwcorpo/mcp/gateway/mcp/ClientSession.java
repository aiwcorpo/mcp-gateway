package pl.aiwcorpo.mcp.gateway.mcp;

/**
 * Legacy MCP session between a client and the gateway; always bound to one {@code sub}, to the route it was opened on and to
 * the canonical filter of its {@code initialize} (CC-172, CC-184).
 */
public record ClientSession(String id, String sub, String client, String protocolVersion, String route, String filter) {
}
