package pl.aiwcorpo.mcp.gateway.mcp;

/** Legacy MCP session between a client and the gateway; always bound to one {@code sub}. */
public record ClientSession(String id, String sub, String client, String protocolVersion) {
}
