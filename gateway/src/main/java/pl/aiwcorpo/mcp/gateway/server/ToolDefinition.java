package pl.aiwcorpo.mcp.gateway.server;

/** Tool known to the gateway: server-side name and risk from the static configuration. */
public record ToolDefinition(String name, Risk risk) {
}
