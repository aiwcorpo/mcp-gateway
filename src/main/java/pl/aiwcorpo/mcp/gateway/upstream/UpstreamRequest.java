package pl.aiwcorpo.mcp.gateway.upstream;

import pl.aiwcorpo.mcp.gateway.broker.Credential;

/**
 * One HTTP request to an MCP server. Only these values become headers: nothing from the client's request is
 * copied, so client X-MCP-*, X-PAT-*, Authorization and X-Request-Id can never reach the server (C3).
 */
public record UpstreamRequest(String jwt, String requestId, String sessionId, String protocolVersion,
                              Credential credential, String body) {
}
