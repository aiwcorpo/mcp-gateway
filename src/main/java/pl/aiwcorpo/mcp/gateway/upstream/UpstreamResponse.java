package pl.aiwcorpo.mcp.gateway.upstream;

import tools.jackson.databind.JsonNode;

/** HTTP status, new session id (initialize) and the JSON-RPC response (null for 202). */
public record UpstreamResponse(int status, String sessionId, JsonNode message) {
}
