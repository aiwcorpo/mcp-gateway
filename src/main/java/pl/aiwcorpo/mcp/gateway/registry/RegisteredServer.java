package pl.aiwcorpo.mcp.gateway.registry;

import java.util.Map;

import tools.jackson.databind.JsonNode;

/** What the registry holds of one server: the last accepted manifest and the tools, approved and pending. */
public record RegisteredServer(String serverId, String system, String version, JsonNode manifest, String source,
                               Map<String, RegisteredTool> tools) {
}
