package pl.aiwcorpo.mcp.gateway.registry;

import java.util.Map;

import tools.jackson.databind.JsonNode;

/**
 * The definitions of one server the gateway accepts: a registered manifest (C6) read once, with the hash that each tool's live
 * definition must still produce. {@code credentialJson} is the manifest's credential object, a part of every hash.
 */
public record ApprovedServer(String serverId, String system, String version, String credentialJson, Map<String, ApprovedTool> tools,
                             JsonNode manifest) {
}
