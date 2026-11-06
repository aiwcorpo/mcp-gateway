package pl.aiwcorpo.mcp.gateway.registry;

import java.util.Map;

import pl.aiwcorpo.mcp.gateway.registry.RegistryStore.StoredPolicies;
import tools.jackson.databind.JsonNode;

/**
 * What the registry holds of one server: the last accepted manifest, the tools (approved and pending) and the policies and resource
 * types (approved and pending). A server behind an adapter has no policies.
 */
public record RegisteredServer(String serverId, String system, String version, JsonNode manifest, String source,
                               Map<String, RegisteredTool> tools, StoredPolicies policies) {
}
