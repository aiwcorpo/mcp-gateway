package pl.aiwcorpo.mcp.gateway.registry;

import java.util.Map;

import pl.aiwcorpo.mcp.gateway.registry.RegistryStore.StoredPolicies;
import tools.jackson.databind.JsonNode;

/**
 * What the registry holds of one server: the last accepted manifest, the tools (approved and pending), the resources, resource templates
 * and prompts (approved and pending, by kind and name), the policies and resource types (approved and pending) and the
 * {@code contractsVersion} of the manifest (null when it names none: 7.x or older). A server behind an adapter has no policies.
 */
public record RegisteredServer(String serverId, String system, String version, JsonNode manifest, String source,
                               Map<String, RegisteredTool> tools, StoredPolicies policies,
                               Map<PrimitiveKind, Map<String, RegisteredEntry>> entries, String contractsVersion) {

    public Map<String, RegisteredEntry> entries(PrimitiveKind kind) {
        return entries.getOrDefault(kind, Map.of());
    }
}
