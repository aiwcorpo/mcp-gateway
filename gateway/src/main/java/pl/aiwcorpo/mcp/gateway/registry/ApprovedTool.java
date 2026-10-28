package pl.aiwcorpo.mcp.gateway.registry;

import java.util.List;

import pl.aiwcorpo.mcp.cedar.entities.ResourceRef;
import tools.jackson.databind.JsonNode;

/** One tool entry of an approved manifest: the metadata the gateway decides with and the hash of the whole definition. */
public record ApprovedTool(String name, String risk, String action, List<ResourceRef> resourceRefs, String title, String description,
                           JsonNode definition, String definitionHash, JsonNode entry) {
}
