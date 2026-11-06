package pl.aiwcorpo.mcp.gateway.registry;

import java.util.Optional;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.server.ToolDefinition;
import pl.aiwcorpo.mcp.manifest.DefinitionHash;

/**
 * The comparison that keeps a server to what was approved: the hash (C6, CC-004) of the definition the server serves now, with
 * the approved risk, action and references and the system and credential the approval was made with, must equal the approved
 * hash. A change of a description, a schema or an annotation on the server, without a new registration, makes the tool unusable.
 */
public final class DefinitionCheck {

    private final JsonMapper json;

    public DefinitionCheck(JsonMapper json) {
        this.json = json;
    }

    /** The hash the live definition would have as the approved tool; empty for anything that cannot be hashed (a mismatch). */
    public Optional<String> hashOf(McpServer server, ToolDefinition approved, JsonNode live) {
        if (approved.definitionHash() == null || approved.credentialJson() == null || live == null || !live.isObject()) {
            return Optional.empty();
        }
        try {
            return Optional.of(DefinitionHash.compute(json.writeValueAsString(live), json.writeValueAsString(entryOf(server, approved)),
                    server.system(), approved.credentialJson()));
        } catch (RuntimeException e) {
            return Optional.empty();
        }
    }

    /** True only when the live definition produces exactly the approved hash. Any malformed definition is a mismatch. */
    public boolean intact(McpServer server, ToolDefinition approved, JsonNode live) {
        return hashOf(server, approved, live).filter(approved.definitionHash()::equals).isPresent();
    }

    /**
     * The entry a live definition is hashed and listed with: the approved risk, action and references, never the server's. The entry of
     * an adapter has neither risk nor action in the hash (CC-206): the classification of the administrator is data of the registry.
     */
    public ObjectNode entryOf(McpServer server, ToolDefinition approved) {
        ObjectNode entry = json.createObjectNode();
        if (!server.adapter()) {
            entry.put("risk", approved.risk().name());
            entry.put("action", approved.action());
        }
        if (approved.additionalGroup() != null) {
            entry.put("additionalGroup", approved.additionalGroup());
        }
        ArrayNode refs = entry.putArray("resourceRefs");
        approved.resourceRefs().forEach(ref -> refs.addObject().put("argument", ref.argument()).put("type", ref.type()));
        return entry;
    }
}
