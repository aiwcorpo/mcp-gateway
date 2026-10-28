package pl.aiwcorpo.mcp.gateway.registry;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.server.ToolDefinition;
import pl.aiwcorpo.mcp.manifest.DefinitionHash;

/**
 * The comparison that keeps a server to what was approved: the hash (C6, CC-004) of the definition the server serves now, with
 * the approved risk, action and references and the manifest's system and credential, must equal the approved hash. A change of
 * a description, a schema or an annotation on the server, without a new registration, makes the tool unusable.
 */
public final class DefinitionCheck {

    private final JsonMapper json;

    public DefinitionCheck(JsonMapper json) {
        this.json = json;
    }

    /** True only when the live definition produces exactly the approved hash. Any malformed definition is a mismatch. */
    public boolean intact(McpServer server, ToolDefinition approved, JsonNode live) {
        if (approved.definitionHash() == null || server.manifestCredentialJson() == null) {
            return false;
        }
        try {
            ObjectNode entry = json.createObjectNode();
            entry.put("risk", approved.risk().name());
            entry.put("action", approved.action());
            ArrayNode refs = entry.putArray("resourceRefs");
            approved.resourceRefs().forEach(ref -> refs.addObject().put("argument", ref.argument()).put("type", ref.type()));
            String hash = DefinitionHash.compute(json.writeValueAsString(live), json.writeValueAsString(entry), server.system(),
                    server.manifestCredentialJson());
            return approved.definitionHash().equals(hash);
        } catch (RuntimeException e) {
            return false;
        }
    }
}
