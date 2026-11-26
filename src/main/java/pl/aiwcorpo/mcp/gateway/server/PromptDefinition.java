package pl.aiwcorpo.mcp.gateway.server;

import tools.jackson.databind.JsonNode;

/**
 * An approved prompt of a server (CC-258). The whole entry is data of the manifest: the gateway renders {@code prompts/get} from its
 * {@code messages} and never asks the server, so its hash is the only thing that pins the text the model receives.
 */
public record PromptDefinition(String name, String additionalGroup, String definitionHash, JsonNode entry, boolean changedSinceApproval) {

    public JsonNode definition() {
        return entry.path("definition");
    }
}
