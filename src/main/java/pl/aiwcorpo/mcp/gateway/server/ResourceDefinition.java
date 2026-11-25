package pl.aiwcorpo.mcp.gateway.server;

import java.util.List;

import tools.jackson.databind.JsonNode;

/**
 * An approved static resource or resource template of a server (CC-258): one namespace of names for both. {@code locator} is the URI of a
 * static resource or the URI template of a template.
 *
 * @param entry the approved manifest entry as the registry holds it (its definition is what a list shows, and what the server's own list is compared with)
 * @param credentialJson the credential block of the manifest the approval was made under, which is part of the hash
 */
public record ResourceDefinition(String name, boolean template, String locator, List<UriVariable> variables, String additionalGroup,
                                 String definitionHash, JsonNode entry, String credentialJson) {

    /**
     * A variable of a template: a type of the server's resource types, or for an adapter its own bound and pattern.
     *
     * @param type null for a variable of an adapter
     */
    public record UriVariable(String name, String type, int maxLength, String pattern) {
    }

    public JsonNode definition() {
        return entry.path("definition");
    }
}
