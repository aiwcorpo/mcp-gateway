package pl.aiwcorpo.mcp.gateway.registry;

import tools.jackson.databind.JsonNode;

/**
 * One static resource, resource template or prompt of a server in the registry (CC-258, CC-265): the entry in force ({@code approved}),
 * the one that waits for an administrator ({@code pending}), or both. An entry is the manifest entry of its kind, with its
 * {@code definitionHash}. Unlike a tool it has no risk, so nothing here is classified and no floor applies.
 */
public record RegisteredEntry(PrimitiveKind kind, String name, Approved approved, Pending pending) {

    public record Approved(JsonNode entry, String hash, String version) {
    }

    /** {@code change} is {@code new} or {@code changed}; {@code source} is {@code manifest}, or {@code adapter} for a server behind an adapter. */
    public record Pending(JsonNode entry, String hash, String version, String change, String source) {
    }

    public RegisteredEntry {
        if (approved == null && pending == null) {
            throw new IllegalArgumentException("a registered entry has an approved or a pending entry");
        }
    }
}
