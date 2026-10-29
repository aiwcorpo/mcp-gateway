package pl.aiwcorpo.mcp.gateway.registry;

import tools.jackson.databind.JsonNode;

/**
 * One tool of a server in the registry: the definition in force ({@code approved}), the one that waits for an administrator
 * ({@code pending}), or both. An entry is the manifest tool entry (C6: name, risk, action, resourceRefs, definition,
 * definitionHash); {@code credentialJson} is the credential object of the manifest it came with, a part of its hash.
 */
public record RegisteredTool(String name, Approved approved, Pending pending) {

    public record Approved(JsonNode entry, String hash, String version, String credentialJson) {
    }

    /**
     * {@code change} is {@code new} or {@code changed}, {@code source} is {@code ci} or {@code server} (CC-162); {@code riskLowered}: the
     * entry has a risk below the floor and only an administrator who accepts the lowering can approve it (CC-167).
     */
    public record Pending(JsonNode entry, String hash, String version, String change, String source, String credentialJson,
                          boolean riskLowered) {
        public Pending(JsonNode entry, String hash, String version, String change, String source, String credentialJson) {
            this(entry, hash, version, change, source, credentialJson, false);
        }
    }

    public RegisteredTool {
        if (approved == null && pending == null) {
            throw new IllegalArgumentException("a registered tool has an approved or a pending entry");
        }
    }

    public RegisteredTool withPending(Pending next) {
        return new RegisteredTool(name, approved, next);
    }

    public int approvedRisk() {
        return approved == null ? 0 : pl.aiwcorpo.mcp.gateway.server.Risk.valueOf(approved.entry().path("risk").asString()).ordinal();
    }
}
