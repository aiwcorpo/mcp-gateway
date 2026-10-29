package pl.aiwcorpo.mcp.gateway.server;

import tools.jackson.databind.JsonNode;

/**
 * Tool known to the gateway (from an approved manifest, or from the static configuration when the server has none): server-side name, risk, Cedar action (C6) and the texts shown in the catalog, from the
 * static configuration. {@code disabled} is an administrator switch (C10 tool_disabled); {@code title} may be null. For a tool of an
 * approved manifest {@code definition} is the approved MCP definition (what the client is shown), {@code definitionHash} its hash and
 * {@code credentialJson} the credential object that hash was computed with.
 */
public record ToolDefinition(String name, Risk risk, String action, String title, String description, boolean disabled,
                             java.util.List<pl.aiwcorpo.mcp.cedar.entities.ResourceRef> resourceRefs, String definitionHash,
                             JsonNode definition, String credentialJson) {

    /** The tool without a hash to check: static configuration. */
    public ToolDefinition(String name, Risk risk, String action, String title, String description, boolean disabled,
                          java.util.List<pl.aiwcorpo.mcp.cedar.entities.ResourceRef> resourceRefs) {
        this(name, risk, action, title, description, disabled, resourceRefs, null, null, null);
    }

    /** DESTRUCTIVE tools need a confirmation on every call (C11). */
    public boolean requiresConfirmation() {
        return risk == Risk.DESTRUCTIVE;
    }
}
