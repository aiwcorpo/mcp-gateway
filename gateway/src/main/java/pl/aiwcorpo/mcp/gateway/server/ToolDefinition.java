package pl.aiwcorpo.mcp.gateway.server;

/**
 * Tool known to the gateway: server-side name, risk, Cedar action (C6) and the texts shown in the catalog, from the
 * static configuration. {@code disabled} is an administrator switch (C10 tool_disabled); {@code title} may be null.
 */
public record ToolDefinition(String name, Risk risk, String action, String title, String description, boolean disabled,
                             java.util.List<pl.aiwcorpo.mcp.cedar.entities.ResourceRef> resourceRefs) {

    /** DESTRUCTIVE tools need a confirmation on every call (C11). */
    public boolean requiresConfirmation() {
        return risk == Risk.DESTRUCTIVE;
    }
}
