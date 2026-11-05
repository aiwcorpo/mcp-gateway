package pl.aiwcorpo.mcp.gateway.server;

import java.util.Optional;

/** Where a tool name of the client goes: {@code <system>__<tool>} to the server {@code mcp-<system>} (CC-169). */
public record ToolRoute(String serverId, String tool) {

    /** Empty for a name without the separator, with an empty system or tool, or naming a system the gateway does not know. */
    public static Optional<ToolRoute> of(String qualifiedName, java.util.Collection<String> knownSystems) {
        if (qualifiedName == null) {
            return Optional.empty();
        }
        int separator = qualifiedName.indexOf("__");
        if (separator <= 0) {
            return Optional.empty();
        }
        String system = qualifiedName.substring(0, separator);
        String tool = qualifiedName.substring(separator + 2);
        if (tool.isEmpty() || !knownSystems.contains(system)) {
            return Optional.empty();
        }
        return Optional.of(new ToolRoute("mcp-" + system, tool));
    }
}
