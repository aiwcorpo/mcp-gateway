package pl.aiwcorpo.mcp.gateway.mcp;

import pl.aiwcorpo.mcp.gateway.server.McpServer;

/** What the client addressed: the aggregate endpoint {@code /mcp} (no server) or one system's {@code /s/<serverId>/mcp}. */
public record Target(McpServer server) {

    public static final String AGGREGATE_ROUTE = "/mcp";

    public static Target aggregate() {
        return new Target(null);
    }

    public static Target of(McpServer server) {
        return new Target(server);
    }

    public boolean aggregateEndpoint() {
        return server == null;
    }

    /** The path a session is bound to (CC-184). */
    public String route() {
        return server == null ? AGGREGATE_ROUTE : "/s/" + server.serverId() + "/mcp";
    }

    /** System of the route without {@code mcp-}, or null on {@code /mcp}: the only value {@code systems} may take there (CC-169). */
    public String routeSystem() {
        return server == null ? null : server.system();
    }

    /** Part of the key of the conversation with the servers: a session reused on another route would be another conversation. */
    public String label() {
        return server == null ? "mcp" : server.serverId();
    }
}
