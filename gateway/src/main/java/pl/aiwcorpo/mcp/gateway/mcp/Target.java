package pl.aiwcorpo.mcp.gateway.mcp;

import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.virtual.VirtualServer;

/** What the client addressed: one full server ({@code /s/<serverId>/mcp}) or one of its links ({@code /v/<slug>/mcp}). */
public record Target(McpServer server, VirtualServer link) {

    public static Target of(McpServer server) {
        return new Target(server, null);
    }

    public static Target of(VirtualServer link) {
        return new Target(null, link);
    }

    /** Slug for {@code vs} (C2) and {@code virtualServer} (C8); null for a full server. */
    public String virtualSlug() {
        return link == null ? null : link.slug();
    }

    /** Name in serverInfo and in metrics: the server id or {@code vs/<slug>}. */
    public String label() {
        return link == null ? server.serverId() : "vs/" + link.slug();
    }
}
