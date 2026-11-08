package pl.aiwcorpo.mcp.gateway.support;

import java.net.URI;
import java.time.Instant;
import java.util.List;

import pl.aiwcorpo.mcp.gateway.registry.ServerConfig;

/** Settings of a server for tests that need one in the registry, with the connection approved as {@code ca}. */
public final class Configs {

    private Configs() {
    }

    public static ServerConfig connected(String serverId, String system, URI url, ServerConfig.Credential credential, boolean enabled,
                                         boolean adapter) {
        return new ServerConfig(serverId, system, url, credential, enabled, adapter, false, ServerConfig.CONNECTED, null, null,
                new ServerConfig.Connection("ca", null, null, null, List.of(), null, "test", Instant.parse("2026-11-08T00:00:00Z")), null);
    }

    /** The same server before an administrator approved its connection. */
    public static ServerConfig waiting(String serverId, String system, URI url, ServerConfig.Credential credential) {
        return new ServerConfig(serverId, system, url, credential, true, false, false, ServerConfig.PENDING_APPROVAL, null, null, null, null);
    }
}
