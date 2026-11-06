package pl.aiwcorpo.mcp.gateway.registry;

import java.net.URI;
import java.util.List;

/**
 * The connection settings of one server as an administrator gave them (C5 {@code ServerConfig}): the rows of table {@code servers}.
 * The tools of the server are not here; they come from its approved manifest.
 */
public record ServerConfig(String serverId, String system, URI internalUrl, String tlsName, Credential credential, boolean enabled,
                           boolean adapter) {

    /** {@code type} is the default credential type of the system and goes into {@code context.credentialType} (CC-136). */
    public record Credential(boolean required, List<String> acceptedTypes, String type) {
        public Credential {
            acceptedTypes = List.copyOf(acceptedTypes);
        }
    }

    public static String defaultTlsName(String serverId) {
        return serverId + ".internal";
    }
}
