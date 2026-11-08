package pl.aiwcorpo.mcp.gateway.registry;

import java.util.Optional;

import pl.aiwcorpo.mcp.gateway.link.ServerLinks;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import tools.jackson.databind.JsonNode;

/**
 * The manifest of a running server (C6, C14), pulled under the approved trust of its connection with a token of purpose {@code manifest}:
 * what the check of the definitions of a running server compares the hash of its policies with. A server whose connection is not approved is
 * not asked.
 */
public class ManifestFetcher {

    private final ServerLinks links;

    public ManifestFetcher(ServerLinks links) {
        this.links = links;
    }

    public Optional<JsonNode> fetch(McpServer server) {
        if (!server.connectionApproved()) {
            return Optional.empty();
        }
        ServerLinks.Pull pull = links.pullManifest(server.internalUrl(), server.connection().tlsMode(),
                server.connection().fingerprint());
        return pull.succeeded() ? Optional.of(pull.manifest()) : Optional.empty();
    }
}
