package pl.aiwcorpo.mcp.gateway.registry;

import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.jwt.UuidV7;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.server.ServerRegistry;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * The development stack only ({@code gateway.registry.bootstrap-from-server}): a server that was added and has no approved connection gets
 * the connection as the gateway proposed it, its policies and every pending tool approved, as an administrator would one by one
 * (trust on first use: nobody sits in the portal of a developer's machine). Never replaces an approval that exists and never classifies
 * the tools of an adapter, which need an administrator's risk and action.
 */
public final class DevBootstrap implements Runnable {

    private static final Logger log = LoggerFactory.getLogger(DevBootstrap.class);
    private static final GatewayUser DEVELOPER = new GatewayUser("dev-bootstrap", "dev-bootstrap", "mcp-portal-bff",
            List.of("mcp-platform-admin"), "unused");

    private final ServerRegistry servers;
    private final RegistryService registry;
    private final ServerAdmin admin;
    private final RegistryStore store;
    private final JsonMapper json;

    public DevBootstrap(ServerRegistry servers, RegistryService registry, ServerAdmin admin, RegistryStore store, JsonMapper json) {
        this.servers = servers;
        this.registry = registry;
        this.admin = admin;
        this.store = store;
        this.json = json;
    }

    @Override
    public void run() {
        for (McpServer server : servers.all()) {
            if (server.adapter() || !server.enabled() || server.connectionApproved()) {
                continue;
            }
            Optional<ServerConfig> config = store.config(server.serverId());
            Optional<RegisteredServer> state = registry.registered(server.serverId());
            if (config.isEmpty() || config.get().pendingConnection() == null || state.isEmpty()) {
                continue;
            }
            ServerConfig.PendingConnection pending = config.get().pendingConnection();
            String requestId = UuidV7.next();
            ObjectNode body = json.createObjectNode().put("tlsMode", pending.tlsMode());
            body.put("fingerprint", pending.fingerprint());
            if (!admin.approveConnection(requestId, server.serverId(), body, DEVELOPER).succeeded()) {
                continue;
            }
            RegisteredServer held = registry.registered(server.serverId()).orElse(state.get());
            if (held.policies().pending()) {
                registry.approvePolicies(requestId, server.serverId(), held.policies().pendingHash(), DEVELOPER);
            }
            registry.approveAllPending(requestId, server.serverId(), DEVELOPER);
            log.info("{} approved on first use (the development bootstrap)", server.serverId());
        }
    }
}
