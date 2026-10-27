package pl.aiwcorpo.mcp.gateway.broker;

import java.util.HashSet;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;

import pl.aiwcorpo.mcp.gateway.jwt.UuidV7;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.server.ServerRegistry;
import tools.jackson.databind.JsonNode;

/**
 * Start-up comparison of the static server configuration with {@code GET /v1/systems} of the broker (service
 * variant of C2, CC-030). Only warns: the broker may start later, and every call is checked anyway.
 */
public class SystemsCheck {

    private static final Logger log = LoggerFactory.getLogger(SystemsCheck.class);

    private final BrokerClient broker;
    private final ServerRegistry servers;

    public SystemsCheck(BrokerClient broker, ServerRegistry servers) {
        this.broker = broker;
        this.servers = servers;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void check() {
        Thread.ofVirtual().name("broker-systems-check").start(this::run);
    }

    private void run() {
        String requestId = UuidV7.next();
        try {
            JsonNode systems = broker.systems(requestId);
            for (McpServer server : servers.all()) {
                if (!server.credential().required()) {
                    continue;
                }
                JsonNode entry = null;
                for (JsonNode system : systems) {
                    if (server.system().equals(system.path("system").asString(null))) {
                        entry = system;
                    }
                }
                if (entry == null) {
                    log.warn("Broker does not know system {} of {}: its tools will fail", server.system(), server.serverId());
                    continue;
                }
                Set<String> supported = new HashSet<>();
                entry.path("supportedTypes").forEach(t -> supported.add(t.asString()));
                if (supported.stream().noneMatch(server.credential().acceptedTypes()::contains)) {
                    log.warn("Broker types {} for {} do not overlap accepted types {}", supported, server.system(),
                            server.credential().acceptedTypes());
                } else {
                    log.info("Broker system {} ready ({})", server.system(), supported);
                }
            }
        } catch (Exception e) {
            log.warn("Broker GET /v1/systems rid={} failed ({}); continuing", requestId, e.getClass().getSimpleName());
        }
    }
}
