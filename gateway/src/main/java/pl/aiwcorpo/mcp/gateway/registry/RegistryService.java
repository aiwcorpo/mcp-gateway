package pl.aiwcorpo.mcp.gateway.registry;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.server.Risk;
import pl.aiwcorpo.mcp.gateway.server.ServerRegistry;
import tools.jackson.databind.JsonNode;

/**
 * The approved definitions of the servers (C5/C6), the M3 form: a manifest that passes {@link ManifestValidator} becomes the
 * approved set of its server as a whole, and the server's live definitions must keep matching it. The registering party is the
 * approval: CI by {@code registerServer}, or, once, the manifest the server itself serves when none is approved yet (bootstrap).
 * Pinning of single tools, the diff and the approval by an administrator (CC-097) are M4; until then a manifest that would
 * lower the risk of an approved tool is refused instead of accepted.
 */
public final class RegistryService {

    private static final Logger log = LoggerFactory.getLogger(RegistryService.class);

    public sealed interface Result {
        record Accepted(ApprovedServer server) implements Result {
        }

        record Rejected(List<String> reasons) implements Result {
        }

        record UnknownServer() implements Result {
        }
    }

    private final ServerRegistry servers;
    private final RegistryStore store;
    private final ManifestValidator validator;
    private final ManifestFetcher fetcher;
    private final DefinitionGuard guard;
    private final Map<String, ApprovedServer> approved = new ConcurrentHashMap<>();

    public RegistryService(ServerRegistry servers, RegistryStore store, ManifestValidator validator, ManifestFetcher fetcher,
                           DefinitionGuard guard) {
        this.servers = servers;
        this.store = store;
        this.validator = validator;
        this.fetcher = fetcher;
        this.guard = guard;
    }

    /** Takes the manifests stored by earlier runs; a stored manifest that no longer passes is ignored and logged. */
    public void load() {
        for (RegistryStore.Stored stored : store.all()) {
            Optional<McpServer> server = servers.find(stored.serverId());
            if (server.isEmpty() || !server.get().approvalRequired()) {
                continue;
            }
            List<String> reasons = validator.violations(stored.manifest(), server.get());
            if (reasons.isEmpty()) {
                take(validator.approved(stored.manifest()));
            } else {
                log.error("stored manifest of {} is no longer acceptable: {}", stored.serverId(), reasons);
            }
        }
    }

    public Result register(String serverId, JsonNode manifest, String source) {
        Optional<McpServer> server = servers.find(serverId);
        if (server.isEmpty()) {
            return new Result.UnknownServer();
        }
        if (!server.get().approvalRequired()) {
            return new Result.Rejected(List.of("this server takes its tools from the gateway configuration"));
        }
        List<String> reasons = new ArrayList<>(validator.violations(manifest, server.get()));
        if (reasons.isEmpty()) {
            ApprovedServer candidate = validator.approved(manifest);
            ApprovedServer current = approved.get(serverId);
            if (current != null) {
                candidate.tools().forEach((name, tool) -> {
                    ApprovedTool before = current.tools().get(name);
                    if (before != null && Risk.valueOf(tool.risk()).ordinal() < Risk.valueOf(before.risk()).ordinal()) {
                        reasons.add("the risk of tool " + name + " was lowered: that needs an approval");
                    }
                });
            }
            if (reasons.isEmpty()) {
                store.save(serverId, manifest, source);
                take(candidate);
                return new Result.Accepted(candidate);
            }
        }
        return new Result.Rejected(List.copyOf(reasons));
    }

    private void take(ApprovedServer server) {
        approved.put(server.serverId(), server);
        servers.apply(server);
        guard.forget(server.serverId());
    }

    public Optional<ApprovedServer> approved(String serverId) {
        return Optional.ofNullable(approved.get(serverId));
    }

    /** Servers that need an approved manifest and have none get the one they serve. Safe to call repeatedly. */
    public void bootstrapMissing() {
        for (McpServer server : servers.requiringApproval()) {
            if (approved.containsKey(server.serverId()) || !server.enabled()) {
                continue;
            }
            fetcher.fetch(server).ifPresent(manifest -> {
                Result result = register(server.serverId(), manifest, "bootstrap");
                if (result instanceof Result.Rejected rejected) {
                    log.error("manifest served by {} refused: {}", server.serverId(), rejected.reasons());
                } else {
                    log.info("manifest of {} taken as approved", server.serverId());
                }
            });
        }
    }
}
