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

    /**
     * Takes the manifests stored by earlier runs. A stored manifest that no longer passes leaves its server without tools
     * (fail-closed) until a new registration, and the risks it names still count for the floors.
     */
    public void load() {
        for (RegistryStore.Stored stored : store.all()) {
            Optional<McpServer> server = servers.find(stored.serverId());
            if (server.isEmpty() || !server.get().approvalRequired()) {
                continue;
            }
            store.raiseFloors(stored.serverId(), lenientRisks(stored.manifest()));
            List<String> reasons = validator.violations(stored.manifest(), server.get());
            if (reasons.isEmpty()) {
                take(validator.approved(stored.manifest()));
            } else {
                log.error("stored manifest of {} is no longer acceptable, the server has no tools: {}", stored.serverId(), reasons);
            }
        }
    }

    public Result register(String serverId, JsonNode manifest, String source) {
        return write(serverId, manifest, source, false);
    }

    private Result write(String serverId, JsonNode manifest, String source, boolean insertOnly) {
        Optional<McpServer> server = servers.find(serverId);
        if (server.isEmpty()) {
            return new Result.UnknownServer();
        }
        if (!server.get().approvalRequired()) {
            return new Result.Rejected(List.of("this server takes its tools from the gateway configuration"));
        }
        List<String> reasons = validator.violations(manifest, server.get());
        if (!reasons.isEmpty()) {
            return new Result.Rejected(reasons);
        }
        ApprovedServer candidate = validator.approved(manifest);
        Map<String, Integer> risks = new java.util.HashMap<>();
        candidate.tools().forEach((name, tool) -> risks.put(name, Risk.valueOf(tool.risk()).ordinal()));
        RegistryStore.Written written = store.write(serverId, manifest, source, risks, servers.configuredMinimumRisks(serverId),
                insertOnly);
        return switch (written) {
            case RegistryStore.Written.Done done -> {
                take(candidate);
                yield new Result.Accepted(candidate);
            }
            case RegistryStore.Written.Lowered lowered -> new Result.Rejected(List.of("the risk of " + String.join(", ", lowered.tools())
                    + " is lower than what was approved before: that needs an administrator"));
            case RegistryStore.Written.AlreadyThere there -> new Result.Rejected(List.of("this server has an approved manifest"));
        };
    }

    private void take(ApprovedServer server) {
        approved.put(server.serverId(), server);
        servers.apply(server);
        guard.forget(server.serverId());
    }

    public Optional<ApprovedServer> approved(String serverId) {
        return Optional.ofNullable(approved.get(serverId));
    }

    /**
     * Servers that need a manifest and have no approval at all (no stored row, valid or not) get the one they serve. It is
     * written insert-only: an approval that exists, or appears meanwhile, is never replaced by what a server says about itself.
     */
    public void bootstrapMissing() {
        for (McpServer server : servers.requiringApproval()) {
            if (approved.containsKey(server.serverId()) || !server.enabled() || store.find(server.serverId()).isPresent()) {
                continue;
            }
            fetcher.fetch(server).ifPresent(manifest -> {
                Result result = write(server.serverId(), manifest, "bootstrap", true);
                if (result instanceof Result.Rejected rejected) {
                    log.error("manifest served by {} not taken: {}", server.serverId(), rejected.reasons());
                } else {
                    log.info("manifest of {} taken as approved", server.serverId());
                }
            });
        }
    }

    /** Risks named by a stored manifest, read without trusting its shape: whatever is readable counts. */
    private static Map<String, Integer> lenientRisks(JsonNode manifest) {
        Map<String, Integer> risks = new java.util.HashMap<>();
        for (JsonNode tool : manifest.path("tools")) {
            String name = tool.path("name").asString(null);
            String risk = tool.path("risk").asString(null);
            if (name != null && name.length() <= 64 && risk != null) {
                try {
                    risks.put(name, Risk.valueOf(risk).ordinal());
                } catch (IllegalArgumentException e) {
                    // not a risk of C6: nothing to raise
                }
            }
        }
        return risks;
    }
}
