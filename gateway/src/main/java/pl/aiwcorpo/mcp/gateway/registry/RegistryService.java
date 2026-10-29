package pl.aiwcorpo.mcp.gateway.registry;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;

import pl.aiwcorpo.mcp.gateway.audit.AuditEvent;
import pl.aiwcorpo.mcp.gateway.audit.AuditLog;
import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.jwt.UuidV7;
import pl.aiwcorpo.mcp.gateway.registry.DefinitionGuard.Verdict;
import pl.aiwcorpo.mcp.gateway.registry.ManifestValidator.Rejection;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.server.Risk;
import pl.aiwcorpo.mcp.gateway.server.ServerRegistry;
import pl.aiwcorpo.mcp.gateway.server.ToolDefinition;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * The definitions of the servers' tools (C5/C6, CC-097, CC-133, CC-161, CC-162). The pipeline of a reviewed commit registers a
 * manifest: its READ_ONLY tools are approved, its UPDATE and DESTRUCTIVE tools wait for an administrator
 * ({@link #approve}), removed tools are removed, a lowered risk is refused. A definition that a running server presents and that
 * is not the approved one is no registration: it blocks the tool and, unless a pending entry of the pipeline is already there,
 * leaves a pending entry with source {@code server} for the administrator to look at ({@link #observe}).
 */
public final class RegistryService {

    private static final Logger log = LoggerFactory.getLogger(RegistryService.class);
    private static final Pattern SEMVER = Pattern.compile(
            "^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\\+[0-9A-Za-z.-]+)?$");

    public sealed interface Result {
        record Accepted(RegisteredServer server) implements Result {
        }

        record Rejected(List<Rejection> rejections) implements Result {
            /** The reason of the response: the first refusal that has one, else none. */
            public String reason() {
                return rejections.stream().map(Rejection::reason).filter(java.util.Objects::nonNull).findFirst().orElse(null);
            }

            public String message() {
                return String.join("; ", rejections.stream().map(Rejection::message).toList());
            }
        }

        record UnknownServer() implements Result {
        }
    }

    public sealed interface Approval {
        record Approved() implements Approval {
        }

        record NotFound() implements Approval {
        }

        record HashMismatch() implements Approval {
        }

        record RiskLowered(String message) implements Approval {
        }
    }

    /** The approved and the pending entry of a tool for the diff of the portal. */
    public record PendingView(RegisteredTool.Approved approved, RegisteredTool.Pending pending) {
    }

    private sealed interface Written {
        record Done(RegistryPlanner.Plan plan) implements Written {
        }

        record Lowered(List<String> tools) implements Written {
        }

        record AlreadyThere() implements Written {
        }
    }

    private final ServerRegistry servers;
    private final RegistryStore store;
    private final ManifestValidator validator;
    private final ManifestFetcher fetcher;
    private final DefinitionGuard guard;
    private final DefinitionCheck definitionCheck;
    private final AuditLog audit;
    private final String componentId;
    private final JsonMapper json;
    private final Map<String, RegisteredServer> held = new ConcurrentHashMap<>();

    public RegistryService(ServerRegistry servers, RegistryStore store, ManifestValidator validator, ManifestFetcher fetcher,
                           DefinitionGuard guard, DefinitionCheck definitionCheck, AuditLog audit, String componentId,
                           JsonMapper json) {
        this.servers = servers;
        this.store = store;
        this.validator = validator;
        this.fetcher = fetcher;
        this.guard = guard;
        this.definitionCheck = definitionCheck;
        this.audit = audit;
        this.componentId = componentId;
        this.json = json;
    }

    /**
     * Takes what the stored runs approved. A held manifest that no longer passes the checks (the credential types of the
     * configuration, the environment) is not replaced and not removed: its server is disabled, its tools answer tool_disabled,
     * until a manifest that passes is registered (CC-159).
     */
    public void load() {
        for (RegistryStore.StoredServer stored : store.servers()) {
            Optional<McpServer> server = servers.find(stored.serverId());
            if (server.isEmpty() || !server.get().approvalRequired()) {
                continue;
            }
            take(stored.serverId());
        }
    }

    public Result register(String requestId, String serverId, JsonNode manifest, String source) {
        return write(requestId, serverId, manifest, source, false);
    }

    private Result write(String requestId, String serverId, JsonNode manifest, String source, boolean bootstrap) {
        Optional<McpServer> server = servers.find(serverId);
        if (server.isEmpty()) {
            return new Result.UnknownServer();
        }
        if (!server.get().approvalRequired()) {
            return new Result.Rejected(List.of(new Rejection(null, "this server takes its tools from the gateway configuration")));
        }
        List<Rejection> rejections = validator.check(manifest, server.get());
        if (!rejections.isEmpty()) {
            denied(requestId, serverId, rejections.stream().map(Rejection::reason).filter(java.util.Objects::nonNull).findFirst().orElse(null));
            return new Result.Rejected(rejections);
        }
        String credentialJson = validator.credentialJson(manifest);
        Written written = store.locked(serverId, tx -> {
            if (bootstrap && tx.server().isPresent()) {
                return new Written.AlreadyThere();
            }
            Map<String, Integer> minimum = new java.util.HashMap<>(servers.configuredMinimumRisks(serverId));
            tx.floors().forEach((name, risk) -> minimum.merge(name, risk, Math::max));
            Map<String, RegisteredTool> existing = tx.tools();
            RegistryPlanner.Plan plan = RegistryPlanner.plan(manifest, credentialJson, existing, minimum, bootstrap);
            if (!plan.lowered().isEmpty()) {
                return new Written.Lowered(plan.lowered());
            }
            tx.saveServer(manifest, source);
            existing.keySet().stream().filter(name -> !plan.tools().containsKey(name)).forEach(tx::deleteTool);
            plan.tools().forEach((name, tool) -> {
                if (!tool.equals(existing.get(name))) {
                    tx.saveTool(tool);
                }
            });
            tx.raiseFloors(plan.risks());
            return new Written.Done(plan);
        });
        return switch (written) {
            case Written.Done done -> {
                take(serverId);
                done.plan().changes().forEach(change -> changed(requestId, serverId, change));
                yield new Result.Accepted(held.get(serverId));
            }
            case Written.Lowered lowered -> {
                denied(requestId, serverId, "risk_lowered");
                yield new Result.Rejected(List.of(new Rejection("risk_lowered", "the risk of " + String.join(", ", lowered.tools())
                        + " is lower than what was approved before")));
            }
            case Written.AlreadyThere there -> {
                // Another instance (or a registration a moment ago) came first: this instance takes that state.
                take(serverId);
                yield new Result.Rejected(List.of(new Rejection(null, "this server has an approved manifest")));
            }
        };
    }

    /** Approves the pending definition whose hash is {@code hash} (CC-133); the administrator is the actor of the audit event. */
    public Approval approve(String requestId, String serverId, String tool, String hash, GatewayUser administrator) {
        Optional<McpServer> server = servers.find(serverId);
        if (server.isEmpty() || !server.get().approvalRequired()) {
            return new Approval.NotFound();
        }
        Approval result = store.locked(serverId, tx -> {
            RegisteredTool current = tx.tools().get(tool);
            if (current == null || current.pending() == null) {
                return new Approval.NotFound();
            }
            RegisteredTool.Pending pending = current.pending();
            if (!pending.hash().equals(hash)) {
                return new Approval.HashMismatch();
            }
            int risk = Risk.valueOf(pending.entry().path("risk").asString()).ordinal();
            int floor = Math.max(tx.floors().getOrDefault(tool, 0), Math.max(servers.configuredMinimumRisks(serverId).getOrDefault(tool, 0),
                    current.approvedRisk()));
            if (risk < floor) {
                return new Approval.RiskLowered(tool + " lowers risk from " + Risk.values()[floor] + " to " + Risk.values()[risk]);
            }
            tx.saveTool(new RegisteredTool(tool, new RegisteredTool.Approved(pending.entry(), pending.hash(), pending.version(),
                    pending.credentialJson()), null));
            tx.raiseFloors(Map.of(tool, risk));
            return new Approval.Approved();
        });
        if (result instanceof Approval.Approved) {
            take(serverId);
            audit.emit(AuditEvent.of("admin_change", requestId, componentId).userWithoutClient(administrator).server(serverId).tool(tool)
                    .reason("definition_approved").definitionHash(hash).outcome("ok"));
        } else if (result instanceof Approval.RiskLowered) {
            denied(requestId, serverId, "risk_lowered");
        }
        return result;
    }

    public Optional<PendingView> pending(String serverId, String tool) {
        RegisteredServer server = held.get(serverId);
        RegisteredTool registered = server == null ? null : server.tools().get(tool);
        if (registered == null || registered.pending() == null) {
            return Optional.empty();
        }
        return Optional.of(new PendingView(registered.approved(), registered.pending()));
    }

    public Optional<RegisteredServer> registered(String serverId) {
        return Optional.ofNullable(held.get(serverId));
    }

    /**
     * Compares what a running server presents with the approved definitions (CC-133, CC-162). The verdict of every approved tool:
     * intact, changed (the definition differs; the approved risk, action and references stay in the hash), or not served. A changed
     * tool gets a pending entry with source {@code server} unless an entry of the pipeline is pending already (that one is never
     * replaced by what the server says); a server that presents the approved definition again loses its own pending entry.
     * A failure of the store does not change a verdict: the tool stays blocked.
     */
    public Map<String, Verdict> observe(McpServer server, Map<String, JsonNode> live, String serverVersion) {
        Map<String, Verdict> verdicts = new LinkedHashMap<>();
        Map<String, String> changedHashes = new LinkedHashMap<>();
        for (ToolDefinition tool : server.tools().values()) {
            JsonNode presented = live.get(tool.name());
            if (presented == null) {
                verdicts.put(tool.name(), Verdict.NOT_SERVED);
            } else if (definitionCheck.intact(server, tool, presented)) {
                verdicts.put(tool.name(), Verdict.INTACT);
            } else {
                verdicts.put(tool.name(), Verdict.CHANGED);
                definitionCheck.hashOf(server, tool, presented).ifPresent(hash -> changedHashes.put(tool.name(), hash));
            }
        }
        if (server.approvalRequired() && needsRecording(server.serverId(), verdicts, changedHashes)) {
            try {
                recordServerEntries(server, live, serverVersion, verdicts, changedHashes);
            } catch (DataAccessException e) {
                log.warn("{}: the definitions the server presented could not be recorded: {}", server.serverId(), e.getClass().getName());
            }
        }
        return verdicts;
    }

    private boolean needsRecording(String serverId, Map<String, Verdict> verdicts, Map<String, String> changedHashes) {
        RegisteredServer state = held.get(serverId);
        if (state == null) {
            return false;
        }
        for (Map.Entry<String, Verdict> verdict : verdicts.entrySet()) {
            RegisteredTool tool = state.tools().get(verdict.getKey());
            RegisteredTool.Pending pending = tool == null ? null : tool.pending();
            if (verdict.getValue() == Verdict.CHANGED && changedHashes.containsKey(verdict.getKey())
                    && (pending == null || ("server".equals(pending.source()) && !pending.hash().equals(changedHashes.get(verdict.getKey()))))) {
                return true;
            }
            if (verdict.getValue() == Verdict.INTACT && pending != null && "server".equals(pending.source())) {
                return true;
            }
        }
        return false;
    }

    private void recordServerEntries(McpServer server, Map<String, JsonNode> live, String serverVersion, Map<String, Verdict> verdicts,
                                     Map<String, String> changedHashes) {
        boolean[] touched = {false};
        store.locked(server.serverId(), tx -> {
            Map<String, RegisteredTool> tools = tx.tools();
            verdicts.forEach((name, verdict) -> {
                RegisteredTool tool = tools.get(name);
                if (tool == null || tool.approved() == null) {
                    return;
                }
                RegisteredTool.Pending pending = tool.pending();
                ToolDefinition approved = server.tools().get(name);
                if (verdict == Verdict.INTACT && pending != null && "server".equals(pending.source())) {
                    tx.saveTool(tool.withPending(null));
                    touched[0] = true;
                } else if (verdict == Verdict.CHANGED && approved != null && changedHashes.containsKey(name)
                        && (pending == null || ("server".equals(pending.source()) && !pending.hash().equals(changedHashes.get(name))))) {
                    ObjectNode entry = definitionCheck.entryOf(approved);
                    ObjectNode full = json.createObjectNode();
                    full.put("name", name);
                    full.set("risk", entry.get("risk"));
                    full.set("action", entry.get("action"));
                    full.set("resourceRefs", entry.get("resourceRefs"));
                    full.set("definition", live.get(name));
                    full.put("definitionHash", changedHashes.get(name));
                    String version = serverVersion != null && SEMVER.matcher(serverVersion).matches() ? serverVersion
                            : tool.approved().version();
                    tx.saveTool(tool.withPending(new RegisteredTool.Pending(full, changedHashes.get(name), version, "changed", "server",
                            tool.approved().credentialJson())));
                    touched[0] = true;
                }
            });
            return null;
        });
        if (touched[0]) {
            take(server.serverId());
        }
    }

    /**
     * The dev stack only: servers that need a manifest and have no stored row at all get the one they serve, all of it approved
     * (there is no reviewed commit behind it, so this is trust on first use). Written insert-only: a state that exists, or appears
     * meanwhile, is never replaced by what a server says about itself.
     */
    public void bootstrapMissing() {
        for (McpServer server : servers.requiringApproval()) {
            if (held.containsKey(server.serverId()) || !server.enabled() || store.findServer(server.serverId()).isPresent()) {
                continue;
            }
            fetcher.fetch(server).ifPresent(manifest -> {
                Result result = write(UuidV7.next(), server.serverId(), manifest, "bootstrap", true);
                if (result instanceof Result.Rejected rejected) {
                    log.error("manifest served by {} not taken: {}", server.serverId(), rejected.message());
                } else {
                    log.info("manifest of {} taken as approved", server.serverId());
                }
            });
        }
    }

    /**
     * Takes the stored state that another instance wrote or changed since this one looked (HA: instances share the tables, not
     * memory). A state that is unchanged is left alone.
     */
    public void reloadChanged() {
        for (RegistryStore.StoredServer stored : store.servers()) {
            RegisteredServer now = read(stored);
            RegisteredServer before = held.get(stored.serverId());
            if (now != null && !now.equals(before)) {
                take(stored.serverId());
            }
        }
    }

    private RegisteredServer read(RegistryStore.StoredServer stored) {
        if (servers.find(stored.serverId()).filter(McpServer::approvalRequired).isEmpty()) {
            return null;
        }
        return new RegisteredServer(stored.serverId(), stored.manifest().path("system").asString(),
                stored.manifest().path("version").asString(), stored.manifest(), stored.source(), store.tools(stored.serverId()));
    }

    /** Reads the stored state of a server into memory and hands the approved tools to the server registry. */
    private void take(String serverId) {
        Optional<RegistryStore.StoredServer> stored = store.findServer(serverId);
        Optional<McpServer> server = servers.find(serverId);
        if (stored.isEmpty() || server.isEmpty() || !server.get().approvalRequired()) {
            return;
        }
        RegisteredServer state = read(stored.get());
        List<Rejection> rejections = validator.check(state.manifest(), server.get());
        if (!rejections.isEmpty()) {
            log.error("held manifest of {} is no longer acceptable, the server is disabled: {}", serverId,
                    String.join("; ", rejections.stream().map(r -> r.reason() == null ? r.message() : r.reason()).toList()));
        }
        RegisteredServer before = held.put(serverId, state);
        servers.apply(serverId, state.version(), state.tools(), store.floors(serverId), rejections.isEmpty());
        if (!state.equals(before)) {
            guard.forget(serverId);
        }
    }

    private void changed(String requestId, String serverId, RegistryPlanner.Change change) {
        AuditEvent event = AuditEvent.of("admin_change", requestId, componentId).server(serverId).tool(change.tool())
                .reason(change.kind()).definitionHash(change.hash()).outcome("ok");
        audit.emit(event);
    }

    private void denied(String requestId, String serverId, String reason) {
        if (reason != null) {
            audit.emit(AuditEvent.of("admin_change", requestId, componentId).server(serverId).reason(reason).outcome("denied"));
        }
    }
}
