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
        /** {@code loweredTo}: the new risk (ordinal) when an administrator accepted a lowering, else -1. */
        record Approved(int loweredTo) implements Approval {
        }

        record NotFound() implements Approval {
        }

        record HashMismatch() implements Approval {
        }

        record RiskLowered(String message) implements Approval {
        }

        /** The classification of an entry of an adapter is missing, given for another entry, or does not fit (CC-193, CC-207). */
        record Rejected(String reason, String message) implements Approval {
        }
    }

    /** The risk and the action an administrator gives to a tool of an adapter when approving it (CC-193). */
    public record Classification(String risk, String action) {
        private static final Map<String, List<String>> FITS = Map.of("READ_ONLY", List.of("read"), "UPDATE", List.of("update", "admin"),
                "DESTRUCTIVE", List.of("delete", "admin"));

        /** read is for READ_ONLY only, update for UPDATE, delete for DESTRUCTIVE, admin for UPDATE or DESTRUCTIVE (CC-207). */
        public boolean consistent() {
            return risk != null && action != null && FITS.getOrDefault(risk, List.of()).contains(action);
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
    private volatile Runnable onChange = () -> { };

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

    /** Told whenever the state this instance holds of a server changed: a registration, an approval, a removal, a change made elsewhere. */
    public void onChange(Runnable listener) {
        this.onChange = listener;
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
        return write(requestId, serverId, manifest, source, false, false);
    }

    /** The manifest an adapter submits at its start (CC-206): the channel of an adapter, which stores nothing as approved. */
    public Result submitAdapter(String requestId, String serverId, JsonNode manifest) {
        return write(requestId, serverId, manifest, "adapter", false, true);
    }

    private Result write(String requestId, String serverId, JsonNode manifest, String source, boolean bootstrap, boolean adapterChannel) {
        Optional<McpServer> server = servers.find(serverId);
        if (server.isEmpty()) {
            return new Result.UnknownServer();
        }
        // Which servers an adapter serves is configuration; a manifest on the wrong channel, or of the wrong kind, is refused whole (CC-206).
        boolean adapterManifest = "adapter".equals(manifest.path("source").asString(null));
        if (server.get().adapter() != adapterChannel || adapterManifest != adapterChannel) {
            denied(requestId, serverId, "adapter_mode_mismatch");
            return new Result.Rejected(List.of(new Rejection("adapter_mode_mismatch", adapterChannel
                    ? serverId + " is not served by an adapter" : server.get().adapter()
                    ? serverId + " is served by an adapter, which submits its manifest on its own channel"
                    : "the manifest of " + serverId + " says source adapter and the server is not served by an adapter")));
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
            Map<String, RegisteredTool> existing = tx.tools();
            RegistryPlanner.Plan plan = adapterChannel ? RegistryPlanner.planAdapter(manifest, credentialJson, existing)
                    : RegistryPlanner.plan(manifest, credentialJson, existing, tx.floors(), servers.configuredMinimumRisks(serverId), bootstrap);
            if (!plan.lowered().isEmpty()) {
                return new Written.Lowered(plan.lowered());
            }
            tx.saveServer(manifest, source);
            // The floor of the risk stays when a tool leaves (CC-167): a tool of an adapter that comes back is new and unclassified, and an
            // administrator who classifies it lower than before needs acceptRiskLowering.
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
    public Approval approve(String requestId, String serverId, String tool, String hash, boolean acceptRiskLowering,
                            GatewayUser administrator) {
        return approve(requestId, serverId, tool, hash, acceptRiskLowering, null, administrator);
    }

    /**
     * Approves the pending definition whose hash is {@code hash}. An entry of an adapter has no risk and no action: the administrator
     * gives both ({@code classification}), they must fit each other and a lower one than given before needs {@code acceptRiskLowering}
     * (CC-167, CC-193, CC-207). Any other entry takes none.
     */
    public Approval approve(String requestId, String serverId, String tool, String hash, boolean acceptRiskLowering,
                            Classification classification, GatewayUser administrator) {
        Optional<McpServer> server = servers.find(serverId);
        if (server.isEmpty() || !server.get().approvalRequired()) {
            return new Approval.NotFound();
        }
        java.time.Instant now = java.time.Instant.now().truncatedTo(java.time.temporal.ChronoUnit.MILLIS);
        Approval result = store.locked(serverId, tx -> {
            RegisteredTool current = tx.tools().get(tool);
            if (current == null || current.pending() == null) {
                return new Approval.NotFound();
            }
            RegisteredTool.Pending pending = current.pending();
            if (!pending.hash().equals(hash)) {
                return new Approval.HashMismatch();
            }
            boolean fromAdapter = "adapter".equals(pending.source());
            if (fromAdapter && (classification == null || classification.risk() == null || classification.action() == null)) {
                return new Approval.Rejected("classification_required", tool + " comes from an adapter and needs risk and action");
            }
            if (!fromAdapter && classification != null) {
                return new Approval.Rejected("classification_not_allowed", tool + " does not come from an adapter and takes no risk and action");
            }
            if (fromAdapter && !classification.consistent()) {
                return new Approval.Rejected("classification_inconsistent", classification.risk() + " does not fit the action " + classification.action());
            }
            int risk = Risk.valueOf(fromAdapter ? classification.risk() : pending.entry().path("risk").asString()).ordinal();
            int configured = servers.configuredMinimumRisks(serverId).getOrDefault(tool, 0);
            int floor = Math.max(tx.floors().getOrDefault(tool, 0), current.approvedRisk());
            boolean lowers = risk < floor;
            if (risk < configured || (lowers && !acceptRiskLowering)) {
                return new Approval.RiskLowered(tool + " lowers risk from " + Risk.values()[Math.max(floor, configured)] + " to " + Risk.values()[risk]);
            }
            JsonNode entry = pending.entry();
            if (fromAdapter) {
                ObjectNode classified = ((ObjectNode) entry).deepCopy();
                classified.put("risk", classification.risk());
                classified.put("action", classification.action());
                entry = classified;
            }
            tx.saveTool(new RegisteredTool(tool, new RegisteredTool.Approved(entry, pending.hash(), pending.version(),
                    pending.credentialJson(), fromAdapter ? administrator.sub() : null, fromAdapter ? now : null), null));
            if (lowers) {
                tx.setFloor(tool, risk);
                return new Approval.Approved(risk);
            }
            tx.raiseFloors(Map.of(tool, risk));
            return new Approval.Approved(-1);
        });
        if (result instanceof Approval.Approved approvedResult) {
            take(serverId);
            AuditEvent event = AuditEvent.of("admin_change", requestId, componentId).userWithoutClient(administrator).server(serverId).tool(tool)
                    .definitionHash(hash).outcome("ok");
            if (approvedResult.loweredTo() >= 0) {
                event.reason("risk_lowered_by_admin").risk(Risk.values()[approvedResult.loweredTo()].name());
            } else {
                event.reason("definition_approved");
                if (classification != null) {
                    event.risk(classification.risk());
                }
            }
            if (classification != null) {
                event.action(classification.action());
            }
            audit.emit(event);
        } else if (result instanceof Approval.RiskLowered) {
            denied(requestId, serverId, "risk_lowered");
        } else if (result instanceof Approval.Rejected rejected) {
            denied(requestId, serverId, rejected.reason());
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
        if (server.approvalRequired() && needsRecording(server, verdicts, changedHashes)) {
            try {
                recordServerEntries(server, live, serverVersion, verdicts, changedHashes);
            } catch (DataAccessException e) {
                log.warn("{}: the definitions the server presented could not be recorded: {}", server.serverId(), e.getClass().getName());
            }
        }
        return verdicts;
    }

    /** What a running server may leave behind: for a server behind an adapter its own definitions come from the adapter (CC-206). */
    private static String presentedSource(McpServer server) {
        return server.adapter() ? "adapter" : "server";
    }

    private boolean needsRecording(McpServer server, Map<String, Verdict> verdicts, Map<String, String> changedHashes) {
        String presented = presentedSource(server);
        RegisteredServer state = held.get(server.serverId());
        if (state == null) {
            return false;
        }
        for (Map.Entry<String, Verdict> verdict : verdicts.entrySet()) {
            RegisteredTool tool = state.tools().get(verdict.getKey());
            RegisteredTool.Pending pending = tool == null ? null : tool.pending();
            if (verdict.getValue() == Verdict.CHANGED && changedHashes.containsKey(verdict.getKey())
                    && (pending == null || (presented.equals(pending.source()) && !pending.hash().equals(changedHashes.get(verdict.getKey()))))) {
                return true;
            }
            if (verdict.getValue() == Verdict.INTACT && pending != null && presented.equals(pending.source())) {
                return true;
            }
        }
        return false;
    }

    private void recordServerEntries(McpServer server, Map<String, JsonNode> live, String serverVersion, Map<String, Verdict> verdicts,
                                     Map<String, String> changedHashes) {
        boolean[] touched = {false};
        String presented = presentedSource(server);
        store.locked(server.serverId(), tx -> {
            Map<String, RegisteredTool> tools = tx.tools();
            verdicts.forEach((name, verdict) -> {
                RegisteredTool tool = tools.get(name);
                if (tool == null || tool.approved() == null) {
                    return;
                }
                RegisteredTool.Pending pending = tool.pending();
                ToolDefinition approved = server.tools().get(name);
                if (verdict == Verdict.INTACT && pending != null && presented.equals(pending.source())) {
                    tx.saveTool(tool.withPending(null));
                    touched[0] = true;
                } else if (verdict == Verdict.CHANGED && approved != null && changedHashes.containsKey(name)
                        && (pending == null || (presented.equals(pending.source()) && !pending.hash().equals(changedHashes.get(name))))) {
                    ObjectNode entry = definitionCheck.entryOf(server, approved);
                    ObjectNode full = json.createObjectNode();
                    full.put("name", name);
                    if (entry.has("risk")) {
                        full.set("risk", entry.get("risk"));
                        full.set("action", entry.get("action"));
                    }
                    full.set("resourceRefs", entry.get("resourceRefs"));
                    full.set("definition", live.get(name));
                    full.put("definitionHash", changedHashes.get(name));
                    boolean valid = serverVersion != null && SEMVER.matcher(serverVersion).matches();
                    if (serverVersion != null && !valid) {
                        log.warn("{}: the server reported a version that is no SemVer; the pending entry of {} says so", server.serverId(), name);
                    }
                    // The schema wants a SemVer; a value that is none must not look like the approved version in the diff.
                    String version = valid ? serverVersion : serverVersion == null ? tool.approved().version() : "0.0.0-invalid";
                    tx.saveTool(tool.withPending(new RegisteredTool.Pending(full, changedHashes.get(name), version, "changed", presented,
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
            if (server.adapter() || held.containsKey(server.serverId()) || !server.enabled() || store.findServer(server.serverId()).isPresent()) {
                continue;
            }
            fetcher.fetch(server).ifPresent(manifest -> {
                Result result = write(UuidV7.next(), server.serverId(), manifest, "bootstrap", true, false);
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
        List<RegistryStore.StoredServer> all = store.servers();
        for (RegistryStore.StoredServer stored : all) {
            RegisteredServer now = read(stored);
            RegisteredServer before = held.get(stored.serverId());
            if (now != null && !now.equals(before)) {
                take(stored.serverId());
            }
        }
        // A state that is gone from the store (an operator emptied the tables) is gone from here too: nothing stays approved on memory alone.
        for (String serverId : List.copyOf(held.keySet())) {
            if (all.stream().noneMatch(stored -> stored.serverId().equals(serverId))) {
                RegisteredServer gone = held.remove(serverId);
                servers.find(serverId).ifPresent(server -> servers.apply(serverId, server.version(), Map.of(), Map.of(), true));
                guard.forget(serverId);
                onChange.run();
                log.warn("{}: the stored state is gone, {} tools are no longer served", serverId, gone == null ? 0 : gone.tools().size());
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
            onChange.run();
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
