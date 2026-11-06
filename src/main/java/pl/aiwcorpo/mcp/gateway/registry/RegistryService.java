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
import pl.aiwcorpo.mcp.cedar.entities.ScopeMapping;
import pl.aiwcorpo.mcp.gateway.jwt.UuidV7;
import pl.aiwcorpo.mcp.gateway.policy.PolicyService;
import pl.aiwcorpo.mcp.gateway.registry.DefinitionGuard.Verdict;
import pl.aiwcorpo.mcp.gateway.registry.ManifestValidator.Rejection;
import pl.aiwcorpo.mcp.gateway.registry.RegistryStore.StoredPolicies;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.server.Risk;
import pl.aiwcorpo.mcp.gateway.server.ServerRegistry;
import pl.aiwcorpo.mcp.gateway.server.ToolDefinition;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * The definitions of the servers' tools and the policies of the servers (C5/C6, CC-097, CC-133, CC-161, CC-162). The pipeline of a
 * reviewed commit registers a manifest: its READ_ONLY tools are approved, its UPDATE and DESTRUCTIVE tools wait for an administrator
 * ({@link #approve}), removed tools are removed, a lowered risk is refused. The policy fragment and the resource type declarations of the
 * manifest (their {@code policiesHash}) are approved at the level of the server ({@link #approvePolicies}); until they are, the tools of the
 * server are blocked. A definition that a running server presents and that is not the approved one is no registration: it blocks the tool
 * and, unless a pending entry of the pipeline is already there, leaves a pending entry with source {@code server} for the administrator to
 * look at ({@link #observe}); the same holds for the policies ({@link #observePolicies}).
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

    /** What approving the policies of a server did: the entries of the scope mapping that evaluation now ignores because of it. */
    public sealed interface PoliciesApproval {
        record Approved(List<ScopeMapping.Ignored> ignoredMappingEntries, List<String> invalidOverrides) implements PoliciesApproval {
        }

        record NotFound() implements PoliciesApproval {
        }

        record HashMismatch() implements PoliciesApproval {
        }

        record Rejected(String reason, String message) implements PoliciesApproval {
        }
    }

    /** The policies a running server presents, against the approved ones. {@code UNKNOWN}: no proof either way (not reachable, nothing approved). */
    public enum PoliciesVerdict {
        INTACT, CHANGED, UNKNOWN,
        /** The manifest could not be read or verified for too many checks or too long: the tools are blocked until a check finds it intact. */
        UNVERIFIED
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

        record NamespaceConflict(String namespace) implements Written {
        }

        /** The server was removed while the registration waited for its lock. */
        record Unknown() implements Written {
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
    private final PolicyService policies;
    private final Map<String, RegisteredServer> held = new ConcurrentHashMap<>();
    private volatile List<ServerConfig> lastConfigs = List.of();
    private volatile Runnable onChange = () -> { };
    private final int unverifiedAfterChecks;
    private final java.time.Duration unverifiedAfter;
    private final java.time.Clock clock;
    private final Map<String, PolicyCheck> checks = new ConcurrentHashMap<>();

    /** What the checks of the live policies of a server have found: when one last verified them, and how many failed since. */
    private static final class PolicyCheck {
        java.time.Instant verifiedAt;
        int failures;
        boolean blocked;
    }

    public RegistryService(ServerRegistry servers, RegistryStore store, ManifestValidator validator, ManifestFetcher fetcher,
                           DefinitionGuard guard, DefinitionCheck definitionCheck, AuditLog audit, String componentId,
                           JsonMapper json, PolicyService policies) {
        this(servers, store, validator, fetcher, guard, definitionCheck, audit, componentId, json, policies, 3, java.time.Duration.ofMinutes(5),
                java.time.Clock.systemUTC());
    }

    /**
     * @param unverifiedAfterChecks consecutive checks in which the manifest of a running server could not be read or verified after which
     *                              its tools are blocked
     * @param unverifiedAfter       the longest time since its policies were last verified before its tools are blocked
     */
    public RegistryService(ServerRegistry servers, RegistryStore store, ManifestValidator validator, ManifestFetcher fetcher,
                           DefinitionGuard guard, DefinitionCheck definitionCheck, AuditLog audit, String componentId,
                           JsonMapper json, PolicyService policies, int unverifiedAfterChecks, java.time.Duration unverifiedAfter,
                           java.time.Clock clock) {
        this.unverifiedAfterChecks = unverifiedAfterChecks;
        this.unverifiedAfter = unverifiedAfter;
        this.clock = clock;
        this.servers = servers;
        this.store = store;
        this.validator = validator;
        this.fetcher = fetcher;
        this.guard = guard;
        this.definitionCheck = definitionCheck;
        this.audit = audit;
        this.componentId = componentId;
        this.json = json;
        this.policies = policies;
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
        refreshServers();
        for (RegistryStore.StoredServer stored : store.servers()) {
            if (servers.find(stored.serverId()).isPresent()) {
                take(stored.serverId());
            }
        }
    }

    /**
     * Takes the list of servers from the database. Returns the servers that were added or whose settings changed: their held manifest is
     * checked again against the new settings (a credential type the manifest does not accept disables the server, CC-159).
     */
    private java.util.Set<String> refreshServers() {
        List<ServerConfig> configs = store.configs();
        if (configs.equals(lastConfigs)) {
            return java.util.Set.of();
        }
        java.util.Set<String> changed = new java.util.LinkedHashSet<>();
        configs.stream().filter(config -> !lastConfigs.contains(config)).forEach(config -> changed.add(config.serverId()));
        servers.replaceConfigs(configs);
        lastConfigs = configs;
        return changed;
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
        List<Rejection> rejections = validator.check(manifest, server.get());
        if (!rejections.isEmpty()) {
            denied(requestId, serverId, rejections.stream().map(Rejection::reason).filter(java.util.Objects::nonNull).findFirst().orElse(null));
            return new Result.Rejected(rejections);
        }
        String credentialJson = validator.credentialJson(manifest);
        PolicyPlan[] policyEvent = {null};
        Written written = store.locked(serverId, tx -> {
            if (tx.config().isEmpty()) {
                return new Written.Unknown();
            }
            if (bootstrap && tx.server().isPresent()) {
                return new Written.AlreadyThere();
            }
            Map<String, RegisteredTool> existing = tx.tools();
            RegistryPlanner.Plan plan = adapterChannel ? RegistryPlanner.planAdapter(manifest, credentialJson, existing)
                    : RegistryPlanner.plan(manifest, credentialJson, existing, tx.floors(), Map.of(), tx.groupFloors(), bootstrap);
            if (!plan.lowered().isEmpty()) {
                return new Written.Lowered(plan.lowered());
            }
            if (!adapterChannel) {
                // A namespace belongs to the first server whose policies were approved with it (C5). Registration claims nothing, so a
                // registration cannot hold a name that another server would need; it is refused only for a name that has an approved owner.
                String namespace = manifest.path("policies").path("namespace").asString();
                if (tx.namespaceOwner(namespace).filter(owner -> !owner.equals(serverId)).isPresent()) {
                    return new Written.NamespaceConflict(namespace);
                }
                PolicyPlan policyPlan = planPolicies(tx.policies(), manifest, bootstrap);
                if (policyPlan.next() != null) {
                    tx.savePolicies(policyPlan.next());
                    if (policyPlan.approves()) {
                        tx.raiseRevision();
                    }
                }
                policyEvent[0] = policyPlan;
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
            tx.setGroupFloors(plan.groups());
            return new Written.Done(plan);
        });
        return switch (written) {
            case Written.Done done -> {
                // The state taken here, not held.get: a reload of another thread that read the server list before this write may have dropped it from held.
                RegisteredServer taken = take(serverId);
                done.plan().changes().forEach(change -> changed(requestId, serverId, change));
                PolicyPlan policyPlan = policyEvent[0];
                if (policyPlan != null && policyPlan.next() != null) {
                    audit.emit(AuditEvent.of("admin_change", requestId, componentId).server(serverId)
                            .reason(policyPlan.approves() ? "policies_approved" : "policies_submitted").definitionHash(policyPlan.hash())
                            .outcome("ok"));
                }
                if (policyPlan != null && policyPlan.approves()) {
                    policies.reload();
                }
                RegisteredServer answer = taken != null ? taken : held.get(serverId);
                yield answer == null ? new Result.UnknownServer() : new Result.Accepted(answer);
            }
            case Written.NamespaceConflict conflict -> {
                denied(requestId, serverId, ManifestValidator.NAMESPACE_CONFLICT);
                yield new Result.Rejected(List.of(new Rejection(ManifestValidator.NAMESPACE_CONFLICT, "the namespace " + conflict.namespace()
                        + " belongs to another server")));
            }
            case Written.Lowered lowered -> {
                denied(requestId, serverId, "risk_lowered");
                yield new Result.Rejected(List.of(new Rejection("risk_lowered", "the risk of " + String.join(", ", lowered.tools())
                        + " is lower than what was approved before")));
            }
            case Written.Unknown unknown -> new Result.UnknownServer();
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
        if (server.isEmpty()) {
            return new Approval.NotFound();
        }
        java.time.Instant now = java.time.Instant.now().truncatedTo(java.time.temporal.ChronoUnit.MILLIS);
        Approval result = store.locked(serverId, tx -> {
            if (tx.config().isEmpty()) {
                return new Approval.NotFound();
            }
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
            if (fromAdapter && !"READ_ONLY".equals(classification.risk())) {
                // The adapter has no resource scope, so there is nothing to evaluate a write against: only reads are classified (CC-227).
                return new Approval.Rejected("classification_not_allowed", "a tool of an adapter is classified READ_ONLY only");
            }
            int risk = Risk.valueOf(fromAdapter ? classification.risk() : pending.entry().path("risk").asString()).ordinal();
            int floor = Math.max(tx.floors().getOrDefault(tool, 0), current.approvedRisk());
            boolean lowers = risk < floor;
            if (lowers && !acceptRiskLowering) {
                return new Approval.RiskLowered(tool + " lowers risk from " + Risk.values()[floor] + " to " + Risk.values()[risk]);
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
            // What an administrator approves is the group the tool keeps from now on, also when it is none.
            tx.setGroupFloors(Map.of(tool, entry.path("additionalGroup").asString("")));
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

    /** What {@code registration} does to the policies row: the row to write (null: nothing changes) and whether it is an approval. */
    private record PolicyPlan(StoredPolicies next, boolean approves, String hash) {
    }

    /**
     * The policies of a registration (C5 registerServer): the ones that are approved already clear what was pending; the ones that are
     * pending already stay; any others wait for an administrator, as does the first registration. The dev bootstrap approves what the
     * server serves (trust on first use).
     */
    private PolicyPlan planPolicies(StoredPolicies current, JsonNode manifest, boolean approveNow) {
        String hash = manifest.path("policiesHash").asString();
        JsonNode policies = manifest.path("policies");
        JsonNode resourceTypes = manifest.path("resourceTypes");
        String version = manifest.path("version").asString();
        if (approveNow) {
            return new PolicyPlan(new StoredPolicies(hash, policies, resourceTypes, version, null, null, null, null, null), true, hash);
        }
        if (hash.equals(current.approvedHash())) {
            return new PolicyPlan(current.pending() ? new StoredPolicies(current.approvedHash(), current.approvedPolicies(),
                    current.approvedResourceTypes(), current.approvedVersion(), null, null, null, null, null) : null, false, hash);
        }
        if (hash.equals(current.pendingHash()) && "ci".equals(current.pendingSource())) {
            return new PolicyPlan(null, false, hash);
        }
        return new PolicyPlan(new StoredPolicies(current.approvedHash(), current.approvedPolicies(), current.approvedResourceTypes(),
                current.approvedVersion(), hash, policies, resourceTypes, version, "ci"), false, hash);
    }

    /** The policies and resource types of a server, approved and pending, for the diff of the portal. */
    public Optional<StoredPolicies> policiesOf(String serverId) {
        RegisteredServer server = held.get(serverId);
        return server == null || "adapter".equals(server.source()) ? Optional.empty() : Optional.of(server.policies());
    }

    /**
     * Approves the pending policies whose hash is {@code hash}. The approval sets the hash the server is served as approved, raises the
     * revision of the policy data and may make entries of the scope mapping invalid (a narrower pattern, a type that is gone); evaluation
     * skips them, and the answer lists them. The overrides aimed at the server are checked against the new fragment.
     */
    public PoliciesApproval approvePolicies(String requestId, String serverId, String hash, GatewayUser administrator) {
        Optional<McpServer> server = servers.find(serverId);
        if (server.isEmpty() || server.get().adapter()) {
            return new PoliciesApproval.NotFound();
        }
        String[] namespaces = new String[2];
        List<MappingCleanup.Removed> freedScopes = new java.util.ArrayList<>();
        long[] revision = {0};
        PoliciesApproval stored = store.locked(serverId, tx -> {
            if (tx.config().isEmpty()) {
                return new PoliciesApproval.NotFound();
            }
            StoredPolicies current = tx.policies();
            if (!current.pending() || !current.pendingHash().equals(hash)) {
                return new PoliciesApproval.HashMismatch();
            }
            String namespace = current.pendingPolicies().path("namespace").asString();
            if (!tx.claimNamespace(namespace).equals(serverId)) {
                return new PoliciesApproval.Rejected(ManifestValidator.NAMESPACE_CONFLICT, "the namespace " + namespace + " belongs to another server");
            }
            // An approval that changes the namespace frees the old one: what was granted for its types goes with it, so that whoever takes
            // the name next does not inherit the grants (as when the server is deleted).
            java.util.Set<String> freed = new java.util.TreeSet<>(tx.namespaces());
            freed.remove(namespace);
            if (!freed.isEmpty()) {
                MappingCleanup.Result cleaned = MappingCleanup.strip(json, tx.lockPolicyState().scopeMapping(), freed);
                freedScopes.addAll(cleaned.removed());
                if (!freedScopes.isEmpty()) {
                    tx.saveScopeMapping(cleaned.mapping());
                }
            }
            tx.releaseNamespacesExcept(namespace);
            tx.savePolicies(new StoredPolicies(current.pendingHash(), current.pendingPolicies(), current.pendingResourceTypes(),
                    current.pendingVersion(), null, null, null, null, null));
            revision[0] = tx.raiseRevision();
            namespaces[0] = namespace;
            namespaces[1] = current.approved() ? current.approvedPolicies().path("namespace").asString() : namespace;
            return new PoliciesApproval.Approved(List.of(), List.of());
        });
        if (!(stored instanceof PoliciesApproval.Approved)) {
            if (stored instanceof PoliciesApproval.Rejected rejected) {
                denied(requestId, serverId, rejected.reason());
            }
            return stored;
        }
        // The decision of the administrator is on record before anything is read back or revalidated.
        audit.emit(AuditEvent.of("admin_change", requestId, componentId).userWithoutClient(administrator).server(serverId)
                .reason("policies_approved").definitionHash(hash).outcome("ok").policyRevision(revision[0]));
        freedScopes.forEach(removed -> audit.emit(AuditEvent.of("admin_change", requestId, componentId).userWithoutClient(administrator)
                .server(serverId).reason("scope_mapping_entry_removed").outcome("ok").group(removed.group())
                .resource(new pl.aiwcorpo.mcp.gateway.confirm.PendingCall.Resource(removed.type(), removed.local(), null))));
        take(serverId);
        policies.reload();
        List<ScopeMapping.Ignored> ignored = policies.snapshot().mapping().ignored().stream()
                .filter(entry -> entry.scope().startsWith(namespaces[0] + "::") || entry.scope().startsWith(namespaces[1] + "::")).toList();
        // The contract's answer has no place for them: the overrides that no longer validate are in the audit (override_invalid).
        List<String> invalidOverrides = policies.revalidateOverrides(requestId, serverId);
        return new PoliciesApproval.Approved(ignored, invalidOverrides);
    }

    /** The highest risk ever reported or classified per tool of a server (ordinals), as the approval compares with it. */
    public Map<String, Integer> floors(String serverId) {
        return store.floors(serverId);
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
        if (needsRecording(server, verdicts, changedHashes)) {
            try {
                recordServerEntries(server, live, serverVersion, verdicts, changedHashes);
            } catch (DataAccessException e) {
                log.warn("{}: the definitions the server presented could not be recorded: {}", server.serverId(), e.getClass().getName());
            }
        }
        return verdicts;
    }

    /**
     * Compares the policies a running server presents with the approved ones: its {@code GET /mcp-manifest} is read and the hash of its
     * policies and resource types is recomputed, never taken from what the manifest claims. A different hash is not a registration: the
     * policies are left as a pending entry with source {@code server} (unless one of the pipeline is already pending) and the tools of the
     * server are blocked until an administrator approves them. A server that presents the approved policies again loses its own pending
     * entry. A server that cannot be read is no proof of a change, but not for ever: after {@code unverifiedAfterChecks} checks in a row that
     * could not read it, or {@code unverifiedAfter} since its policies were last verified, its tools are blocked ({@code UNVERIFIED}, audited)
     * until a check finds them intact.
     */
    public PoliciesVerdict observePolicies(McpServer server) {
        RegisteredServer state = held.get(server.serverId());
        if (server.adapter() || state == null || !state.policies().approved()) {
            return PoliciesVerdict.UNKNOWN;
        }
        PoliciesVerdict verdict = observeLive(server, state);
        PolicyCheck check = checks.computeIfAbsent(server.serverId(), id -> {
            PolicyCheck created = new PolicyCheck();
            created.verifiedAt = clock.instant();
            return created;
        });
        synchronized (check) {
            switch (verdict) {
                case INTACT -> {
                    check.verifiedAt = clock.instant();
                    check.failures = 0;
                    if (check.blocked) {
                        check.blocked = false;
                        audit.emit(AuditEvent.of("admin_change", UuidV7.next(), componentId).server(server.serverId())
                                .reason("policies_verified").outcome("ok"));
                    }
                }
                case CHANGED -> check.failures = 0;
                default -> {
                    check.failures++;
                    if (check.failures >= unverifiedAfterChecks
                            || java.time.Duration.between(check.verifiedAt, clock.instant()).compareTo(unverifiedAfter) > 0) {
                        if (!check.blocked) {
                            check.blocked = true;
                            audit.emit(AuditEvent.of("admin_change", UuidV7.next(), componentId).server(server.serverId())
                                    .reason("policies_unverified").outcome("denied"));
                            log.error("{}: its policies could not be verified for {} checks or {}; its tools are blocked", server.serverId(),
                                    check.failures, unverifiedAfter);
                        }
                        return PoliciesVerdict.UNVERIFIED;
                    }
                }
            }
        }
        return verdict;
    }

    private PoliciesVerdict observeLive(McpServer server, RegisteredServer state) {
        Optional<JsonNode> live = fetcher.fetch(server);
        if (live.isEmpty()) {
            return PoliciesVerdict.UNKNOWN;
        }
        JsonNode manifest = live.get();
        Optional<String> hash = validator.policiesHashOf(manifest);
        StoredPolicies current = state.policies();
        if (hash.isPresent() && hash.get().equals(current.approvedHash())) {
            if (current.pending() && "server".equals(current.pendingSource())) {
                dropServerPending(server.serverId());
            }
            return PoliciesVerdict.INTACT;
        }
        // A manifest that does not hold together, or whose fragment does not validate, is not what was approved either; there is nothing
        // an administrator could approve, so nothing is recorded.
        if (hash.isEmpty() || !validator.policiesProblems(manifest).isEmpty()) {
            return PoliciesVerdict.CHANGED;
        }
        boolean recorded = current.pending() && (hash.get().equals(current.pendingHash()) || "ci".equals(current.pendingSource()));
        if (!recorded) {
            try {
                recordServerPolicies(server, manifest, hash.get());
            } catch (DataAccessException e) {
                log.warn("{}: the policies the server presented could not be recorded: {}", server.serverId(), e.getClass().getName());
            }
        }
        return PoliciesVerdict.CHANGED;
    }

    private void recordServerPolicies(McpServer server, JsonNode manifest, String hash) {
        String reported = manifest.path("version").asString(null);
        boolean valid = reported != null && SEMVER.matcher(reported).matches();
        boolean[] touched = {false};
        store.locked(server.serverId(), tx -> {
            if (tx.config().isEmpty()) {
                return null;
            }
            StoredPolicies current = tx.policies();
            if (!current.approved() || hash.equals(current.approvedHash())
                    || (current.pending() && (hash.equals(current.pendingHash()) || "ci".equals(current.pendingSource())))) {
                return null;
            }
            String namespace = manifest.path("policies").path("namespace").asString();
            if (tx.namespaceOwner(namespace).filter(owner -> !owner.equals(server.serverId())).isPresent()) {
                return null;
            }
            tx.savePolicies(new StoredPolicies(current.approvedHash(), current.approvedPolicies(), current.approvedResourceTypes(),
                    current.approvedVersion(), hash, manifest.get("policies"), manifest.get("resourceTypes"),
                    valid ? reported : "0.0.0-invalid", "server"));
            touched[0] = true;
            return null;
        });
        if (touched[0]) {
            take(server.serverId());
            audit.emit(AuditEvent.of("admin_change", UuidV7.next(), componentId).server(server.serverId()).reason("policies_changed")
                    .definitionHash(hash).outcome("ok"));
        }
    }

    private void dropServerPending(String serverId) {
        boolean[] touched = {false};
        store.locked(serverId, tx -> {
            if (tx.config().isEmpty()) {
                return null;
            }
            StoredPolicies current = tx.policies();
            if (current.approved() && current.pending() && "server".equals(current.pendingSource())) {
                tx.savePolicies(new StoredPolicies(current.approvedHash(), current.approvedPolicies(), current.approvedResourceTypes(),
                        current.approvedVersion(), null, null, null, null, null));
                touched[0] = true;
            }
            return null;
        });
        if (touched[0]) {
            take(serverId);
        }
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
            if (tx.config().isEmpty()) {
                return null;
            }
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
        for (McpServer server : servers.all()) {
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
     * A server whose policies are pending because it presented them itself is looked at again without waiting for a user: its tools are
     * blocked, so no list of a user reads its definitions, and one that went back to the approved policies would stay blocked.
     */
    public void recheckServerPolicies() {
        for (RegisteredServer state : List.copyOf(held.values())) {
            if (state.policies().pending() && "server".equals(state.policies().pendingSource())) {
                servers.find(state.serverId()).ifPresent(this::observePolicies);
            }
        }
    }

    /**
     * Takes the stored state that another instance wrote or changed since this one looked (HA: instances share the tables, not
     * memory). A state that is unchanged is left alone.
     */
    public void reloadChanged() {
        java.util.Set<String> reconfigured = refreshServers();
        List<RegistryStore.StoredServer> all = store.servers();
        for (RegistryStore.StoredServer stored : all) {
            RegisteredServer now = read(stored);
            RegisteredServer before = held.get(stored.serverId());
            if (now != null && (!now.equals(before) || reconfigured.contains(stored.serverId()))) {
                take(stored.serverId());
            }
        }
        // A state that is gone from the store (a server was removed, or an operator emptied the tables) is gone from here too: nothing
        // stays approved on memory alone.
        for (String serverId : List.copyOf(held.keySet())) {
            // The list was read before this loop: a server created and registered in between is in held but not in the list, so the store is asked again.
            if ((all.stream().noneMatch(stored -> stored.serverId().equals(serverId)) && store.findServer(serverId).isEmpty())
                    || servers.find(serverId).isEmpty()) {
                RegisteredServer gone = held.remove(serverId);
                servers.forgetState(serverId);
                guard.forget(serverId);
                onChange.run();
                log.warn("{}: the stored state is gone, {} tools are no longer served", serverId, gone == null ? 0 : gone.tools().size());
            }
        }
        if (!reconfigured.isEmpty()) {
            onChange.run();
        }
    }

    private RegisteredServer read(RegistryStore.StoredServer stored) {
        if (servers.find(stored.serverId()).isEmpty()) {
            return null;
        }
        return new RegisteredServer(stored.serverId(), stored.manifest().path("system").asString(),
                stored.manifest().path("version").asString(), stored.manifest(), stored.source(), store.tools(stored.serverId()),
                store.policiesOf(stored.serverId()));
    }

    /** Reads the stored state of a server into memory and hands the approved tools to the server registry. */
    private RegisteredServer take(String serverId) {
        Optional<RegistryStore.StoredServer> stored = store.findServer(serverId);
        Optional<McpServer> server = servers.find(serverId);
        if (stored.isEmpty() || server.isEmpty()) {
            return null;
        }
        RegisteredServer state = read(stored.get());
        List<Rejection> rejections = new java.util.ArrayList<>(validator.check(state.manifest(), server.get()));
        // The kind of manifest must be the kind of server: the registry says whether it is behind an adapter, and the manifest cannot say otherwise.
        if ("adapter".equals(state.manifest().path("source").asString(null)) != server.get().adapter()) {
            rejections.add(new Rejection("adapter_mode_mismatch", "the held manifest is not of the kind the server is registered as"));
        }
        if (!rejections.isEmpty()) {
            log.error("held manifest of {} is no longer acceptable, the server is disabled: {}", serverId,
                    String.join("; ", rejections.stream().map(r -> r.reason() == null ? r.message() : r.reason()).toList()));
        }
        RegisteredServer before = held.put(serverId, state);
        boolean policiesApproved = server.get().adapter() || (state.policies().approved() && !state.policies().pending());
        servers.apply(serverId, new ServerRegistry.Applied(state.version(), state.tools(), store.floors(serverId), rejections.isEmpty(),
                policiesApproved));
        if (!state.equals(before)) {
            guard.forget(serverId);
            onChange.run();
        }
        return state;
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
