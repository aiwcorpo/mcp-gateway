package pl.aiwcorpo.mcp.gateway.policy;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.cedarpolicy.model.exception.InternalException;
import com.cedarpolicy.model.policy.Policy;
import com.cedarpolicy.model.policy.PolicySet;

import pl.aiwcorpo.mcp.cedar.entities.McpCedarSchema;
import pl.aiwcorpo.mcp.cedar.entities.PolicyFragments;
import pl.aiwcorpo.mcp.cedar.entities.ResourceTypes;
import pl.aiwcorpo.mcp.cedar.entities.ScopeMapping;
import pl.aiwcorpo.mcp.gateway.audit.AuditEvent;
import pl.aiwcorpo.mcp.gateway.audit.AuditLog;
import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.registry.Outcome;
import pl.aiwcorpo.mcp.gateway.registry.RegistryStore;
import pl.aiwcorpo.mcp.gateway.registry.RegistryStore.StoredPolicies;
import pl.aiwcorpo.mcp.gateway.registry.ServerConfig;
import pl.aiwcorpo.mcp.manifest.CanonicalJson;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * The policy data of the gateway (C5, C7): the scope mapping, the emergency overrides, the allowed clients and the approved policies
 * of the servers, with one revision that only rises. This class holds what this instance decides with ({@link Snapshot}, rebuilt when
 * the change counter moves) and takes the writes of the administrator (mapping, overrides) under the lock of the policy row.
 *
 * <p>Every error while a snapshot is built (two servers in one namespace, an override that does not parse, a policy id used twice) makes
 * a snapshot that denies: the gateway never goes on with the data it had before. The reason is an audit event and the log, not the answer.
 */
public final class PolicyService implements PolicySource {

    private static final Logger log = LoggerFactory.getLogger(PolicyService.class);
    private static final Pattern GROUP = Pattern.compile("^mcp-[A-Za-z0-9][A-Za-z0-9._-]{0,254}$");
    private static final Pattern SCOPE = Pattern.compile("^[A-Z][A-Za-z0-9]{0,30}::[A-Z][A-Za-z0-9]{0,30}/[!-~]{1,1024}$");
    private static final Pattern OVERRIDE_ID = Pattern.compile("^override-[a-z0-9][a-z0-9-]{0,54}$");
    private static final Pattern OVERRIDE_TARGET = Pattern.compile("^(gateway|all-servers|mcp-[a-z][a-z0-9]{1,30})$");
    private static final Pattern ETAG = Pattern.compile("^\"[A-Za-z0-9_-]{8,128}\"$");
    private static final int MAX_MAPPING_ENTRIES = 5000;
    private static final int MAX_SCOPES_PER_GROUP = 1000;
    private static final int MAX_OVERRIDE_TEXT = 8000;

    /**
     * What this instance decides with. {@code error} is null for usable data; otherwise every decision is a deny and {@code types},
     * {@code mapping} and {@code gatewayPolicies} are empty. {@code revision} is 0 before the first load.
     */
    public record Snapshot(long revision, ResourceTypes types, ScopeMapping mapping, PolicySet gatewayPolicies, List<String> allowedClients,
                           Map<String, String> namespaces, Map<String, String> approvedHashes, List<PolicyOverride> overrides, String error) {

        static Snapshot unavailable(List<String> allowedClients) {
            return new Snapshot(0, ResourceTypes.empty(), ScopeMapping.empty(), null, allowedClients, Map.of(), Map.of(), List.of(),
                    "not loaded");
        }

        public boolean usable() {
            return error == null && gatewayPolicies != null;
        }
    }

    /** What a server gets from {@code GET /internal/v1/policy-data}. */
    public record ServerData(long revision, String approvedPoliciesHash, ScopeMapping scopeMapping, List<String> allowedClients,
                             List<PolicyOverride> overrides) {
    }

    /** The scope mapping document and its ETag. */
    public record MappingDocument(JsonNode document, String etag) {
    }

    private final RegistryStore store;
    private final PolicyDataStore data;
    private final AuditLog audit;
    private final String componentId;
    private final JsonMapper json;
    private final List<String> allowedClients;
    private final List<Runnable> listeners = new CopyOnWriteArrayList<>();
    private volatile Snapshot snapshot;
    private String lastError;

    public PolicyService(RegistryStore store, PolicyDataStore data, AuditLog audit, String componentId, JsonMapper json,
                         List<String> allowedClients) {
        this.store = store;
        this.data = data;
        this.audit = audit;
        this.componentId = componentId;
        this.json = json;
        this.allowedClients = List.copyOf(new TreeSet<>(allowedClients));
        this.snapshot = Snapshot.unavailable(this.allowedClients);
    }

    /**
     * First load. The allowed clients are policy data: the list in the database is the one every instance enforces and every server is
     * served. The configuration ({@code MCP_ALLOWED_CLIENTS}) only seeds it, once, when the database has none; a configuration that differs from
     * what the database holds is logged and otherwise ignored, so two instances never decide with different lists.
     */
    public PolicyService start() {
        String configured = String.join(",", allowedClients);
        store.policyLocked(tx -> {
            String stored = tx.state().allowedClients();
            if (stored.isBlank()) {
                data.saveAllowedClients(configured);
                tx.raiseRevision();
                log.info("the allowed clients of the database were empty and are now {}", configured);
            } else if (!stored.equals(configured)) {
                log.warn("MCP_ALLOWED_CLIENTS ({}) differs from the allowed clients in the database ({}); the database is in force", configured, stored);
            }
            return null;
        });
        reload();
        return this;
    }

    /** Told when what the instance decides with changed: lists computed before may differ now. */
    public void onChange(Runnable listener) {
        listeners.add(listener);
    }

    @Override
    public Snapshot snapshot() {
        return snapshot;
    }

    /** Reads the policy data again. A failure of the database leaves the snapshot as it is and is thrown to the caller, which tries again. */
    public synchronized void reload() {
        record Read(PolicyDataStore.State state, List<PolicyOverride> overrides, Map<String, StoredPolicies> policies,
                    List<ServerConfig> configs) {
        }
        // One read: a writer raises the revision in the transaction of its change, so all of this belongs to one revision.
        Read read = store.consistentRead(() -> new Read(data.state(), data.overrides(), store.allPolicies(), store.configs()));
        PolicyDataStore.State state = read.state();
        List<PolicyOverride> overrides = read.overrides();
        Map<String, StoredPolicies> policies = read.policies();
        Set<String> registered = new LinkedHashSet<>();
        read.configs().forEach(config -> registered.add(config.serverId()));
        List<String> clients = state.allowedClients().isBlank() ? allowedClients : List.of(state.allowedClients().split(","));
        Snapshot before = snapshot;
        Snapshot next;
        List<ScopeMapping.Ignored> ignored = List.of();
        try {
            ResourceTypes types = approvedTypes(policies, registered);
            ScopeMapping mapping = ScopeMapping.fromJson(types, json.writeValueAsString(state.scopeMapping()), true);
            ignored = mapping.ignored();
            PolicySet gateway = PolicyFragments.merge(McpCedarSchema.platformPolicies(), gatewayOverrides(overrides));
            Map<String, String> namespaces = new LinkedHashMap<>();
            Map<String, String> hashes = new LinkedHashMap<>();
            policies.forEach((serverId, stored) -> {
                if (registered.contains(serverId) && stored.approved()) {
                    namespaces.put(serverId, stored.approvedPolicies().path("namespace").asString());
                    hashes.put(serverId, stored.approvedHash());
                }
            });
            next = new Snapshot(state.revision(), types, mapping, gateway, clients, Map.copyOf(namespaces), Map.copyOf(hashes),
                    List.copyOf(overrides), null);
        } catch (RuntimeException e) {
            String why = e.getClass().getSimpleName() + ": " + e.getMessage();
            log.error("the policy data of revision {} cannot be used, every decision is a deny: {}", state.revision(), why);
            if (!why.equals(lastError)) {
                lastError = why;
                audit.emit(AuditEvent.of("admin_change", pl.aiwcorpo.mcp.gateway.jwt.UuidV7.next(), componentId).reason("policy_data_invalid")
                        .outcome("error", "internal_error").policyRevision(state.revision()));
            }
            next = new Snapshot(state.revision(), ResourceTypes.empty(), ScopeMapping.empty(), null, clients, Map.of(), Map.of(),
                    List.of(), why);
        }
        if (next.error() == null) {
            lastError = null;
        }
        snapshot = next;
        boolean changed = before.revision() != next.revision() || (before.error() == null) != (next.error() == null);
        if (changed) {
            for (ScopeMapping.Ignored entry : ignored) {
                audit.emit(AuditEvent.of("admin_change", pl.aiwcorpo.mcp.gateway.jwt.UuidV7.next(), componentId)
                        .reason("scope_mapping_entry_ignored").outcome("denied").policyRevision(next.revision()).group(entry.group())
                        .resource(resourceOf(entry.scope())));
                log.warn("scope mapping entry of group {} ignored ({}): {}", entry.group(), entry.reason(), entry.scope());
            }
            listeners.forEach(listener -> {
                try {
                    listener.run();
                } catch (RuntimeException e) {
                    log.warn("a listener of the policy change failed: {}", e.getClass().getName());
                }
            });
        }
    }

    private static pl.aiwcorpo.mcp.gateway.confirm.PendingCall.Resource resourceOf(String scope) {
        int slash = scope.indexOf('/');
        if (slash <= 0 || !SCOPE.matcher(scope).matches()) {
            return null;
        }
        return new pl.aiwcorpo.mcp.gateway.confirm.PendingCall.Resource(scope.substring(0, slash), scope.substring(slash + 1), null);
    }

    private ResourceTypes approvedTypes(Map<String, StoredPolicies> policies, Set<String> registered) {
        List<ResourceTypes> perServer = new ArrayList<>();
        policies.forEach((serverId, stored) -> {
            if (registered.contains(serverId) && stored.approved()) {
                perServer.add(ResourceTypes.fromJson(json.writeValueAsString(stored.approvedResourceTypes())));
            }
        });
        return ResourceTypes.union(perServer);
    }

    private static PolicySet gatewayOverrides(List<PolicyOverride> overrides) {
        Set<Policy> policies = new LinkedHashSet<>();
        for (PolicyOverride override : overrides) {
            if (PolicyOverride.GATEWAY.equals(override.target())) {
                policies.add(parseOne(override));
            }
        }
        return new PolicySet(policies);
    }

    private static Policy parseOne(PolicyOverride override) {
        try {
            PolicySet parsed = PolicySet.parsePolicies(override.text());
            if (parsed.policies.size() != 1 || !parsed.templates.isEmpty()) {
                throw new IllegalArgumentException("override " + override.id() + " is not one policy");
            }
            return new Policy(parsed.policies.iterator().next().policySrc, override.id());
        } catch (InternalException e) {
            throw new IllegalArgumentException("override " + override.id() + " does not parse", e);
        }
    }

    /**
     * The data a server of this registry gets: the scopes of its own namespace only, the hash approved for it, the allowed clients and the
     * overrides aimed at it or at all servers. Empty when this instance cannot decide (the data of the snapshot is unusable).
     */
    public Optional<ServerData> dataFor(String serverId) {
        Snapshot now = snapshot;
        if (!now.usable()) {
            return Optional.empty();
        }
        String namespace = now.namespaces().get(serverId);
        ScopeMapping mapping = namespace == null ? ScopeMapping.empty() : now.mapping().forNamespace(namespace);
        List<PolicyOverride> own = now.overrides().stream()
                .filter(o -> o.target().equals(serverId) || PolicyOverride.ALL_SERVERS.equals(o.target())).toList();
        return Optional.of(new ServerData(now.revision(), now.approvedHashes().get(serverId), mapping, now.allowedClients(), own));
    }

    // ---- scope mapping ----

    public MappingDocument mapping() {
        return document(data.state().scopeMapping());
    }

    private MappingDocument document(JsonNode entries) {
        ObjectNode document = json.createObjectNode();
        document.set("scopeMapping", entries);
        return new MappingDocument(document, etag(entries));
    }

    /**
     * Replaces the whole mapping. Every scope is checked against the approved declarations of the registered servers: the type must be
     * declared and grantable and the local part must match its scopePattern.
     */
    public Outcome<MappingDocument> putMapping(String requestId, String ifMatch, JsonNode body, GatewayUser administrator) {
        if (ifMatch == null) {
            return Outcome.of(Outcome.Status.PRECONDITION_REQUIRED);
        }
        Outcome<ArrayNode> shaped = shape(body);
        if (!shaped.succeeded()) {
            return Outcome.rejected(shaped.reason(), shaped.message());
        }
        Outcome<MappingDocument> result = store.policyLocked(tx -> {
            PolicyDataStore.State state = tx.state();
            if (!etag(state.scopeMapping()).equals(ifMatch)) {
                return Outcome.of(Outcome.Status.PRECONDITION_FAILED);
            }
            ResourceTypes types;
            try {
                Set<String> registered = new LinkedHashSet<>();
                tx.configs().forEach(config -> registered.add(config.serverId()));
                types = approvedTypes(tx.allPolicies(), registered);
            } catch (RuntimeException e) {
                return Outcome.rejected("unknown_resource_type", "the resource types of the registered servers cannot be combined");
            }
            Outcome<ArrayNode> checked = check(types, shaped.value());
            if (!checked.succeeded()) {
                return Outcome.rejected(checked.reason(), checked.message());
            }
            ArrayNode entries = checked.value();
            if (etag(entries).equals(etag(state.scopeMapping()))) {
                return Outcome.ok(document(entries));
            }
            tx.saveScopeMapping(entries);
            tx.raiseRevision();
            return Outcome.ok(document(entries));
        });
        if (result.succeeded()) {
            audit.emit(AuditEvent.of("admin_change", requestId, componentId).userWithoutClient(administrator)
                    .reason("scope_mapping_changed").outcome("ok"));
            refreshAfterWrite();
        } else if (result.status() == Outcome.Status.REJECTED) {
            audit.emit(AuditEvent.of("admin_change", requestId, componentId).userWithoutClient(administrator)
                    .reason(result.reason()).outcome("denied"));
        }
        return result;
    }

    /** The shape the schema of the contract gives: a list of {group, scopes}, patterns, limits; the answer is 400 for anything else. */
    private Outcome<ArrayNode> shape(JsonNode body) {
        if (body == null || !body.isObject() || body.size() != 1 || !body.path("scopeMapping").isArray()) {
            return Outcome.rejected("invalid_request", null);
        }
        ArrayNode entries = (ArrayNode) body.get("scopeMapping");
        if (entries.size() > MAX_MAPPING_ENTRIES) {
            return Outcome.rejected("invalid_request", null);
        }
        for (JsonNode entry : entries) {
            if (!entry.isObject() || entry.size() != 2 || !entry.path("group").isString() || !entry.path("scopes").isArray()
                    || !GROUP.matcher(entry.get("group").asString()).matches() || entry.get("scopes").size() > MAX_SCOPES_PER_GROUP) {
                return Outcome.rejected("invalid_request", null);
            }
            Set<String> seen = new LinkedHashSet<>();
            for (JsonNode scope : entry.get("scopes")) {
                if (!scope.isString() || !SCOPE.matcher(scope.asString()).matches() || !seen.add(scope.asString())) {
                    return Outcome.rejected("invalid_request", null);
                }
            }
        }
        return Outcome.ok(entries);
    }

    private Outcome<ArrayNode> check(ResourceTypes types, ArrayNode entries) {
        Map<String, TreeSet<String>> byGroup = new TreeMap<>();
        for (JsonNode entry : entries) {
            String group = entry.get("group").asString();
            if (byGroup.containsKey(group)) {
                return Outcome.rejected("group_duplicate", "the group " + group + " is listed twice");
            }
            TreeSet<String> scopes = new TreeSet<>();
            for (JsonNode scope : entry.get("scopes")) {
                String id = scope.asString();
                String type = id.substring(0, id.indexOf('/'));
                if (!types.isDeclared(type)) {
                    return Outcome.rejected("unknown_resource_type", type + " is a type that no registered server declares");
                }
                if (!types.isGrantable(type)) {
                    return Outcome.rejected("scope_not_grantable", type + " has no scopePattern, so it cannot be granted");
                }
                if (types.scopeType(id).isEmpty()) {
                    return Outcome.rejected("scope_invalid", "the part after the slash of a scope of " + type + " does not match its scopePattern");
                }
                scopes.add(id);
            }
            byGroup.put(group, scopes);
        }
        return Outcome.ok(canonicalMapping(byGroup));
    }

    /** The mapping as stored: groups in order, scopes in order. */
    public ArrayNode canonicalMapping(Map<String, ? extends Set<String>> byGroup) {
        ArrayNode out = json.createArrayNode();
        new TreeMap<>(byGroup).forEach((group, scopes) -> {
            ObjectNode entry = out.addObject();
            entry.put("group", group);
            ArrayNode list = entry.putArray("scopes");
            new TreeSet<>(scopes).forEach(list::add);
        });
        return out;
    }

    // ---- overrides ----

    public List<PolicyOverride> overrides() {
        return data.overrides();
    }

    public Optional<PolicyOverride> override(String id) {
        return data.override(id);
    }

    /**
     * Creates ({@code createOnly}: {@code If-None-Match: *}) or replaces ({@code ifMatch}) an override. The text is validated for its target
     * with PolicyFragments#validateOverride against the base schema and the approved fragment of the server, or of every server.
     */
    public Outcome<PolicyOverride> putOverride(String requestId, String id, String ifMatch, boolean createOnly, JsonNode body,
                                               GatewayUser administrator) {
        if (!OVERRIDE_ID.matcher(id).matches() || body == null || !body.isObject() || body.size() != 2
                || !body.path("target").isString() || !body.path("text").isString()
                || !OVERRIDE_TARGET.matcher(body.get("target").asString()).matches()
                || body.get("text").asString().isEmpty() || body.get("text").asString().length() > MAX_OVERRIDE_TEXT) {
            return Outcome.rejected("invalid_request", null);
        }
        if (ifMatch == null && !createOnly) {
            return Outcome.of(Outcome.Status.PRECONDITION_REQUIRED);
        }
        String target = body.get("target").asString();
        String text = body.get("text").asString();
        String[] before = {null};
        Outcome<PolicyOverride> result = store.policyLocked(tx -> {
            Optional<PolicyOverride> existing = tx.override(id);
            if (createOnly ? existing.isPresent() : existing.isEmpty() || !etag(existing.get()).equals(ifMatch)) {
                return Outcome.of(Outcome.Status.PRECONDITION_FAILED);
            }
            existing.ifPresent(found -> before[0] = found.text());
            Outcome<PolicyOverride> invalid = validate(id, text, target, tx.allPolicies(), tx.configs());
            if (invalid != null) {
                return invalid;
            }
            PolicyOverride override = new PolicyOverride(id, target, text, administrator.sub(), Instant.now().truncatedTo(ChronoUnit.MILLIS));
            tx.saveOverride(override);
            tx.raiseRevision();
            return Outcome.ok(override);
        });
        if (result.succeeded()) {
            audit.emit(AuditEvent.of("admin_change", requestId, componentId).userWithoutClient(administrator).reason("override_set")
                    .override(id, target, text, before[0]).outcome("ok"));
            refreshAfterWrite();
        } else if (result.status() == Outcome.Status.REJECTED && !"invalid_request".equals(result.reason())) {
            audit.emit(AuditEvent.of("admin_change", requestId, componentId).userWithoutClient(administrator).reason("override_rejected")
                    .override(id, target, text, null).outcome("denied"));
        }
        return result;
    }

    private Outcome<PolicyOverride> validate(String id, String text, String target, Map<String, StoredPolicies> policies,
                                             List<ServerConfig> configs) {
        PolicyFragments.OverrideTarget kind;
        List<String> fragments = new ArrayList<>();
        switch (target) {
            case PolicyOverride.GATEWAY -> kind = PolicyFragments.OverrideTarget.GATEWAY;
            case PolicyOverride.ALL_SERVERS -> {
                kind = PolicyFragments.OverrideTarget.ALL_SERVERS;
                policies.forEach((serverId, stored) -> {
                    if (stored.approved() && configs.stream().anyMatch(c -> c.serverId().equals(serverId))) {
                        fragments.add(stored.approvedPolicies().path("schema").asString());
                    }
                });
            }
            default -> {
                if (configs.stream().noneMatch(c -> c.serverId().equals(target))) {
                    return Outcome.rejected("target_unknown", target + " is not in the registry of servers");
                }
                kind = PolicyFragments.OverrideTarget.SERVER;
                StoredPolicies stored = policies.get(target);
                if (stored != null && stored.approved()) {
                    fragments.add(stored.approvedPolicies().path("schema").asString());
                }
            }
        }
        PolicyFragments.Result result;
        try {
            result = PolicyFragments.validateOverride(id, text, kind, fragments);
        } catch (RuntimeException e) {
            return Outcome.rejected("invalid_policy", "the override cannot be checked");
        }
        if (result.ok()) {
            return null;
        }
        String first = result.errors().getFirst();
        return Outcome.rejected(overrideReason(first), first.length() > 500 ? first.substring(0, 500) : first);
    }

    private static String overrideReason(String error) {
        if (error.startsWith("an override id is")) {
            return "id_invalid";
        }
        if (error.startsWith("an override holds exactly one policy")) {
            return "not_one_policy";
        }
        if (error.startsWith("an override is forbid only")) {
            return "not_forbid";
        }
        if (error.startsWith("@id ")) {
            return "id_mismatch";
        }
        if (error.startsWith("a gateway override must be") || error.startsWith("a server override may not mention")) {
            return "target_mismatch";
        }
        return "invalid_policy";
    }

    public Outcome<Void> deleteOverride(String requestId, String id, String ifMatch, GatewayUser administrator) {
        if (ifMatch == null) {
            return Outcome.of(Outcome.Status.PRECONDITION_REQUIRED);
        }
        PolicyOverride[] removed = {null};
        Outcome<Void> result = store.policyLocked(tx -> {
            Optional<PolicyOverride> existing = tx.override(id);
            if (existing.isEmpty()) {
                return Outcome.of(Outcome.Status.NOT_FOUND);
            }
            if (!etag(existing.get()).equals(ifMatch)) {
                return Outcome.of(Outcome.Status.PRECONDITION_FAILED);
            }
            removed[0] = existing.get();
            tx.deleteOverride(id);
            tx.raiseRevision();
            return Outcome.noContent();
        });
        if (result.succeeded()) {
            audit.emit(AuditEvent.of("admin_change", requestId, componentId).userWithoutClient(administrator).reason("override_removed")
                    .override(id, removed[0].target(), removed[0].text(), null).outcome("ok"));
            refreshAfterWrite();
        }
        return result;
    }

    /**
     * After the approval of a server's policies: the overrides that target the server or all servers are checked again against the
     * fragments now approved. One that no longer validates stays (the server refuses every call while it does not validate, which is the
     * safe side) and is audited, so an administrator sees which one to fix.
     *
     * @return the ids of the overrides that do not validate
     */
    public List<String> revalidateOverrides(String requestId, String serverId) {
        Map<String, StoredPolicies> policies = store.allPolicies();
        List<ServerConfig> configs = store.configs();
        List<String> invalid = new ArrayList<>();
        for (PolicyOverride override : data.overrides()) {
            if (PolicyOverride.GATEWAY.equals(override.target())
                    || !(override.target().equals(serverId) || PolicyOverride.ALL_SERVERS.equals(override.target()))) {
                continue;
            }
            Outcome<PolicyOverride> verdict = validate(override.id(), override.text(), override.target(), policies, configs);
            if (verdict != null) {
                invalid.add(override.id());
                audit.emit(AuditEvent.of("admin_change", requestId, componentId).server(serverId).reason("override_invalid")
                        .override(override.id(), override.target(), override.text(), null).outcome("denied"));
                log.error("the override {} no longer validates against the policies of {}: {}", override.id(), serverId, verdict.message());
            }
        }
        return invalid;
    }

    /** The write is visible on this instance at once; the others take it when the counter moves. */
    private void refreshAfterWrite() {
        try {
            reload();
        } catch (RuntimeException e) {
            log.warn("the policy data was stored but could not be read back: {}", e.getClass().getName());
        }
    }

    // ---- ETags ----

    public String etag(JsonNode entries) {
        return etagOf(CanonicalJson.canonicalize(json.writeValueAsString(entries)));
    }

    public String etag(PolicyOverride override) {
        ObjectNode node = json.createObjectNode();
        node.put("id", override.id());
        node.put("target", override.target());
        node.put("text", override.text());
        node.put("setBy", override.setBy());
        node.put("setAt", override.setAt().toString());
        return etag(node);
    }

    public static String etagOf(String text) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8));
            return "\"" + Base64.getUrlEncoder().withoutPadding().encodeToString(digest).substring(0, 22) + "\"";
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    /** Whether the header is an entity tag of the shape the contract gives; anything else is a 400 before it is compared. */
    public static boolean wellFormedEtag(String value) {
        return value != null && ETAG.matcher(value).matches();
    }
}
