package pl.aiwcorpo.mcp.gateway.registry;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pl.aiwcorpo.mcp.gateway.audit.AuditEvent;
import pl.aiwcorpo.mcp.gateway.audit.AuditLog;
import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.confirm.PendingCall;
import pl.aiwcorpo.mcp.gateway.net.AddressPolicy;
import pl.aiwcorpo.mcp.gateway.net.ServerUrl;
import pl.aiwcorpo.mcp.gateway.policy.PolicyService;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.server.CredentialPolicy;
import pl.aiwcorpo.mcp.manifest.CanonicalJson;
import pl.aiwcorpo.mcp.manifest.ReservedSystemIds;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * The registry of servers (C5 {@code /admin/v1/servers}): the only list of servers. A server is added by its address (CC-249): the gateway
 * checks the address, reads the certificate, pulls the manifest and derives the {@code serverId} from it; the server is created with
 * everything pending (its connection, its policies, every tool). A change is written with the counter of changes in one transaction, so
 * that every instance reads it again within a poll interval, and is applied on this instance at once. Removing a server takes everything
 * the gateway holds about it: its manifests, approvals, connection, emergency switches, policy fragment and namespace, the entries of the
 * scope mapping for the types of that namespace and the overrides aimed at it. Every change is an {@code admin_change} event.
 */
public final class ServerAdmin {

    private static final Logger log = LoggerFactory.getLogger(ServerAdmin.class);
    private static final Set<String> CREDENTIAL_TYPES = Set.of("user-oauth", "user-secret", "token-exchange", "service-account");
    private static final Set<String> ADD_FIELDS = Set.of("internalUrl", "allowPlainHttp", "credential");
    private static final Set<String> PATCH_FIELDS = Set.of("credential", "enabled");
    private static final Set<String> APPROVE_FIELDS = Set.of("tlsMode", "fingerprint");

    /** A server as the API shows it, with the ETag of its settings. */
    public record Item(ServerConfig config, String etag) {
    }

    private final RegistryStore store;
    private final RegistryService registry;
    private final ServerChecks checks;
    private final ManifestValidator validator;
    private final AddressPolicy addresses;
    private final PolicyService policies;
    private final AuditLog audit;
    private final String componentId;
    private final JsonMapper json;
    private final Clock clock;
    private final Duration refreshInterval;
    private final Consumer<String> onDeleted;
    private final Map<String, Instant> refreshed = new ConcurrentHashMap<>();

    /**
     * @param refreshInterval the shortest time between two refreshes of one server (5 s, C5); a faster one is refused with the seconds to wait
     * @param onDeleted       told the serverId after a server was removed: sessions and connections towards it are dropped
     */
    public ServerAdmin(RegistryStore store, RegistryService registry, ServerChecks checks, ManifestValidator validator, AddressPolicy addresses,
                       PolicyService policies, AuditLog audit, String componentId, JsonMapper json, Clock clock, Duration refreshInterval,
                       Consumer<String> onDeleted) {
        this.store = store;
        this.registry = registry;
        this.checks = checks;
        this.validator = validator;
        this.addresses = addresses;
        this.policies = policies;
        this.audit = audit;
        this.componentId = componentId;
        this.json = json;
        this.clock = clock;
        this.refreshInterval = refreshInterval;
        this.onDeleted = onDeleted;
    }

    public List<Item> list() {
        return store.configs().stream().map(this::item).toList();
    }

    public Optional<Item> get(String serverId) {
        return store.config(serverId).map(this::item);
    }

    private Item item(ServerConfig config) {
        return new Item(config, etag(config));
    }

    /** The ETag covers what an administrator edits (settings), not what the gateway sees: it does not change at every check. */
    public String etag(ServerConfig config) {
        ObjectNode settings = json.createObjectNode();
        settings.put("serverId", config.serverId());
        settings.put("system", config.system());
        settings.put("internalUrl", config.internalUrl().toString());
        settings.put("allowPlainHttp", config.allowPlainHttp());
        settings.set("credential", credentialView(config.credential()));
        settings.put("enabled", config.enabled());
        settings.put("adapter", config.adapter());
        return PolicyService.etagOf(CanonicalJson.canonicalize(json.writeValueAsString(settings)));
    }

    public ObjectNode view(ServerConfig config) {
        ObjectNode node = json.createObjectNode();
        node.put("serverId", config.serverId());
        node.put("system", config.system());
        node.put("internalUrl", config.internalUrl().toString());
        node.put("allowPlainHttp", config.allowPlainHttp());
        node.set("credential", credentialView(config.credential()));
        node.put("enabled", config.enabled());
        node.put("adapter", config.adapter());
        node.put("status", config.status());
        node.put("lastCheckedAt", seconds(config.lastCheckedAt()));
        node.put("lastError", config.lastError());
        ServerConfig.Connection connection = config.connection();
        if (connection == null) {
            node.putNull("connection");
        } else {
            ObjectNode shown = node.putObject("connection");
            shown.put("tlsMode", connection.tlsMode());
            certificate(shown, connection.fingerprint(), connection.subject(), connection.issuer(), connection.sans(), connection.notAfter());
            shown.put("approvedBy", connection.approvedBy());
            shown.put("approvedAt", seconds(connection.approvedAt()));
        }
        ServerConfig.PendingConnection pending = config.pendingConnection();
        if (pending == null) {
            node.putNull("pendingConnection");
        } else {
            ObjectNode shown = node.putObject("pendingConnection");
            shown.put("tlsMode", pending.tlsMode());
            certificate(shown, pending.fingerprint(), pending.subject(), pending.issuer(), pending.sans(), pending.notAfter());
            shown.put("validatesAsCa", pending.validatesAsCa());
            shown.put("reason", pending.reason());
            shown.put("detectedAt", seconds(pending.detectedAt()));
        }
        return node;
    }

    private ObjectNode credentialView(ServerConfig.Credential credential) {
        ObjectNode node = json.createObjectNode();
        node.put("required", credential.required());
        ArrayNode types = node.putArray("acceptedTypes");
        credential.acceptedTypes().forEach(types::add);
        node.put("type", credential.type());
        return node;
    }

    private static void certificate(ObjectNode node, String fingerprint, String subject, String issuer, List<String> sans, Instant notAfter) {
        node.put("fingerprint", fingerprint);
        node.put("subject", subject);
        node.put("issuer", issuer);
        ArrayNode names = node.putArray("sans");
        sans.forEach(names::add);
        node.put("notAfter", seconds(notAfter));
    }

    private static String seconds(Instant at) {
        return at == null ? null : at.truncatedTo(ChronoUnit.SECONDS).toString();
    }

    /**
     * Adds a server by its address, in the order of the contract: {@code 400} for a body or an address that is not of the shape, then
     * {@code 422 server_rejected} with the reason of the first step that fails (address, http without the flag, handshake, manifest, the
     * identity derived from it), {@code 409} for a server that exists. Nothing is stored for a refusal.
     */
    public Outcome<Item> create(String requestId, JsonNode body, GatewayUser administrator) {
        if (body == null || !body.isObject() || !allKnown(body, ADD_FIELDS) || !body.path("internalUrl").isString()
                || (body.has("allowPlainHttp") && !body.get("allowPlainHttp").isBoolean())) {
            return Outcome.rejected("invalid_request", null);
        }
        Optional<ServerUrl> parsed = ServerUrl.parse(body.get("internalUrl").asString());
        Optional<ServerConfig.Credential> given = body.has("credential") ? credential(body.get("credential")) : Optional.empty();
        if (parsed.isEmpty() || (body.has("credential") && given.isEmpty())) {
            return Outcome.rejected("invalid_request", null);
        }
        ServerUrl url = parsed.get();
        boolean allowPlainHttp = body.path("allowPlainHttp").asBoolean(false);
        Optional<AddressPolicy.Refusal> refusal = addresses.check(url.host());
        if (refusal.isPresent()) {
            return refused(requestId, administrator, refusal.get().address() == null ? "tls_handshake_failed" : "address_refused",
                    refusal.get().message());
        }
        if (!url.https() && !allowPlainHttp) {
            return refused(requestId, administrator, "plain_http_not_allowed", "http needs allowPlainHttp");
        }
        Instant now = clock.instant();
        ServerChecks.Contact contact = checks.contact(url.uri(), now);
        if (contact instanceof ServerChecks.Contact.Failed failed) {
            return refused(requestId, administrator, failed.reason(), failed.message());
        }
        ServerChecks.Contact.Reached reached = (ServerChecks.Contact.Reached) contact;
        JsonNode manifest = reached.manifest();
        String system = manifest.path("system").asString("");
        if (ReservedSystemIds.isReserved(system)) {
            // Before the checks of the manifest, which refuse this system too: the administrator learns the reason that names the id.
            return refused(requestId, administrator, "system_reserved", system + " is a reserved system id: mcp-" + system
                    + " is the name of a platform component");
        }
        boolean adapter = "adapter".equals(manifest.path("source").asString(null));
        ServerConfig.Credential credential = given.orElseGet(() -> derived(manifest));
        Outcome<Item> consistent = credentialConsistent(credential);
        if (!consistent.succeeded() && consistent.status() == Outcome.Status.REJECTED) {
            return refused(requestId, administrator, consistent.reason(), consistent.message());
        }
        McpServer asManifest = new McpServer("mcp-" + system, system, url.uri(), manifest.path("version").asString(""), true,
                policyOf(credential), Map.of(), adapter, null);
        List<ManifestValidator.Rejection> rejections = registry.checkPulled(manifest, asManifest, adapter);
        if (!rejections.isEmpty()) {
            String cause = rejections.stream().map(ManifestValidator.Rejection::reason).filter(java.util.Objects::nonNull).findFirst().orElse(null);
            audit.emit(base(requestId, administrator, "mcp-" + system).reason("manifest_invalid").outcome("denied"));
            return Outcome.manifestRejected(String.join("; ", rejections.stream().map(ManifestValidator.Rejection::message).toList()), cause);
        }
        String serverId = "mcp-" + system;
        String credentialJson = validator.credentialJson(manifest);
        String namespace = manifest.path("policies").path("namespace").asString("");
        ServerConfig config = ServerConfig.added(serverId, system, url.uri(), credential, adapter, allowPlainHttp, reached.pending(), now);
        RegistryService.Stored[] stored = {null};
        Outcome<Item> written = store.locked(serverId, tx -> {
            if (tx.config().isPresent()) {
                return Outcome.of(Outcome.Status.EXISTS);
            }
            if (!adapter && tx.namespaceOwner(namespace).filter(owner -> !owner.equals(serverId)).isPresent()) {
                return Outcome.rejected(ManifestValidator.NAMESPACE_CONFLICT, "the namespace " + namespace + " belongs to another server");
            }
            tx.purgeLeftovers();
            tx.saveConfig(config, true);
            stored[0] = registry.writeManifest(tx, serverId, adapter, manifest, credentialJson);
            return Outcome.created(item(config));
        });
        if (written.succeeded()) {
            audit.emit(base(requestId, administrator, serverId).reason("server_created").outcome("ok"));
            registry.recordPulled(requestId, serverId, stored[0]);
            applyHere();
        } else if (written.status() == Outcome.Status.REJECTED) {
            audit.emit(base(requestId, administrator, serverId).reason(written.reason()).outcome("denied"));
        }
        return written;
    }

    private Outcome<Item> refused(String requestId, GatewayUser administrator, String reason, String message) {
        audit.emit(AuditEvent.of("admin_change", requestId, componentId).userWithoutClient(administrator).reason(reason).outcome("denied"));
        return Outcome.rejected(reason, message);
    }

    /** The credential settings of a server that was added without them: what its manifest says it accepts. */
    private static ServerConfig.Credential derived(JsonNode manifest) {
        JsonNode credential = manifest.path("credential");
        Set<String> accepted = new LinkedHashSet<>();
        credential.path("acceptedTypes").forEach(type -> accepted.add(type.asString()));
        if (accepted.isEmpty()) {
            // A system that needs no credential accepts none; the settings still need a type (it is the default of the system).
            accepted.add("user-secret");
        }
        return new ServerConfig.Credential(credential.path("required").asBoolean(true), List.copyOf(accepted), accepted.iterator().next());
    }

    private static CredentialPolicy policyOf(ServerConfig.Credential credential) {
        return new CredentialPolicy(credential.required(), Set.copyOf(credential.acceptedTypes()), List.of(),
                "token-exchange".equals(credential.type()), credential.required() ? credential.type() : null);
    }

    /** {@code service-account} stays alone (CC-168), and the default type is one of the accepted ones. */
    private static Outcome<Item> credentialConsistent(ServerConfig.Credential credential) {
        if (credential.acceptedTypes().contains("service-account") && credential.acceptedTypes().size() > 1) {
            // context.credentialType is one default type: a mixed set would hide a service account from the rules about it (CC-168).
            return Outcome.rejected("credential_types_mixed", "acceptedTypes mixes service-account with user types");
        }
        if (!credential.acceptedTypes().contains(credential.type())) {
            return Outcome.rejected("credential_type_not_accepted", "type must be one of acceptedTypes");
        }
        return Outcome.ok(null);
    }

    /** Only the fields in the body change; the address, the plain-http flag, {@code serverId}, {@code system} and the adapter mode never do. */
    public Outcome<Item> update(String requestId, String serverId, String ifMatch, JsonNode body, GatewayUser administrator) {
        if (body == null || !body.isObject() || body.isEmpty() || !allKnown(body, PATCH_FIELDS)) {
            return Outcome.rejected("invalid_request", null);
        }
        if (ifMatch == null) {
            return Outcome.of(Outcome.Status.PRECONDITION_REQUIRED);
        }
        List<String> changed = new ArrayList<>();
        Outcome<Item> written = store.locked(serverId, tx -> {
            Optional<ServerConfig> current = tx.config();
            if (current.isEmpty()) {
                return Outcome.of(Outcome.Status.NOT_FOUND);
            }
            if (!etag(current.get()).equals(ifMatch)) {
                return Outcome.of(Outcome.Status.PRECONDITION_FAILED);
            }
            ServerConfig before = current.get();
            ServerConfig.Credential credential = before.credential();
            if (body.has("credential")) {
                Optional<ServerConfig.Credential> parsed = credential(body.get("credential"));
                if (parsed.isEmpty()) {
                    return Outcome.rejected("invalid_request", null);
                }
                credential = parsed.get();
                Outcome<Item> consistent = credentialConsistent(credential);
                if (consistent.status() == Outcome.Status.REJECTED) {
                    return Outcome.rejected(consistent.reason(), consistent.message());
                }
            }
            if (body.has("enabled") && !body.get("enabled").isBoolean()) {
                return Outcome.rejected("invalid_request", null);
            }
            boolean enabled = body.has("enabled") ? body.get("enabled").asBoolean() : before.enabled();
            ServerConfig after = new ServerConfig(before.serverId(), before.system(), before.internalUrl(), credential, enabled, before.adapter(),
                    before.allowPlainHttp(), before.status(), before.lastCheckedAt(), before.lastError(), before.connection(),
                    before.pendingConnection());
            if (!before.credential().equals(after.credential())) {
                changed.add("credential");
            }
            if (before.enabled() != after.enabled()) {
                changed.add("enabled");
            }
            tx.saveConfig(after, false);
            return Outcome.ok(item(after));
        });
        if (written.succeeded()) {
            audit.emit(base(requestId, administrator, serverId).reason("server_updated").changedFields(changed).outcome("ok"));
            applyHere();
        } else if (written.status() == Outcome.Status.REJECTED && !"invalid_request".equals(written.reason())) {
            audit.emit(base(requestId, administrator, serverId).reason(written.reason()).outcome("denied"));
        }
        return written;
    }

    /**
     * Approves the pending connection (C5 approveServerConnection): the body repeats the mode and the fingerprint the administrator saw.
     * Approves no policy and no tool. The gateway then connects under the approved trust, which sets the status.
     */
    public Outcome<Item> approveConnection(String requestId, String serverId, JsonNode body, GatewayUser administrator) {
        if (body == null || !body.isObject() || !allKnown(body, APPROVE_FIELDS) || !body.path("tlsMode").isString()
                || !(body.path("fingerprint").isString() || body.path("fingerprint").isNull())
                || !body.has("fingerprint") || !Set.of("ca", "pinned", "plain").contains(body.get("tlsMode").asString())) {
            return Outcome.rejected("invalid_request", null);
        }
        String tlsMode = body.get("tlsMode").asString();
        String fingerprint = body.get("fingerprint").isNull() ? null : body.get("fingerprint").asString();
        if (fingerprint != null && !Pattern.matches("^sha256:[0-9a-f]{64}$", fingerprint)) {
            return Outcome.rejected("invalid_request", null);
        }
        Instant now = clock.instant();
        Outcome<ServerConfig> decided = store.locked(serverId, tx -> {
            Optional<ServerConfig> current = tx.config();
            if (current.isEmpty()) {
                return Outcome.of(Outcome.Status.NOT_FOUND);
            }
            ServerConfig before = current.get();
            ConnectionRules.Approval verdict = ConnectionRules.approve(before.pendingConnection(), tlsMode, fingerprint,
                    "https".equals(before.internalUrl().getScheme()), before.allowPlainHttp());
            if (verdict instanceof ConnectionRules.Approval.Refused refused) {
                return refused.status() == 409 ? Outcome.conflict(refused.error()) : Outcome.rejected(refused.reason(), "the connection cannot be approved as " + tlsMode);
            }
            ServerConfig.PendingConnection pending = before.pendingConnection();
            ServerConfig.Connection connection = new ServerConfig.Connection(tlsMode, fingerprint, pending.subject(), pending.issuer(),
                    pending.sans(), pending.notAfter(), administrator.sub(), now.truncatedTo(ChronoUnit.MILLIS));
            ServerConfig after = new ServerConfig(before.serverId(), before.system(), before.internalUrl(), before.credential(), before.enabled(),
                    before.adapter(), before.allowPlainHttp(), before.status(), before.lastCheckedAt(), before.lastError(), connection, null);
            tx.saveState(after);
            return Outcome.ok(after);
        });
        if (!decided.succeeded()) {
            if (decided.status() == Outcome.Status.REJECTED || decided.status() == Outcome.Status.CONFLICT) {
                audit.emit(base(requestId, administrator, serverId).reason(decided.reason()).outcome("denied"));
            }
            return new Outcome<>(decided.status(), null, decided.reason(), decided.message());
        }
        audit.emit(base(requestId, administrator, serverId).reason("server_connection_approved").tlsMode(tlsMode).fingerprint(fingerprint)
                .outcome("ok"));
        applyHere();
        Optional<ServerConfig> after = checks.check(requestId, serverId);
        return after.<Outcome<Item>>map(config -> Outcome.ok(item(config))).orElseGet(() -> Outcome.of(Outcome.Status.NOT_FOUND));
    }

    /**
     * Probes the server and pulls its manifest now (C5 refreshServer): what the gateway does at add time and in its loop. A failure of the
     * connection is no error here, it is the status and the error of the server in the answer. At most one per server per
     * {@code refreshInterval}.
     */
    public Outcome<Item> refresh(String requestId, String serverId) {
        if (store.config(serverId).isEmpty()) {
            return Outcome.of(Outcome.Status.NOT_FOUND);
        }
        Instant now = clock.instant();
        Instant[] previous = {null};
        refreshed.compute(serverId, (id, last) -> {
            previous[0] = last;
            return last != null && Duration.between(last, now).compareTo(refreshInterval) < 0 ? last : now;
        });
        if (previous[0] != null && Duration.between(previous[0], now).compareTo(refreshInterval) < 0) {
            long wait = Math.max(1, refreshInterval.minus(Duration.between(previous[0], now)).plusMillis(999).toSeconds());
            return new Outcome<>(Outcome.Status.TOO_MANY_REQUESTS, null, "refresh_too_frequent", Long.toString(wait));
        }
        Optional<ServerConfig> after = checks.check(requestId, serverId);
        return after.<Outcome<Item>>map(config -> Outcome.ok(item(config))).orElseGet(() -> Outcome.of(Outcome.Status.NOT_FOUND));
    }

    private static boolean allKnown(JsonNode body, Set<String> fields) {
        return body.propertyNames().stream().allMatch(fields::contains);
    }

    private static Optional<ServerConfig.Credential> credential(JsonNode node) {
        if (!node.isObject() || node.size() != 3 || !node.path("required").isBoolean() || !node.path("acceptedTypes").isArray()
                || !node.path("type").isString() || node.get("acceptedTypes").isEmpty()) {
            return Optional.empty();
        }
        Set<String> accepted = new LinkedHashSet<>();
        for (JsonNode type : node.get("acceptedTypes")) {
            if (!type.isString() || !CREDENTIAL_TYPES.contains(type.asString()) || !accepted.add(type.asString())) {
                return Optional.empty();
            }
        }
        if (!CREDENTIAL_TYPES.contains(node.get("type").asString())) {
            return Optional.empty();
        }
        return Optional.of(new ServerConfig.Credential(node.get("required").asBoolean(), List.copyOf(accepted), node.get("type").asString()));
    }

    /**
     * Removes the server and everything of it: its tools leave {@code tools/list} (listChanged to the clients), the gateway no longer pulls
     * from it or pushes policy data to it, its namespace is free, the entries of the scope mapping for the types of that namespace and the
     * overrides aimed at it are removed and audited one by one.
     */
    public Outcome<Void> delete(String requestId, String serverId, GatewayUser administrator) {
        List<MappingCleanup.Removed> removedScopes = new ArrayList<>();
        List<pl.aiwcorpo.mcp.gateway.policy.PolicyOverride> removedOverrides = new ArrayList<>();
        List<RegisteredTool> removedTools = new ArrayList<>();
        List<String> removedSwitches = new ArrayList<>();
        List<String> removedNamespaces = new ArrayList<>();
        boolean[] hadPolicies = {false};
        Outcome<Void> result = store.locked(serverId, tx -> {
            if (tx.config().isEmpty()) {
                return Outcome.of(Outcome.Status.NOT_FOUND);
            }
            var state = tx.lockPolicyState();
            removedNamespaces.addAll(tx.namespaces());
            MappingCleanup.Result cleaned = MappingCleanup.strip(json, state.scopeMapping(), new TreeSet<>(removedNamespaces));
            removedScopes.addAll(cleaned.removed());
            if (!removedScopes.isEmpty()) {
                tx.saveScopeMapping(cleaned.mapping());
            }
            removedTools.addAll(tx.tools().values());
            removedSwitches.addAll(tx.killSwitchTools());
            hadPolicies[0] = tx.policies().approved() || tx.policies().pending();
            removedOverrides.addAll(tx.overridesOf());
            tx.deleteOverridesOf();
            tx.deleteAll();
            tx.raiseRevision();
            return Outcome.noContent();
        });
        if (result.succeeded()) {
            audit.emit(base(requestId, administrator, serverId).reason("server_deleted").outcome("ok"));
            removedScopes.forEach(removed -> audit.emit(base(requestId, administrator, serverId).reason("scope_mapping_entry_removed")
                    .outcome("ok").group(removed.group()).resource(new PendingCall.Resource(removed.type(), removed.local(), null))));
            removedOverrides.forEach(override -> audit.emit(base(requestId, administrator, serverId).reason("override_removed")
                    .override(override.id(), override.target(), override.text(), null).outcome("ok")));
            removedTools.forEach(tool -> audit.emit(base(requestId, administrator, serverId).reason("tool_removed").tool(tool.name())
                    .definitionHash(tool.approved() != null ? tool.approved().hash() : tool.pending().hash()).outcome("ok")));
            removedSwitches.forEach(tool -> audit.emit(base(requestId, administrator, serverId).reason("kill_switch_cleared")
                    .tool(tool.isEmpty() ? null : tool).outcome("ok")));
            if (hadPolicies[0]) {
                audit.emit(base(requestId, administrator, serverId).reason("policies_removed").outcome("ok"));
            }
            removedNamespaces.forEach(namespace -> audit.emit(base(requestId, administrator, serverId).reason("namespace_released")
                    .outcome("ok")));
            log.info("{} removed: {} scope mapping entries and {} overrides went with it", serverId, removedScopes.size(),
                    removedOverrides.size());
            refreshed.remove(serverId);
            onDeleted.accept(serverId);
            applyHere();
        }
        return result;
    }

    private AuditEvent base(String requestId, GatewayUser administrator, String serverId) {
        return AuditEvent.of("admin_change", requestId, componentId).userWithoutClient(administrator).server(serverId);
    }

    /** The change is in force on this instance at once; the others read it when the counter moves. */
    private void applyHere() {
        try {
            registry.reloadChanged();
            policies.reload();
        } catch (RuntimeException e) {
            log.warn("the change was stored but could not be read back: {}", e.getClass().getName());
        }
    }
}
