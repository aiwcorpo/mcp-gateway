package pl.aiwcorpo.mcp.gateway.registry;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Consumer;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pl.aiwcorpo.mcp.gateway.audit.AuditEvent;
import pl.aiwcorpo.mcp.gateway.audit.AuditLog;
import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.confirm.PendingCall;
import pl.aiwcorpo.mcp.gateway.policy.PolicyService;
import pl.aiwcorpo.mcp.manifest.CanonicalJson;
import pl.aiwcorpo.mcp.manifest.ReservedSystemIds;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * The registry of servers (C5 {@code /admin/v1/servers}): the only list of servers. A change is written with the counter of changes in one
 * transaction, so that every instance reads it again within a poll interval, and is applied on this instance at once. Removing a server
 * takes everything the gateway holds about it: its manifests, approvals, emergency switches, policy fragment and namespace, the entries of
 * the scope mapping for the types of that namespace and the overrides aimed at it. Every change is an {@code admin_change} event.
 */
public final class ServerAdmin {

    private static final Logger log = LoggerFactory.getLogger(ServerAdmin.class);
    private static final Pattern SERVER_ID = Pattern.compile("^mcp-[a-z][a-z0-9]{1,30}$");
    private static final Pattern SYSTEM = Pattern.compile("^[a-z][a-z0-9]{1,30}$");
    private static final Pattern TLS_NAME = Pattern.compile("^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$");
    private static final Set<String> CREDENTIAL_TYPES = Set.of("user-oauth", "user-secret", "token-exchange", "service-account");
    private static final Set<String> CREATE_FIELDS = Set.of("serverId", "system", "internalUrl", "tlsName", "credential", "enabled", "adapter");
    private static final Set<String> PATCH_FIELDS = Set.of("internalUrl", "tlsName", "credential", "enabled", "adapter");

    /** A server as the API shows it, with the ETag of that document. */
    public record Item(ServerConfig config, String etag) {
    }

    private final RegistryStore store;
    private final RegistryService registry;
    private final PolicyService policies;
    private final AuditLog audit;
    private final String componentId;
    private final JsonMapper json;
    private final Consumer<String> onDeleted;

    /** @param onDeleted told the serverId after a server was removed: sessions and connections towards it are dropped */
    public ServerAdmin(RegistryStore store, RegistryService registry, PolicyService policies, AuditLog audit, String componentId,
                       JsonMapper json, Consumer<String> onDeleted) {
        this.store = store;
        this.registry = registry;
        this.policies = policies;
        this.audit = audit;
        this.componentId = componentId;
        this.json = json;
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

    public String etag(ServerConfig config) {
        return PolicyService.etagOf(CanonicalJson.canonicalize(json.writeValueAsString(view(config))));
    }

    public ObjectNode view(ServerConfig config) {
        ObjectNode node = json.createObjectNode();
        node.put("serverId", config.serverId());
        node.put("system", config.system());
        node.put("internalUrl", config.internalUrl().toString());
        node.put("tlsName", config.tlsName());
        ObjectNode credential = node.putObject("credential");
        credential.put("required", config.credential().required());
        ArrayNode types = credential.putArray("acceptedTypes");
        config.credential().acceptedTypes().forEach(types::add);
        credential.put("type", config.credential().type());
        node.put("enabled", config.enabled());
        node.put("adapter", config.adapter());
        return node;
    }

    /** {@code 400} for a body that is not of the shape of the contract (reason invalid_request), {@code 422 server_rejected} for one that is inconsistent. */
    public Outcome<Item> create(String requestId, JsonNode body, GatewayUser administrator) {
        if (body == null || !body.isObject() || !allKnown(body, CREATE_FIELDS) || !body.has("serverId") || !body.has("system")
                || !body.has("internalUrl") || !body.has("credential")) {
            return Outcome.rejected("invalid_request", null);
        }
        String serverId = body.path("serverId").asString("");
        String system = body.path("system").asString("");
        if (!SERVER_ID.matcher(serverId).matches() || !SYSTEM.matcher(system).matches()) {
            return Outcome.rejected("invalid_request", null);
        }
        Outcome<ServerConfig> parsed = parse(serverId, system, body, true, null);
        if (!parsed.succeeded()) {
            return rejection(requestId, serverId, parsed, administrator);
        }
        ServerConfig config = parsed.value();
        Outcome<Item> written = store.locked(serverId, tx -> {
            if (tx.config().isPresent()) {
                return Outcome.of(Outcome.Status.EXISTS);
            }
            tx.saveConfig(config, true);
            return Outcome.created(item(config));
        });
        if (written.succeeded()) {
            audit.emit(base(requestId, administrator, serverId).reason("server_created").outcome("ok"));
            applyHere();
        }
        return written;
    }

    /** Only the fields in the body change; {@code serverId} and {@code system} never do. */
    public Outcome<Item> update(String requestId, String serverId, String ifMatch, JsonNode body, GatewayUser administrator) {
        if (body == null || !body.isObject() || body.isEmpty() || !allKnown(body, PATCH_FIELDS)) {
            return Outcome.rejected("invalid_request", null);
        }
        if (ifMatch == null) {
            return Outcome.of(Outcome.Status.PRECONDITION_REQUIRED);
        }
        Outcome<Item> written = store.locked(serverId, tx -> {
            Optional<ServerConfig> current = tx.config();
            if (current.isEmpty()) {
                return Outcome.of(Outcome.Status.NOT_FOUND);
            }
            if (!etag(current.get()).equals(ifMatch)) {
                return Outcome.of(Outcome.Status.PRECONDITION_FAILED);
            }
            Outcome<ServerConfig> parsed = parse(serverId, current.get().system(), body, false, current.get());
            if (!parsed.succeeded()) {
                return Outcome.rejected(parsed.reason(), parsed.message());
            }
            tx.saveConfig(parsed.value(), false);
            return Outcome.ok(item(parsed.value()));
        });
        if (written.succeeded()) {
            audit.emit(base(requestId, administrator, serverId).reason("server_updated").outcome("ok"));
            applyHere();
        } else if (written.status() == Outcome.Status.REJECTED && !"invalid_request".equals(written.reason())) {
            audit.emit(base(requestId, administrator, serverId).reason(written.reason()).outcome("denied"));
        }
        return written;
    }

    private Outcome<Item> rejection(String requestId, String serverId, Outcome<ServerConfig> parsed, GatewayUser administrator) {
        if (!"invalid_request".equals(parsed.reason())) {
            audit.emit(base(requestId, administrator, serverId).reason(parsed.reason()).outcome("denied"));
        }
        return Outcome.rejected(parsed.reason(), parsed.message());
    }

    private static boolean allKnown(JsonNode body, Set<String> fields) {
        return body.propertyNames().stream().allMatch(fields::contains);
    }

    /** The settings that result: {@code current} (null for a create) overlaid with the fields of the body, checked as a whole. */
    private Outcome<ServerConfig> parse(String serverId, String system, JsonNode body, boolean create, ServerConfig current) {
        if (!serverId.equals("mcp-" + system)) {
            return Outcome.rejected("server_id_mismatch", "serverId must be mcp-<system>");
        }
        if (ReservedSystemIds.isReserved(system)) {
            return Outcome.rejected("system_reserved", system + " is a reserved system id: mcp-" + system + " is the name of a platform component");
        }
        URI url = current == null ? null : current.internalUrl();
        if (body.has("internalUrl")) {
            String text = body.get("internalUrl").isString() ? body.get("internalUrl").asString() : "";
            try {
                url = URI.create(text);
            } catch (IllegalArgumentException e) {
                return Outcome.rejected("invalid_request", null);
            }
            if (text.length() > 255 || !"https".equals(url.getScheme()) || url.getHost() == null || url.getUserInfo() != null) {
                return Outcome.rejected("invalid_request", null);
            }
        }
        String tlsName = current == null ? ServerConfig.defaultTlsName(serverId) : current.tlsName();
        if (body.has("tlsName")) {
            tlsName = body.get("tlsName").isString() ? body.get("tlsName").asString() : "";
            if (!TLS_NAME.matcher(tlsName).matches()) {
                return Outcome.rejected("invalid_request", null);
            }
        }
        ServerConfig.Credential credential = current == null ? null : current.credential();
        if (body.has("credential")) {
            Optional<ServerConfig.Credential> parsed = credential(body.get("credential"));
            if (parsed.isEmpty()) {
                return Outcome.rejected("invalid_request", null);
            }
            credential = parsed.get();
        }
        boolean enabled = current == null || current.enabled();
        boolean adapter = current != null && current.adapter();
        for (String flag : List.of("enabled", "adapter")) {
            if (body.has(flag) && !body.get(flag).isBoolean()) {
                return Outcome.rejected("invalid_request", null);
            }
        }
        enabled = body.has("enabled") ? body.get("enabled").asBoolean() : enabled;
        adapter = body.has("adapter") ? body.get("adapter").asBoolean() : adapter;
        if (!create && body.isEmpty()) {
            return Outcome.rejected("invalid_request", null);
        }
        if (credential.acceptedTypes().contains("service-account") && credential.acceptedTypes().size() > 1) {
            // context.credentialType is one default type: a mixed set would hide a service account from the rules about it (CC-168).
            return Outcome.rejected("credential_types_mixed", "acceptedTypes mixes service-account with user types");
        }
        if (!credential.acceptedTypes().contains(credential.type())) {
            return Outcome.rejected("credential_type_not_accepted", "type must be one of acceptedTypes");
        }
        return Outcome.ok(new ServerConfig(serverId, system, url, tlsName, credential, enabled, adapter));
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
     * Removes the server and everything of it: its tools leave {@code tools/list} (listChanged to the clients), its certificate no longer
     * gets policy data, its namespace is free, the entries of the scope mapping for the types of that namespace and the overrides aimed at it
     * are removed and audited one by one.
     */
    public Outcome<Void> delete(String requestId, String serverId, GatewayUser administrator) {
        List<PendingCall.Resource> removedScopes = new ArrayList<>();
        List<String> removedOverrides = new ArrayList<>();
        Outcome<Void> result = store.locked(serverId, tx -> {
            if (tx.config().isEmpty()) {
                return Outcome.of(Outcome.Status.NOT_FOUND);
            }
            var state = tx.lockPolicyState();
            Set<String> prefixes = new TreeSet<>();
            tx.namespaces().forEach(namespace -> prefixes.add(namespace + "::"));
            ArrayNode kept = json.createArrayNode();
            for (JsonNode entry : state.scopeMapping()) {
                ArrayNode scopes = json.createArrayNode();
                boolean touched = false;
                for (JsonNode scope : entry.path("scopes")) {
                    String id = scope.asString();
                    if (prefixes.stream().anyMatch(id::startsWith)) {
                        touched = true;
                        int slash = id.indexOf('/');
                        removedScopes.add(new PendingCall.Resource(id.substring(0, slash), id.substring(slash + 1), null));
                    } else {
                        scopes.add(scope);
                    }
                }
                if (!touched) {
                    kept.add(entry);
                } else if (!scopes.isEmpty()) {
                    ObjectNode rewritten = json.createObjectNode();
                    rewritten.put("group", entry.path("group").asString());
                    rewritten.set("scopes", scopes);
                    kept.add(rewritten);
                }
            }
            if (!removedScopes.isEmpty()) {
                tx.saveScopeMapping(kept);
            }
            tx.overridesOf().forEach(override -> removedOverrides.add(override.id()));
            tx.deleteOverridesOf();
            tx.deleteAll();
            tx.raiseRevision();
            return Outcome.noContent();
        });
        if (result.succeeded()) {
            audit.emit(base(requestId, administrator, serverId).reason("server_deleted").outcome("ok"));
            removedScopes.forEach(scope -> audit.emit(base(requestId, administrator, serverId).reason("scope_mapping_entry_removed")
                    .outcome("ok").resource(scope)));
            removedOverrides.forEach(id -> audit.emit(base(requestId, administrator, serverId).reason("override_removed").outcome("ok")));
            if (!removedScopes.isEmpty() || !removedOverrides.isEmpty()) {
                log.info("{} removed: {} scope mapping entries and {} overrides went with it", serverId, removedScopes.size(),
                        removedOverrides.size());
            }
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
