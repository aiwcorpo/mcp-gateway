package pl.aiwcorpo.mcp.gateway.agent;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pl.aiwcorpo.mcp.gateway.audit.AuditEvent;
import pl.aiwcorpo.mcp.gateway.audit.AuditLog;
import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.confirm.TextHygiene;
import pl.aiwcorpo.mcp.gateway.policy.PolicyService;
import pl.aiwcorpo.mcp.gateway.registry.Outcome;
import pl.aiwcorpo.mcp.gateway.registry.RegistryStore;
import pl.aiwcorpo.mcp.gateway.server.Risk;
import pl.aiwcorpo.mcp.manifest.CanonicalJson;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * The registry of agents (C5, CC-266): create, change, key rotation record, delete, suspend and resume. Every write runs under the lock of
 * the policy data row, so two changes of agents go one after another, and raises the counter of changes in its transaction. Creating,
 * deleting, suspending and resuming an agent also raises the revision of the policy data (the servers hold the active agents of that
 * revision once they are told about them). The writes are audited as {@code admin_change}; the text of a suspension stays in the registry.
 */
public final class AgentAdmin {

    private static final Logger log = LoggerFactory.getLogger(AgentAdmin.class);
    private static final Pattern GROUP = Pattern.compile("^mcp-[A-Za-z0-9][A-Za-z0-9._-]*$");
    private static final Set<String> CREATE_FIELDS = Set.of("clientId", "serviceAccountSub", "ownerSub", "maxRisk", "allowedGroups", "delegationAllowed");
    private static final Set<String> PATCH_FIELDS = Set.of("maxRisk", "allowedGroups", "delegationAllowed", "ownerSub");

    /** An agent with the entity tag of its document, which {@code PATCH} sends back in {@code If-Match}. */
    public record Item(AgentClient agent, String etag) {
    }

    private final AgentStore agents;
    private final RegistryStore store;
    private final AuditLog audit;
    private final String componentId;
    private final JsonMapper json;
    private final Clock clock;
    private final Runnable afterWrite;

    /** @param afterWrite told after a change was stored, so that this instance reads it at once; the other instances read it within the poll interval */
    public AgentAdmin(AgentStore agents, RegistryStore store, AuditLog audit, String componentId, JsonMapper json, Clock clock, Runnable afterWrite) {
        this.agents = agents;
        this.store = store;
        this.audit = audit;
        this.componentId = componentId;
        this.json = json;
        this.clock = clock;
        this.afterWrite = afterWrite;
    }

    public List<AgentClient> list() {
        return agents.all();
    }

    public List<AgentClient> ownedBy(String ownerSub) {
        return agents.ownedBy(ownerSub);
    }

    public Optional<Item> get(String clientId) {
        return agents.find(clientId).map(this::item);
    }

    public Item item(AgentClient agent) {
        return new Item(agent, PolicyService.etagOf(CanonicalJson.canonicalize(json.writeValueAsString(view(agent)))));
    }

    /** The {@code AgentClient} of the contract. */
    public ObjectNode view(AgentClient agent) {
        ObjectNode node = json.createObjectNode();
        node.put("clientId", agent.clientId());
        node.put("serviceAccountSub", agent.serviceAccountSub());
        node.put("ownerSub", agent.ownerSub());
        node.put("status", agent.suspended() ? "suspended" : "active");
        node.put("maxRisk", agent.maxRisk().name());
        agent.allowedGroups().forEach(node.putArray("allowedGroups")::add);
        node.put("delegationAllowed", agent.delegationAllowed());
        node.put("createdBy", agent.createdBy());
        node.put("createdAt", second(agent.createdAt()));
        if (agent.keyRotatedAt() != null) {
            node.put("keyRotatedAt", second(agent.keyRotatedAt()));
        }
        if (agent.suspended()) {
            node.put("suspendedBy", agent.suspension().by());
            node.put("suspendedAt", second(agent.suspension().at()));
            node.put("suspendReason", agent.suspension().reason());
        }
        return node;
    }

    private static String second(Instant instant) {
        return instant.truncatedTo(ChronoUnit.SECONDS).toString();
    }

    public Outcome<Item> create(String requestId, JsonNode body, GatewayUser administrator) {
        if (body == null || !body.isObject() || !CREATE_FIELDS.containsAll(fieldNames(body)) || !body.has("clientId")
                || !body.has("serviceAccountSub") || !body.has("ownerSub")) {
            return Outcome.rejected("invalid_request", null);
        }
        String clientId = text(body.get("clientId"), 64);
        String serviceAccountSub = text(body.get("serviceAccountSub"), 255);
        String ownerSub = text(body.get("ownerSub"), 255);
        Optional<Risk> maxRisk = body.has("maxRisk") ? risk(body.get("maxRisk")) : Optional.of(Risk.READ_ONLY);
        Optional<List<String>> groups = body.has("allowedGroups") ? groups(body.get("allowedGroups")) : Optional.of(List.of());
        if (clientId == null || !AgentClient.CLIENT_ID.matcher(clientId).matches() || serviceAccountSub == null
                || serviceAccountSub.startsWith("system:") || ownerSub == null || maxRisk.isEmpty() || groups.isEmpty()
                || (body.has("delegationAllowed") && !body.get("delegationAllowed").isBoolean())) {
            return Outcome.rejected("invalid_request", null);
        }
        Outcome<Item> rejection = rejection(maxRisk.get(), groups.get());
        if (rejection != null) {
            auditRejected(requestId, administrator, clientId, ownerSub, rejection.reason());
            return rejection;
        }
        AgentClient agent = new AgentClient(clientId, serviceAccountSub, ownerSub, maxRisk.get(), groups.get(),
                body.path("delegationAllowed").asBoolean(false), administrator.sub(), clock.instant().truncatedTo(ChronoUnit.MILLIS), null, null);
        Outcome<Item> result = store.policyLocked(tx -> {
            if (agents.find(clientId).isPresent()) {
                return Outcome.of(Outcome.Status.EXISTS);
            }
            agents.insert(agent);
            tx.raiseRevision();
            return Outcome.created(item(agent));
        });
        if (result.succeeded()) {
            audit.emit(adminEvent(requestId, administrator, agent).reason("agent_registered").outcome("ok"));
            written();
        }
        return result;
    }

    public Outcome<Item> update(String requestId, String clientId, String ifMatch, JsonNode body, GatewayUser administrator) {
        if (body == null || !body.isObject() || body.isEmpty() || !PATCH_FIELDS.containsAll(fieldNames(body))) {
            return Outcome.rejected("invalid_request", null);
        }
        if (ifMatch == null) {
            return Outcome.of(Outcome.Status.PRECONDITION_REQUIRED);
        }
        Optional<Risk> maxRisk = body.has("maxRisk") ? risk(body.get("maxRisk")) : Optional.empty();
        Optional<List<String>> groups = body.has("allowedGroups") ? groups(body.get("allowedGroups")) : Optional.empty();
        String ownerSub = body.has("ownerSub") ? text(body.get("ownerSub"), 255) : null;
        if ((body.has("maxRisk") && maxRisk.isEmpty()) || (body.has("allowedGroups") && groups.isEmpty())
                || (body.has("ownerSub") && ownerSub == null) || (body.has("delegationAllowed") && !body.get("delegationAllowed").isBoolean())) {
            return Outcome.rejected("invalid_request", null);
        }
        Outcome<Item> rejection = rejection(maxRisk.orElse(Risk.READ_ONLY), groups.orElse(List.of()));
        if (rejection != null) {
            auditRejected(requestId, administrator, clientId, null, rejection.reason());
            return rejection;
        }
        List<String> changed = new ArrayList<>();
        Outcome<Item> result = store.policyLocked(tx -> {
            Optional<AgentClient> current = agents.lock(clientId);
            if (current.isEmpty()) {
                return Outcome.of(Outcome.Status.NOT_FOUND);
            }
            if (!item(current.get()).etag().equals(ifMatch)) {
                return Outcome.of(Outcome.Status.PRECONDITION_FAILED);
            }
            AgentClient before = current.get();
            AgentClient after = new AgentClient(before.clientId(), before.serviceAccountSub(), ownerSub != null ? ownerSub : before.ownerSub(),
                    maxRisk.orElse(before.maxRisk()), groups.orElse(before.allowedGroups()),
                    body.has("delegationAllowed") ? body.get("delegationAllowed").asBoolean() : before.delegationAllowed(), before.createdBy(),
                    before.createdAt(), before.keyRotatedAt(), before.suspension());
            if (!after.maxRisk().equals(before.maxRisk())) {
                changed.add("maxRisk");
            }
            if (!after.allowedGroups().equals(before.allowedGroups())) {
                changed.add("allowedGroups");
            }
            if (after.delegationAllowed() != before.delegationAllowed()) {
                changed.add("delegationAllowed");
            }
            if (!after.ownerSub().equals(before.ownerSub())) {
                changed.add("ownerSub");
            }
            if (!changed.isEmpty()) {
                agents.updateSettings(after);
                tx.changed();
            }
            return Outcome.ok(item(after));
        });
        if (result.succeeded() && !changed.isEmpty()) {
            audit.emit(adminEvent(requestId, administrator, result.value().agent()).reason("agent_updated").outcome("ok"));
            written();
        }
        return result;
    }

    /** Idempotent: removing an agent that is not there is no failure and leaves no event. */
    public Outcome<Void> delete(String requestId, String clientId, GatewayUser administrator) {
        AtomicReference<AgentClient> removed = new AtomicReference<>();
        store.policyLocked(tx -> {
            removed.set(agents.lock(clientId).orElse(null));
            if (removed.get() != null) {
                agents.delete(clientId);
                tx.raiseRevision();
            }
            return null;
        });
        if (removed.get() != null) {
            audit.emit(adminEvent(requestId, administrator, removed.get()).reason("agent_deleted").outcome("ok"));
            written();
        }
        return Outcome.noContent();
    }

    public Outcome<Void> recordKeyRotation(String requestId, String clientId, GatewayUser administrator) {
        AtomicReference<AgentClient> found = new AtomicReference<>();
        store.policyLocked(tx -> {
            found.set(agents.lock(clientId).orElse(null));
            if (found.get() != null) {
                agents.recordKeyRotation(clientId, clock.instant().truncatedTo(ChronoUnit.MILLIS));
                tx.changed();
            }
            return null;
        });
        if (found.get() == null) {
            return Outcome.of(Outcome.Status.NOT_FOUND);
        }
        audit.emit(adminEvent(requestId, administrator, found.get()).reason("agent_key_rotated").outcome("ok"));
        written();
        return Outcome.noContent();
    }

    /**
     * Suspends an agent. An administrator may suspend any agent, the owner only theirs; for anyone else the agent does not exist.
     * A suspension that is on stays on and only its text changes, so the revision of the policy data is raised once.
     */
    public Outcome<Void> suspend(String requestId, String clientId, String reason, GatewayUser actor, boolean administrator) {
        AtomicReference<AgentClient> found = new AtomicReference<>();
        store.policyLocked(tx -> {
            AgentClient current = agents.lock(clientId).orElse(null);
            if (current == null || !(administrator || current.ownerSub().equals(actor.sub()))) {
                return null;
            }
            found.set(current);
            agents.suspend(clientId, actor.sub(), clock.instant().truncatedTo(ChronoUnit.MILLIS), reason);
            if (current.suspended()) {
                tx.changed();
            } else {
                tx.raiseRevision();
            }
            return null;
        });
        if (found.get() == null) {
            return Outcome.of(Outcome.Status.NOT_FOUND);
        }
        audit.emit(adminEvent(requestId, actor, found.get()).reason("agent_kill_switch_set").outcome("ok"));
        written();
        return Outcome.noContent();
    }

    /** Only an administrator lifts a suspension; idempotent for an agent that is active. */
    public Outcome<Void> resume(String requestId, String clientId, GatewayUser administrator) {
        AtomicReference<AgentClient> found = new AtomicReference<>();
        store.policyLocked(tx -> {
            found.set(agents.lock(clientId).orElse(null));
            if (found.get() != null && found.get().suspended()) {
                agents.resume(clientId);
                tx.raiseRevision();
            }
            return null;
        });
        if (found.get() == null) {
            return Outcome.of(Outcome.Status.NOT_FOUND);
        }
        audit.emit(adminEvent(requestId, administrator, found.get()).reason("agent_kill_switch_cleared").outcome("ok"));
        written();
        return Outcome.noContent();
    }

    /** The owner left (offboarding): their agents that are active are suspended, each with an event of its own. */
    public void suspendAgentsOf(String requestId, String ownerSub) {
        List<AgentClient> suspended = new ArrayList<>();
        store.policyLocked(tx -> {
            for (AgentClient agent : agents.activeOwnedBy(ownerSub)) {
                agents.lock(agent.clientId());
                agents.suspend(agent.clientId(), ownerSub, clock.instant().truncatedTo(ChronoUnit.MILLIS), "Owner removed from the platform");
                suspended.add(agent);
            }
            if (!suspended.isEmpty()) {
                tx.raiseRevision();
            }
            return null;
        });
        suspended.forEach(agent -> audit.emit(AuditEvent.of("admin_change", requestId, componentId).sub(ownerSub).client(agent.clientId())
                .agentOwner(agent.ownerSub()).reason("agent_owner_purged").outcome("ok")));
        if (!suspended.isEmpty()) {
            written();
        }
    }

    private Outcome<Item> rejection(Risk maxRisk, List<String> groups) {
        if (groups.stream().anyMatch(AgentClient::groupNotAllowed)) {
            return Outcome.rejected("agent_group_not_allowed", "a group with the suffix -destructive, or mcp-platform-admin, cannot be granted to an agent");
        }
        if (maxRisk == Risk.DESTRUCTIVE) {
            return Outcome.rejected("max_risk_not_allowed", "no agent may call a DESTRUCTIVE tool");
        }
        return null;
    }

    private void auditRejected(String requestId, GatewayUser administrator, String clientId, String ownerSub, String reason) {
        audit.emit(AuditEvent.of("admin_change", requestId, componentId).userWithoutClient(administrator).client(clientId).agentOwner(ownerSub)
                .reason(reason).outcome("denied"));
    }

    private AuditEvent adminEvent(String requestId, GatewayUser administrator, AgentClient agent) {
        return AuditEvent.of("admin_change", requestId, componentId).userWithoutClient(administrator).client(agent.clientId())
                .agentOwner(agent.ownerSub());
    }

    private void written() {
        try {
            afterWrite.run();
        } catch (RuntimeException e) {
            log.warn("an agent change was stored but this instance could not read it back: {}", e.getClass().getName());
        }
    }

    private static Set<String> fieldNames(JsonNode body) {
        Set<String> names = new LinkedHashSet<>();
        body.propertyNames().forEach(names::add);
        return names;
    }

    /** A string of 1 to {@code max} characters without the characters CC-121 forbids: these values reach the audit events. */
    private static String text(JsonNode node, int max) {
        if (node == null || !node.isString()) {
            return null;
        }
        String value = node.asString();
        return value.isEmpty() || value.length() > max || TextHygiene.containsForbidden(value) ? null : value;
    }

    private static Optional<Risk> risk(JsonNode node) {
        if (!node.isString()) {
            return Optional.empty();
        }
        try {
            return Optional.of(Risk.valueOf(node.asString()));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    private static Optional<List<String>> groups(JsonNode node) {
        if (!node.isArray() || node.size() > 100) {
            return Optional.empty();
        }
        List<String> groups = new ArrayList<>();
        for (JsonNode element : node) {
            if (!element.isString() || element.asString().length() > 255 || !GROUP.matcher(element.asString()).matches()
                    || groups.contains(element.asString())) {
                return Optional.empty();
            }
            groups.add(element.asString());
        }
        return Optional.of(groups);
    }
}
