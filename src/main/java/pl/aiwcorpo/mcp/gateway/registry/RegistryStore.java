package pl.aiwcorpo.mcp.gateway.registry;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import pl.aiwcorpo.mcp.gateway.policy.PolicyDataStore;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * PostgreSQL tables {@code servers} (the settings of a server), {@code registry_servers} (the last accepted manifest of a server),
 * {@code registry_tools} (the approved and the pending definition of each tool), {@code registry_risk_floor} (the highest risk ever
 * approved per tool), {@code registry_policies} (the approved and the pending policies and resource types of a server) and
 * {@code registry_namespaces} (which server owns a Cedar namespace). Every change goes
 * through {@link #locked}: an advisory lock of the server for the whole transaction, so a registration, an approval and a report
 * of a live definition cannot interleave, on this instance or on another one.
 */
public class RegistryStore {

    public record StoredServer(String serverId, JsonNode manifest, String source) {
    }

    /**
     * The policy fragment and the resource type declarations of a server (the object {@code policies} and the array {@code resourceTypes}
     * of the manifest) as approved, and as they wait for an administrator; {@code policiesHash} covers both.
     */
    public record StoredPolicies(String approvedHash, JsonNode approvedPolicies, JsonNode approvedResourceTypes, String approvedVersion,
                                 String pendingHash, JsonNode pendingPolicies, JsonNode pendingResourceTypes, String pendingVersion,
                                 String pendingSource) {

        public static StoredPolicies none() {
            return new StoredPolicies(null, null, null, null, null, null, null, null, null);
        }

        public boolean approved() {
            return approvedHash != null;
        }

        public boolean pending() {
            return pendingHash != null;
        }
    }

    /** The state of one server inside a locked transaction. */
    public final class Tx {
        private final String serverId;
        private boolean wrote;

        private Tx(String serverId) {
            this.serverId = serverId;
        }

        public Optional<StoredServer> server() {
            return findServer(serverId);
        }

        public Optional<ServerConfig> config() {
            return RegistryStore.this.config(serverId);
        }

        public void saveConfig(ServerConfig config, boolean create) {
            wrote = true;
            String credential = json.writeValueAsString(credentialJson(config.credential()));
            if (create) {
                jdbc.sql("INSERT INTO servers (server_id, system, internal_url, credential, enabled, adapter, allow_plain_http, status, "
                                + "last_checked_at, last_error, connection, pending_connection) "
                                + "VALUES (?, ?, ?, ?::jsonb, ?, ?, ?, ?, ?, ?, ?::jsonb, ?::jsonb)")
                        .params(config.serverId(), config.system(), config.internalUrl().toString(), credential, config.enabled(),
                                config.adapter(), config.allowPlainHttp(), config.status(), timestamp(config.lastCheckedAt()),
                                config.lastError(), connectionText(config.connection()), pendingText(config.pendingConnection())).update();
            } else {
                // Only the credential and the switch change by hand: the address, the plain-http flag and the adapter mode are set when
                // the server is added, the rest is what the gateway saw (saveState).
                jdbc.sql("UPDATE servers SET credential = ?::jsonb, enabled = ?, updated_at = now() WHERE server_id = ?")
                        .params(credential, config.enabled(), config.serverId()).update();
            }
        }

        /** What a check or an approval found: the status, the connection and the connection that waits. Moves the change counter. */
        public void saveState(ServerConfig config) {
            wrote = true;
            jdbc.sql("UPDATE servers SET status = ?, last_checked_at = ?, last_error = ?, connection = ?::jsonb, "
                            + "pending_connection = ?::jsonb, updated_at = now() WHERE server_id = ?")
                    .params(config.status(), timestamp(config.lastCheckedAt()), config.lastError(), connectionText(config.connection()),
                            pendingText(config.pendingConnection()), config.serverId()).update();
        }

        /** The time of a check that found nothing new: the instances need not read the registry again for it. */
        public void touchChecked(java.time.Instant at) {
            jdbc.sql("UPDATE servers SET last_checked_at = ? WHERE server_id = ?").params(timestamp(at), serverId).update();
        }

        public StoredPolicies policies() {
            return policiesOf(serverId);
        }

        public void savePolicies(StoredPolicies policies) {
            wrote = true;
            jdbc.sql("INSERT INTO registry_policies (server_id, approved_hash, approved_policies, approved_resource_types, approved_version, "
                            + "pending_hash, pending_policies, pending_resource_types, pending_version, pending_source) "
                            + "VALUES (?, ?, ?::jsonb, ?::jsonb, ?, ?, ?::jsonb, ?::jsonb, ?, ?) "
                            + "ON CONFLICT (server_id) DO UPDATE SET approved_hash = EXCLUDED.approved_hash, "
                            + "approved_policies = EXCLUDED.approved_policies, approved_resource_types = EXCLUDED.approved_resource_types, "
                            + "approved_version = EXCLUDED.approved_version, pending_hash = EXCLUDED.pending_hash, "
                            + "pending_policies = EXCLUDED.pending_policies, pending_resource_types = EXCLUDED.pending_resource_types, "
                            + "pending_version = EXCLUDED.pending_version, pending_source = EXCLUDED.pending_source")
                    .params(serverId, policies.approvedHash(), text(policies.approvedPolicies()), text(policies.approvedResourceTypes()),
                            policies.approvedVersion(), policies.pendingHash(), text(policies.pendingPolicies()),
                            text(policies.pendingResourceTypes()), policies.pendingVersion(), policies.pendingSource()).update();
        }

        /** The server whose approved policies own the namespace, if any. */
        public Optional<String> namespaceOwner(String namespace) {
            return jdbc.sql("SELECT server_id FROM registry_namespaces WHERE namespace = ?").param(namespace).query(String.class).optional();
        }

        /** The serverId that owns the namespace after this call: this server when it was free or already its own. Only an approval claims. */
        public String claimNamespace(String namespace) {
            wrote = true;
            jdbc.sql("INSERT INTO registry_namespaces (namespace, server_id) VALUES (?, ?) ON CONFLICT (namespace) DO NOTHING")
                    .params(namespace, serverId).update();
            return jdbc.sql("SELECT server_id FROM registry_namespaces WHERE namespace = ?").param(namespace).query(String.class).single();
        }

        /** Namespaces this server owns. */
        public List<String> namespaces() {
            return jdbc.sql("SELECT namespace FROM registry_namespaces WHERE server_id = ? ORDER BY namespace").param(serverId)
                    .query(String.class).list();
        }

        /** An approval of policies that name one namespace frees the others the server held (it declared another one before). */
        public void releaseNamespacesExcept(String keep) {
            wrote = true;
            jdbc.sql("DELETE FROM registry_namespaces WHERE server_id = ? AND namespace <> ?").params(serverId, keep).update();
        }

        public long raiseRevision() {
            wrote = true;
            return policyData.raiseRevision();
        }

        /** The policy row, locked until the end of the transaction. */
        public PolicyDataStore.State lockPolicyState() {
            wrote = true;
            return policyData.lockState();
        }

        public void saveScopeMapping(JsonNode document) {
            wrote = true;
            policyData.saveScopeMapping(document);
        }

        public List<pl.aiwcorpo.mcp.gateway.policy.PolicyOverride> overridesOf() {
            return policyData.overrides().stream().filter(o -> o.target().equals(serverId)).toList();
        }

        public void deleteOverridesOf() {
            wrote = true;
            policyData.deleteOverridesOf(serverId);
        }

        /**
         * Everything the registry holds of the server, its settings last: no tool, approval, switch, policy or namespace stays. The risk floors
         * stay (CC-167): a server added again under the same id cannot bring back a lowered risk without an administrator accepting it.
         */
        public void deleteAll() {
            wrote = true;
            for (String table : List.of("registry_tools", "kill_switches", "registry_policies", "registry_namespaces", "registry_servers",
                    "servers")) {
                jdbc.sql("DELETE FROM " + table + " WHERE server_id = ?").param(serverId).update();
            }
        }

        /** Rows of the switches of the server, as (tool or empty), for the audit of its removal. */
        public List<String> killSwitchTools() {
            return jdbc.sql("SELECT tool FROM kill_switches WHERE server_id = ? ORDER BY tool").param(serverId).query(String.class).list();
        }

        /**
         * Before a server is added: what an earlier removal or a race left under its id is purged (tools, manifests, policies, namespaces and
         * switches; the risk floors stay). Rows of a build before this one are legacy: they are taken again, once.
         */
        public void purgeLeftovers() {
            wrote = true;
            boolean legacy = jdbc.sql("DELETE FROM registry_legacy WHERE server_id = ?").param(serverId).update() > 0;
            if (legacy) {
                return;
            }
            for (String table : List.of("registry_tools", "kill_switches", "registry_policies", "registry_namespaces", "registry_servers")) {
                jdbc.sql("DELETE FROM " + table + " WHERE server_id = ?").param(serverId).update();
            }
        }

        public Map<String, RegisteredTool> tools() {
            return RegistryStore.this.tools(serverId);
        }

        public Map<String, String> groupFloors() {
            return RegistryStore.this.groupFloors(serverId);
        }

        /** Sets the group floor of tools: a name with an empty group has none any more. */
        public void setGroupFloors(Map<String, String> groups) {
            wrote = true;
            groups.forEach((tool, group) -> {
                if (group.isEmpty()) {
                    jdbc.sql("DELETE FROM registry_group_floor WHERE server_id = ? AND tool = ?").params(serverId, tool).update();
                } else {
                    jdbc.sql("INSERT INTO registry_group_floor (server_id, tool, additional_group) VALUES (?, ?, ?) "
                            + "ON CONFLICT (server_id, tool) DO UPDATE SET additional_group = EXCLUDED.additional_group")
                            .params(serverId, tool, group).update();
                }
            });
        }

        public Map<String, Integer> floors() {
            return RegistryStore.this.floors(serverId);
        }

        public void saveServer(JsonNode manifest, String source) {
            wrote = true;
            jdbc.sql("INSERT INTO registry_servers (server_id, manifest, source) VALUES (?, ?::jsonb, ?) "
                            + "ON CONFLICT (server_id) DO UPDATE SET manifest = EXCLUDED.manifest, source = EXCLUDED.source, "
                            + "registered_at = now()")
                    .params(serverId, json.writeValueAsString(manifest), source).update();
        }

        public void saveTool(RegisteredTool tool) {
            wrote = true;
            RegisteredTool.Approved a = tool.approved();
            RegisteredTool.Pending p = tool.pending();
            jdbc.sql("INSERT INTO registry_tools (server_id, tool, approved_entry, approved_hash, approved_version, approved_credential, "
                            + "pending_entry, pending_hash, pending_version, pending_change, pending_source, pending_credential, pending_risk_lowered, "
                            + "classified_by, classified_at) "
                            + "VALUES (?, ?, ?::jsonb, ?, ?, ?::jsonb, ?::jsonb, ?, ?, ?, ?, ?::jsonb, ?, ?, ?) "
                            + "ON CONFLICT (server_id, tool) DO UPDATE SET approved_entry = EXCLUDED.approved_entry, "
                            + "approved_hash = EXCLUDED.approved_hash, approved_version = EXCLUDED.approved_version, "
                            + "approved_credential = EXCLUDED.approved_credential, pending_entry = EXCLUDED.pending_entry, "
                            + "pending_hash = EXCLUDED.pending_hash, pending_version = EXCLUDED.pending_version, "
                            + "pending_change = EXCLUDED.pending_change, pending_source = EXCLUDED.pending_source, "
                            + "pending_credential = EXCLUDED.pending_credential, pending_risk_lowered = EXCLUDED.pending_risk_lowered, "
                            + "classified_by = EXCLUDED.classified_by, classified_at = EXCLUDED.classified_at")
                    .params(serverId, tool.name(),
                            a == null ? null : json.writeValueAsString(a.entry()), a == null ? null : a.hash(),
                            a == null ? null : a.version(), a == null ? null : a.credentialJson(),
                            p == null ? null : json.writeValueAsString(p.entry()), p == null ? null : p.hash(),
                            p == null ? null : p.version(), p == null ? null : p.change(), p == null ? null : p.source(),
                            p == null ? null : p.credentialJson(), p != null && p.riskLowered(),
                            a == null ? null : a.classifiedBy(), a == null || a.classifiedAt() == null ? null : java.sql.Timestamp.from(a.classifiedAt()))
                    .update();
        }

        public void deleteTool(String name) {
            wrote = true;
            jdbc.sql("DELETE FROM registry_tools WHERE server_id = ? AND tool = ?").params(serverId, name).update();
        }

        /** Sets the floor of a tool to this risk, lower or not: only the approval of a lowering by an administrator does it (CC-167). */
        public void setFloor(String tool, int risk) {
            wrote = true;
            jdbc.sql("INSERT INTO registry_risk_floor (server_id, tool, risk) VALUES (?, ?, ?) "
                    + "ON CONFLICT (server_id, tool) DO UPDATE SET risk = EXCLUDED.risk").params(serverId, tool, risk).update();
        }

        /** Raises the floors to these risks (ordinals); a floor is never lowered here. */
        public void raiseFloors(Map<String, Integer> risks) {
            wrote = true;
            RegistryStore.this.raiseFloors(serverId, risks);
        }
    }

    private final JdbcClient jdbc;
    private final JsonMapper json;
    private final PlatformTransactionManager transactionManager;
    private final TransactionTemplate transactions;
    private final ChangeCounter changes;
    private final PolicyDataStore policyData;

    public RegistryStore(JdbcClient jdbc, JsonMapper json, PlatformTransactionManager transactionManager, ChangeCounter changes,
                         PolicyDataStore policyData) {
        this.jdbc = jdbc;
        this.json = json;
        this.transactionManager = transactionManager;
        this.transactions = new TransactionTemplate(transactionManager);
        this.changes = changes;
        this.policyData = policyData;
    }

    /** Policy data inside a transaction that holds the lock of the {@code policy_state} row (see {@link #policyLocked}). */
    public final class PolicyTx {
        private boolean wrote;

        public PolicyDataStore.State state() {
            return policyData.state();
        }

        public void saveScopeMapping(JsonNode document) {
            wrote = true;
            policyData.saveScopeMapping(document);
        }

        public List<pl.aiwcorpo.mcp.gateway.policy.PolicyOverride> overrides() {
            return policyData.overrides();
        }

        public Optional<pl.aiwcorpo.mcp.gateway.policy.PolicyOverride> override(String id) {
            return policyData.override(id);
        }

        public void saveOverride(pl.aiwcorpo.mcp.gateway.policy.PolicyOverride override) {
            wrote = true;
            policyData.saveOverride(override);
        }

        public boolean deleteOverride(String id) {
            boolean removed = policyData.deleteOverride(id);
            wrote |= removed;
            return removed;
        }

        /** Rows of servers: the registry as the data of this change sees it. */
        public Map<String, StoredPolicies> allPolicies() {
            return RegistryStore.this.allPolicies();
        }

        public List<ServerConfig> configs() {
            return RegistryStore.this.configs();
        }

        /** The new revision; every change of policy data raises it exactly once. */
        public long raiseRevision() {
            wrote = true;
            return policyData.raiseRevision();
        }
    }

    /**
     * Runs {@code work} with the {@code policy_state} row locked: writers of the scope mapping and of the overrides go one after another,
     * and when {@code work} wrote anything the change counter is raised in the same transaction.
     */
    public <T> T policyLocked(Function<PolicyTx, T> work) {
        return transactions.execute(status -> {
            policyData.lockState();
            PolicyTx tx = new PolicyTx();
            T result = work.apply(tx);
            if (tx.wrote) {
                changes.raise();
            }
            return result;
        });
    }

    /** Runs {@code work} under the lock of the server; when it wrote anything the change counter is raised in the same transaction. */
    public <T> T locked(String serverId, Function<Tx, T> work) {
        return transactions.execute(status -> {
            jdbc.sql("SELECT pg_advisory_xact_lock(hashtextextended(?, 1))").param("registry:" + serverId).query().singleRow();
            Tx tx = new Tx(serverId);
            T result = work.apply(tx);
            if (tx.wrote) {
                changes.raise();
            }
            return result;
        });
    }

    /**
     * Reads several tables as of one moment (REPEATABLE READ, read only): a writer raises the revision in the transaction of its change,
     * so what is read together belongs to one revision.
     */
    public <T> T consistentRead(java.util.function.Supplier<T> work) {
        TransactionTemplate read = new TransactionTemplate(transactionManager);
        read.setIsolationLevel(TransactionTemplate.ISOLATION_REPEATABLE_READ);
        read.setReadOnly(true);
        return read.execute(status -> work.get());
    }

    private static final String CONFIG_SELECT = "SELECT server_id, system, internal_url, credential::text AS credential, enabled, adapter, "
            + "allow_plain_http, status, last_checked_at, last_error, connection::text AS connection, "
            + "pending_connection::text AS pending_connection FROM servers";

    /** Every server of the registry, in serverId order. */
    public List<ServerConfig> configs() {
        return jdbc.sql(CONFIG_SELECT + " ORDER BY server_id").query(this::mapConfig).list();
    }

    public Optional<ServerConfig> config(String serverId) {
        return jdbc.sql(CONFIG_SELECT + " WHERE server_id = ?").param(serverId).query(this::mapConfig).optional();
    }

    public StoredPolicies policiesOf(String serverId) {
        return jdbc.sql(POLICIES_SELECT + " WHERE server_id = ?").param(serverId).query(this::policies).optional()
                .orElse(StoredPolicies.none());
    }

    /** The policies of every server that has a row. */
    public Map<String, StoredPolicies> allPolicies() {
        Map<String, StoredPolicies> all = new LinkedHashMap<>();
        jdbc.sql(POLICIES_SELECT + " ORDER BY server_id").query((rs, row) -> all.put(rs.getString("server_id"), policies(rs, row))).list();
        return all;
    }

    private static final String POLICIES_SELECT = "SELECT server_id, approved_hash, approved_policies::text AS approved_policies, "
            + "approved_resource_types::text AS approved_resource_types, approved_version, pending_hash, "
            + "pending_policies::text AS pending_policies, pending_resource_types::text AS pending_resource_types, pending_version, "
            + "pending_source FROM registry_policies";

    private StoredPolicies policies(ResultSet rs, int row) throws SQLException {
        return new StoredPolicies(rs.getString("approved_hash"), tree(rs.getString("approved_policies")),
                tree(rs.getString("approved_resource_types")), rs.getString("approved_version"), rs.getString("pending_hash"),
                tree(rs.getString("pending_policies")), tree(rs.getString("pending_resource_types")), rs.getString("pending_version"),
                rs.getString("pending_source"));
    }

    private JsonNode tree(String text) {
        return text == null ? null : json.readTree(text);
    }

    private String text(JsonNode node) {
        return node == null ? null : json.writeValueAsString(node);
    }

    private ServerConfig mapConfig(ResultSet rs, int row) throws SQLException {
        JsonNode credential = json.readTree(rs.getString("credential"));
        List<String> accepted = new java.util.ArrayList<>();
        credential.path("acceptedTypes").forEach(type -> accepted.add(type.asString()));
        java.sql.Timestamp checked = rs.getTimestamp("last_checked_at");
        return new ServerConfig(rs.getString("server_id"), rs.getString("system"), java.net.URI.create(rs.getString("internal_url")),
                new ServerConfig.Credential(credential.path("required").asBoolean(true), accepted,
                        credential.path("type").asString(null)), rs.getBoolean("enabled"), rs.getBoolean("adapter"),
                rs.getBoolean("allow_plain_http"), rs.getString("status"), checked == null ? null : checked.toInstant(),
                rs.getString("last_error"), connection(rs.getString("connection")), pending(rs.getString("pending_connection")));
    }

    private static java.sql.Timestamp timestamp(java.time.Instant at) {
        return at == null ? null : java.sql.Timestamp.from(at);
    }

    private String connectionText(ServerConfig.Connection connection) {
        if (connection == null) {
            return null;
        }
        ObjectNode node = json.createObjectNode();
        node.put("tlsMode", connection.tlsMode());
        certificateFields(node, connection.fingerprint(), connection.subject(), connection.issuer(), connection.sans(), connection.notAfter());
        node.put("approvedBy", connection.approvedBy());
        node.put("approvedAt", connection.approvedAt().toString());
        return json.writeValueAsString(node);
    }

    private String pendingText(ServerConfig.PendingConnection pending) {
        if (pending == null) {
            return null;
        }
        ObjectNode node = json.createObjectNode();
        node.put("tlsMode", pending.tlsMode());
        certificateFields(node, pending.fingerprint(), pending.subject(), pending.issuer(), pending.sans(), pending.notAfter());
        node.put("validatesAsCa", pending.validatesAsCa());
        node.put("reason", pending.reason());
        node.put("detectedAt", pending.detectedAt().toString());
        return json.writeValueAsString(node);
    }

    private static void certificateFields(ObjectNode node, String fingerprint, String subject, String issuer, List<String> sans,
                                          java.time.Instant notAfter) {
        node.put("fingerprint", fingerprint);
        node.put("subject", subject);
        node.put("issuer", issuer);
        tools.jackson.databind.node.ArrayNode names = node.putArray("sans");
        sans.forEach(names::add);
        node.put("notAfter", notAfter == null ? null : notAfter.toString());
    }

    private ServerConfig.Connection connection(String text) {
        if (text == null) {
            return null;
        }
        JsonNode node = json.readTree(text);
        return new ServerConfig.Connection(node.path("tlsMode").asString(), node.path("fingerprint").asString(null),
                node.path("subject").asString(null), node.path("issuer").asString(null), sansOf(node), instant(node.path("notAfter")),
                node.path("approvedBy").asString(null), instant(node.path("approvedAt")));
    }

    private ServerConfig.PendingConnection pending(String text) {
        if (text == null) {
            return null;
        }
        JsonNode node = json.readTree(text);
        return new ServerConfig.PendingConnection(node.path("tlsMode").asString(), node.path("fingerprint").asString(null),
                node.path("subject").asString(null), node.path("issuer").asString(null), sansOf(node), instant(node.path("notAfter")),
                node.path("validatesAsCa").asBoolean(false), node.path("reason").asString(), instant(node.path("detectedAt")));
    }

    private static List<String> sansOf(JsonNode node) {
        List<String> sans = new java.util.ArrayList<>();
        node.path("sans").forEach(san -> sans.add(san.asString()));
        return sans;
    }

    private static java.time.Instant instant(JsonNode node) {
        return node.isString() ? java.time.Instant.parse(node.asString()) : null;
    }

    private ObjectNode credentialJson(ServerConfig.Credential credential) {
        ObjectNode node = json.createObjectNode();
        node.put("required", credential.required());
        credential.acceptedTypes().forEach(node.putArray("acceptedTypes")::add);
        node.put("type", credential.type());
        return node;
    }

    public Optional<StoredServer> findServer(String serverId) {
        return jdbc.sql("SELECT server_id, manifest::text AS manifest, source FROM registry_servers WHERE server_id = ?")
                .param(serverId).query(this::server).optional();
    }

    public List<StoredServer> servers() {
        return jdbc.sql("SELECT server_id, manifest::text AS manifest, source FROM registry_servers ORDER BY server_id")
                .query(this::server).list();
    }

    public Map<String, RegisteredTool> tools(String serverId) {
        Map<String, RegisteredTool> tools = new LinkedHashMap<>();
        jdbc.sql("SELECT tool, approved_entry::text AS approved_entry, approved_hash, approved_version, "
                        + "approved_credential::text AS approved_credential, pending_entry::text AS pending_entry, pending_hash, "
                        + "pending_version, pending_change, pending_source, pending_credential::text AS pending_credential, "
                        + "pending_risk_lowered, classified_by, classified_at FROM registry_tools WHERE server_id = ? ORDER BY tool")
                .param(serverId).query((rs, row) -> tools.put(rs.getString("tool"), tool(rs))).list();
        return tools;
    }

    /** Raises the floors to the risks of a manifest that is already stored (also one that is no longer acceptable). */
    public void raiseFloors(String serverId, Map<String, Integer> risks) {
        risks.forEach((tool, risk) -> jdbc.sql("INSERT INTO registry_risk_floor (server_id, tool, risk) VALUES (?, ?, ?) "
                + "ON CONFLICT (server_id, tool) DO UPDATE SET risk = GREATEST(registry_risk_floor.risk, EXCLUDED.risk)")
                .params(serverId, tool, risk).update());
    }

    /** The additionalGroup each tool of the server last had approved; it outlives the tool and the server, like the risk floors. */
    public Map<String, String> groupFloors(String serverId) {
        Map<String, String> floors = new HashMap<>();
        jdbc.sql("SELECT tool, additional_group FROM registry_group_floor WHERE server_id = ?").param(serverId)
                .query((rs, row) -> floors.put(rs.getString("tool"), rs.getString("additional_group"))).list();
        return floors;
    }

    public Map<String, Integer> floors(String serverId) {
        Map<String, Integer> floors = new HashMap<>();
        jdbc.sql("SELECT tool, risk FROM registry_risk_floor WHERE server_id = ?").param(serverId)
                .query((rs, row) -> floors.put(rs.getString("tool"), (int) rs.getShort("risk"))).list();
        return floors;
    }

    private StoredServer server(ResultSet rs, int row) throws SQLException {
        return new StoredServer(rs.getString("server_id"), json.readTree(rs.getString("manifest")), rs.getString("source"));
    }

    private RegisteredTool tool(ResultSet rs) throws SQLException {
        RegisteredTool.Approved approved = rs.getString("approved_entry") == null ? null
                : new RegisteredTool.Approved(json.readTree(rs.getString("approved_entry")), rs.getString("approved_hash"),
                        rs.getString("approved_version"), rs.getString("approved_credential"), rs.getString("classified_by"),
                        rs.getTimestamp("classified_at") == null ? null : rs.getTimestamp("classified_at").toInstant());
        RegisteredTool.Pending pending = rs.getString("pending_entry") == null ? null
                : new RegisteredTool.Pending(json.readTree(rs.getString("pending_entry")), rs.getString("pending_hash"),
                        rs.getString("pending_version"), rs.getString("pending_change"), rs.getString("pending_source"),
                        rs.getString("pending_credential"), rs.getBoolean("pending_risk_lowered"));
        return new RegisteredTool(rs.getString("tool"), approved, pending);
    }
}
