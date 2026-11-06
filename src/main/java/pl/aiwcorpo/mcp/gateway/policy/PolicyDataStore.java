package pl.aiwcorpo.mcp.gateway.policy;

import java.sql.Timestamp;
import java.util.List;
import java.util.Optional;

import org.springframework.jdbc.core.simple.JdbcClient;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Tables {@code policy_state} (the revision, the scope mapping document and the allowed clients) and {@code policy_overrides}. The
 * methods take part in the transaction of the caller: a writer raises the revision and the change counter in the same transaction as the
 * data, so that no instance sees the new revision before the data (RegistryStore#locked, PolicyAdmin).
 */
public class PolicyDataStore {

    /** The one row of {@code policy_state}. */
    public record State(long revision, JsonNode scopeMapping, String allowedClients) {
    }

    private final JdbcClient jdbc;
    private final JsonMapper json;

    public PolicyDataStore(JdbcClient jdbc, JsonMapper json) {
        this.jdbc = jdbc;
        this.json = json;
    }

    public State state() {
        return read("SELECT revision, scope_mapping::text AS scope_mapping, allowed_clients FROM policy_state WHERE id = 1");
    }

    /** The row, locked until the end of the transaction: writers of policy data go one after another. */
    public State lockState() {
        return read("SELECT revision, scope_mapping::text AS scope_mapping, allowed_clients FROM policy_state WHERE id = 1 FOR UPDATE");
    }

    private State read(String sql) {
        return jdbc.sql(sql).query((rs, row) -> new State(rs.getLong("revision"), json.readTree(rs.getString("scope_mapping")),
                rs.getString("allowed_clients"))).single();
    }

    /**
     * Raises the revision to the larger of the next one and the clock in milliseconds (CC-240): it never falls, and a store that was
     * restored from an older copy still hands out revisions that every server takes as new. The caller holds the row lock.
     */
    public long raiseRevision() {
        return jdbc.sql("UPDATE policy_state SET revision = GREATEST(revision + 1, ?) WHERE id = 1 RETURNING revision")
                .param(System.currentTimeMillis()).query(Long.class).single();
    }

    public void saveScopeMapping(JsonNode document) {
        jdbc.sql("UPDATE policy_state SET scope_mapping = ?::jsonb WHERE id = 1").param(json.writeValueAsString(document)).update();
    }

    public void saveAllowedClients(String clients) {
        jdbc.sql("UPDATE policy_state SET allowed_clients = ? WHERE id = 1").param(clients).update();
    }

    public List<PolicyOverride> overrides() {
        return jdbc.sql("SELECT id, target, text, set_by, set_at FROM policy_overrides ORDER BY id").query(PolicyDataStore::override).list();
    }

    public Optional<PolicyOverride> override(String id) {
        return jdbc.sql("SELECT id, target, text, set_by, set_at FROM policy_overrides WHERE id = ?").param(id)
                .query(PolicyDataStore::override).optional();
    }

    public void saveOverride(PolicyOverride override) {
        jdbc.sql("INSERT INTO policy_overrides (id, target, text, set_by, set_at) VALUES (?, ?, ?, ?, ?) "
                        + "ON CONFLICT (id) DO UPDATE SET target = EXCLUDED.target, text = EXCLUDED.text, set_by = EXCLUDED.set_by, "
                        + "set_at = EXCLUDED.set_at")
                .params(override.id(), override.target(), override.text(), override.setBy(), Timestamp.from(override.setAt())).update();
    }

    public boolean deleteOverride(String id) {
        return jdbc.sql("DELETE FROM policy_overrides WHERE id = ?").param(id).update() > 0;
    }

    /** Overrides that name the server as their target: they go with it. */
    public int deleteOverridesOf(String serverId) {
        return jdbc.sql("DELETE FROM policy_overrides WHERE target = ?").param(serverId).update();
    }

    private static PolicyOverride override(java.sql.ResultSet rs, int row) throws java.sql.SQLException {
        return new PolicyOverride(rs.getString("id"), rs.getString("target"), rs.getString("text"), rs.getString("set_by"),
                rs.getTimestamp("set_at").toInstant().truncatedTo(java.time.temporal.ChronoUnit.MILLIS));
    }
}
