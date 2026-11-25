package pl.aiwcorpo.mcp.gateway.agent;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.springframework.jdbc.core.simple.JdbcClient;

import pl.aiwcorpo.mcp.gateway.server.Risk;
import tools.jackson.databind.json.JsonMapper;

/**
 * Table {@code agent_clients}. The writing methods join the transaction of the caller (RegistryStore#policyLocked): an agent change raises
 * the counter of changes, and a suspension, a creation or a removal raises the revision of the policy data, in the transaction of the row.
 */
public class AgentStore {

    private static final String COLUMNS = "client_id, service_account_sub, owner_sub, max_risk, allowed_groups::text AS allowed_groups, "
            + "delegation_allowed, created_by, created_at, key_rotated_at, suspended_by, suspended_at, suspend_reason";

    private final JdbcClient jdbc;
    private final JsonMapper json;

    public AgentStore(JdbcClient jdbc, JsonMapper json) {
        this.jdbc = jdbc;
        this.json = json;
    }

    /** Ordered by {@code clientId}, as the list of the contract wants it. */
    public List<AgentClient> all() {
        return jdbc.sql("SELECT " + COLUMNS + " FROM agent_clients ORDER BY client_id").query(this::row).list();
    }

    public List<AgentClient> ownedBy(String ownerSub) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM agent_clients WHERE owner_sub = ? ORDER BY client_id").param(ownerSub).query(this::row).list();
    }

    public Optional<AgentClient> find(String clientId) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM agent_clients WHERE client_id = ?").param(clientId).query(this::row).optional();
    }

    /** The row, locked until the end of the transaction. */
    public Optional<AgentClient> lock(String clientId) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM agent_clients WHERE client_id = ? FOR UPDATE").param(clientId).query(this::row).optional();
    }

    public boolean serviceAccountTaken(String serviceAccountSub) {
        return jdbc.sql("SELECT count(*) FROM agent_clients WHERE service_account_sub = ?").param(serviceAccountSub).query(Long.class).single() > 0;
    }

    public void insert(AgentClient agent) {
        jdbc.sql("INSERT INTO agent_clients (client_id, service_account_sub, owner_sub, max_risk, allowed_groups, delegation_allowed, "
                        + "created_by, created_at) VALUES (?, ?, ?, ?, ?::jsonb, ?, ?, ?)")
                .params(agent.clientId(), agent.serviceAccountSub(), agent.ownerSub(), agent.maxRisk().name(),
                        json.writeValueAsString(agent.allowedGroups()), agent.delegationAllowed(), agent.createdBy(),
                        Timestamp.from(agent.createdAt())).update();
    }

    public void updateSettings(AgentClient agent) {
        jdbc.sql("UPDATE agent_clients SET owner_sub = ?, max_risk = ?, allowed_groups = ?::jsonb, delegation_allowed = ? WHERE client_id = ?")
                .params(agent.ownerSub(), agent.maxRisk().name(), json.writeValueAsString(agent.allowedGroups()), agent.delegationAllowed(),
                        agent.clientId()).update();
    }

    public void recordKeyRotation(String clientId, Instant at) {
        jdbc.sql("UPDATE agent_clients SET key_rotated_at = ? WHERE client_id = ?").params(Timestamp.from(at), clientId).update();
    }

    /** An agent that is suspended stays so: only the reason changes, who suspended it first and when stay (the audit has every putting). */
    public void suspend(String clientId, String by, Instant at, String reason) {
        jdbc.sql("UPDATE agent_clients SET suspended_by = COALESCE(suspended_by, ?), suspended_at = COALESCE(suspended_at, ?), suspend_reason = ? "
                + "WHERE client_id = ?").params(by, Timestamp.from(at), reason, clientId).update();
    }

    public void resume(String clientId) {
        jdbc.sql("UPDATE agent_clients SET suspended_by = NULL, suspended_at = NULL, suspend_reason = NULL WHERE client_id = ?")
                .param(clientId).update();
    }

    public boolean delete(String clientId) {
        return jdbc.sql("DELETE FROM agent_clients WHERE client_id = ?").param(clientId).update() > 0;
    }

    /** The agents of an owner who left, not yet suspended. */
    public List<AgentClient> activeOwnedBy(String ownerSub) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM agent_clients WHERE owner_sub = ? AND suspended_at IS NULL ORDER BY client_id")
                .param(ownerSub).query(this::row).list();
    }

    private AgentClient row(ResultSet rs, int index) throws SQLException {
        List<String> groups = new java.util.ArrayList<>();
        json.readTree(rs.getString("allowed_groups")).forEach(group -> groups.add(group.asString()));
        Timestamp suspendedAt = rs.getTimestamp("suspended_at");
        Timestamp rotated = rs.getTimestamp("key_rotated_at");
        return new AgentClient(rs.getString("client_id"), rs.getString("service_account_sub"), rs.getString("owner_sub"),
                Risk.valueOf(rs.getString("max_risk")), groups, rs.getBoolean("delegation_allowed"), rs.getString("created_by"),
                rs.getTimestamp("created_at").toInstant(), rotated == null ? null : rotated.toInstant(),
                suspendedAt == null ? null : new AgentClient.Suspension(rs.getString("suspended_by"), suspendedAt.toInstant(),
                        rs.getString("suspend_reason")));
    }
}
