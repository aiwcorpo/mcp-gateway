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

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * PostgreSQL tables {@code registry_servers} (the last accepted manifest of a server), {@code registry_tools} (the approved and the
 * pending definition of each tool) and {@code registry_risk_floor} (the highest risk ever approved per tool). Every change goes
 * through {@link #locked}: an advisory lock of the server for the whole transaction, so a registration, an approval and a report
 * of a live definition cannot interleave, on this instance or on another one.
 */
public class RegistryStore {

    public record StoredServer(String serverId, JsonNode manifest, String source) {
    }

    /** The state of one server inside a locked transaction. */
    public final class Tx {
        private final String serverId;

        private Tx(String serverId) {
            this.serverId = serverId;
        }

        public Optional<StoredServer> server() {
            return findServer(serverId);
        }

        public Map<String, RegisteredTool> tools() {
            return RegistryStore.this.tools(serverId);
        }

        public Map<String, Integer> floors() {
            return RegistryStore.this.floors(serverId);
        }

        public void saveServer(JsonNode manifest, String source) {
            jdbc.sql("INSERT INTO registry_servers (server_id, manifest, source) VALUES (?, ?::jsonb, ?) "
                            + "ON CONFLICT (server_id) DO UPDATE SET manifest = EXCLUDED.manifest, source = EXCLUDED.source, "
                            + "registered_at = now()")
                    .params(serverId, json.writeValueAsString(manifest), source).update();
        }

        public void saveTool(RegisteredTool tool) {
            RegisteredTool.Approved a = tool.approved();
            RegisteredTool.Pending p = tool.pending();
            jdbc.sql("INSERT INTO registry_tools (server_id, tool, approved_entry, approved_hash, approved_version, approved_credential, "
                            + "pending_entry, pending_hash, pending_version, pending_change, pending_source, pending_credential, pending_risk_lowered) "
                            + "VALUES (?, ?, ?::jsonb, ?, ?, ?::jsonb, ?::jsonb, ?, ?, ?, ?, ?::jsonb, ?) "
                            + "ON CONFLICT (server_id, tool) DO UPDATE SET approved_entry = EXCLUDED.approved_entry, "
                            + "approved_hash = EXCLUDED.approved_hash, approved_version = EXCLUDED.approved_version, "
                            + "approved_credential = EXCLUDED.approved_credential, pending_entry = EXCLUDED.pending_entry, "
                            + "pending_hash = EXCLUDED.pending_hash, pending_version = EXCLUDED.pending_version, "
                            + "pending_change = EXCLUDED.pending_change, pending_source = EXCLUDED.pending_source, "
                            + "pending_credential = EXCLUDED.pending_credential, pending_risk_lowered = EXCLUDED.pending_risk_lowered")
                    .params(serverId, tool.name(),
                            a == null ? null : json.writeValueAsString(a.entry()), a == null ? null : a.hash(),
                            a == null ? null : a.version(), a == null ? null : a.credentialJson(),
                            p == null ? null : json.writeValueAsString(p.entry()), p == null ? null : p.hash(),
                            p == null ? null : p.version(), p == null ? null : p.change(), p == null ? null : p.source(),
                            p == null ? null : p.credentialJson(), p != null && p.riskLowered())
                    .update();
        }

        public void deleteTool(String name) {
            jdbc.sql("DELETE FROM registry_tools WHERE server_id = ? AND tool = ?").params(serverId, name).update();
        }

        /** Sets the floor of a tool to this risk, lower or not: only the approval of a lowering by an administrator does it (CC-167). */
        public void setFloor(String tool, int risk) {
            jdbc.sql("INSERT INTO registry_risk_floor (server_id, tool, risk) VALUES (?, ?, ?) "
                    + "ON CONFLICT (server_id, tool) DO UPDATE SET risk = EXCLUDED.risk").params(serverId, tool, risk).update();
        }

        /** Raises the floors to these risks (ordinals); a floor is never lowered here. */
        public void raiseFloors(Map<String, Integer> risks) {
            RegistryStore.this.raiseFloors(serverId, risks);
        }
    }

    private final JdbcClient jdbc;
    private final JsonMapper json;
    private final TransactionTemplate transactions;

    public RegistryStore(JdbcClient jdbc, JsonMapper json, PlatformTransactionManager transactionManager) {
        this.jdbc = jdbc;
        this.json = json;
        this.transactions = new TransactionTemplate(transactionManager);
    }

    public <T> T locked(String serverId, Function<Tx, T> work) {
        return transactions.execute(status -> {
            jdbc.sql("SELECT pg_advisory_xact_lock(hashtextextended(?, 1))").param("registry:" + serverId).query().singleRow();
            return work.apply(new Tx(serverId));
        });
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
                        + "pending_risk_lowered FROM registry_tools WHERE server_id = ? ORDER BY tool")
                .param(serverId).query((rs, row) -> tools.put(rs.getString("tool"), tool(rs))).list();
        return tools;
    }

    /** Raises the floors to the risks of a manifest that is already stored (also one that is no longer acceptable). */
    public void raiseFloors(String serverId, Map<String, Integer> risks) {
        risks.forEach((tool, risk) -> jdbc.sql("INSERT INTO registry_risk_floor (server_id, tool, risk) VALUES (?, ?, ?) "
                + "ON CONFLICT (server_id, tool) DO UPDATE SET risk = GREATEST(registry_risk_floor.risk, EXCLUDED.risk)")
                .params(serverId, tool, risk).update());
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
                        rs.getString("approved_version"), rs.getString("approved_credential"));
        RegisteredTool.Pending pending = rs.getString("pending_entry") == null ? null
                : new RegisteredTool.Pending(json.readTree(rs.getString("pending_entry")), rs.getString("pending_hash"),
                        rs.getString("pending_version"), rs.getString("pending_change"), rs.getString("pending_source"),
                        rs.getString("pending_credential"), rs.getBoolean("pending_risk_lowered"));
        return new RegisteredTool(rs.getString("tool"), approved, pending);
    }
}
