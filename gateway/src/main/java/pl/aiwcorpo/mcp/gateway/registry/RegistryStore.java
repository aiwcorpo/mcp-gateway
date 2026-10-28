package pl.aiwcorpo.mcp.gateway.registry;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * PostgreSQL tables {@code registry_servers} (the approved manifest of a server) and {@code registry_risk_floor} (the highest
 * risk ever approved per tool). A write takes an advisory lock of the server for the whole transaction, so the checks against
 * the stored manifest and the floors and the write itself cannot interleave with another registration, on this instance or on
 * another one.
 */
public class RegistryStore {

    public record Stored(String serverId, JsonNode manifest, String source) {
    }

    public sealed interface Written {
        record Done(Stored stored) implements Written {
        }

        /** A risk below what was approved before (or below the configured minimum): nothing was written. */
        record Lowered(List<String> tools) implements Written {
        }

        /** Insert-only write found an approval that is already there: nothing was written. */
        record AlreadyThere(Stored existing) implements Written {
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

    /**
     * @param risks risk ordinal (0 READ_ONLY, 1 UPDATE, 2 DESTRUCTIVE) of every tool of the new manifest
     * @param configuredMinimum risk ordinal per tool that the gateway configuration names; the manifest may not go below
     * @param insertOnly the bootstrap: write only when the server has no row at all, never replace an approval
     */
    public Written write(String serverId, JsonNode manifest, String source, Map<String, Integer> risks,
                         Map<String, Integer> configuredMinimum, boolean insertOnly) {
        return transactions.execute(status -> {
            jdbc.sql("SELECT pg_advisory_xact_lock(hashtextextended(?, 1))").param("registry:" + serverId).query().singleRow();
            Optional<Stored> existing = find(serverId);
            if (insertOnly && existing.isPresent()) {
                return new Written.AlreadyThere(existing.get());
            }
            Map<String, Integer> floors = floors(serverId);
            List<String> lowered = risks.entrySet().stream()
                    .filter(e -> e.getValue() < Math.max(floors.getOrDefault(e.getKey(), 0), configuredMinimum.getOrDefault(e.getKey(), 0)))
                    .map(Map.Entry::getKey).sorted().toList();
            if (!lowered.isEmpty()) {
                return new Written.Lowered(lowered);
            }
            jdbc.sql("INSERT INTO registry_servers (server_id, manifest, source) VALUES (?, ?::jsonb, ?) "
                            + "ON CONFLICT (server_id) DO UPDATE SET manifest = EXCLUDED.manifest, source = EXCLUDED.source, "
                            + "registered_at = now()")
                    .params(serverId, json.writeValueAsString(manifest), source).update();
            raiseFloors(serverId, risks);
            return new Written.Done(new Stored(serverId, manifest, source));
        });
    }

    /** Raises the floors to the risks of a manifest that is already stored (also one that is no longer acceptable). */
    public void raiseFloors(String serverId, Map<String, Integer> risks) {
        risks.forEach((tool, risk) -> jdbc.sql("INSERT INTO registry_risk_floor (server_id, tool, risk) VALUES (?, ?, ?) "
                + "ON CONFLICT (server_id, tool) DO UPDATE SET risk = GREATEST(registry_risk_floor.risk, EXCLUDED.risk)")
                .params(serverId, tool, risk).update());
    }

    public Optional<Stored> find(String serverId) {
        return jdbc.sql("SELECT server_id, manifest::text AS manifest, source FROM registry_servers WHERE server_id = ?")
                .param(serverId).query(this::map).optional();
    }

    public List<Stored> all() {
        return jdbc.sql("SELECT server_id, manifest::text AS manifest, source FROM registry_servers").query(this::map).list();
    }

    public Map<String, Integer> floors(String serverId) {
        Map<String, Integer> floors = new HashMap<>();
        jdbc.sql("SELECT tool, risk FROM registry_risk_floor WHERE server_id = ?").param(serverId)
                .query((rs, row) -> floors.put(rs.getString("tool"), (int) rs.getShort("risk"))).list();
        return floors;
    }

    private Stored map(java.sql.ResultSet rs, int row) throws java.sql.SQLException {
        return new Stored(rs.getString("server_id"), json.readTree(rs.getString("manifest")), rs.getString("source"));
    }
}
