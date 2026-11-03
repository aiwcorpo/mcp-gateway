package pl.aiwcorpo.mcp.gateway.killswitch;

import java.time.Instant;
import java.util.List;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import pl.aiwcorpo.mcp.gateway.registry.ChangeCounter;

/** Table {@code kill_switches} (CC-194): written with the change counter in one transaction, read as a whole. */
public class KillSwitchStore {

    /** {@code tool} is null for the switch of a whole server. */
    public record Entry(String serverId, String tool, String setBy, Instant setAt, String reason) {

        public String scope() {
            return tool == null ? "server" : "tool";
        }
    }

    private final JdbcClient jdbc;
    private final TransactionTemplate transactions;
    private final ChangeCounter changes;

    public KillSwitchStore(JdbcClient jdbc, PlatformTransactionManager transactionManager, ChangeCounter changes) {
        this.jdbc = jdbc;
        this.transactions = new TransactionTemplate(transactionManager);
        this.changes = changes;
    }

    /** Oldest first, as the list of the contract wants it. */
    public List<Entry> all() {
        return jdbc.sql("SELECT server_id, tool, set_by, set_at, reason FROM kill_switches ORDER BY set_at, server_id, tool")
                .query((rs, row) -> new Entry(rs.getString("server_id"), rs.getString("tool").isEmpty() ? null : rs.getString("tool"),
                        rs.getString("set_by"), rs.getTimestamp("set_at").toInstant(), rs.getString("reason")))
                .list();
    }

    /** A switch that is on stays on; only the reason (and who gave it) changes, the time of the first putting stays. */
    public void put(String serverId, String tool, String setBy, String reason) {
        transactions.executeWithoutResult(status -> {
            jdbc.sql("INSERT INTO kill_switches (server_id, tool, set_by, reason) VALUES (?, ?, ?, ?) "
                    + "ON CONFLICT (server_id, tool) DO UPDATE SET reason = EXCLUDED.reason").params(serverId, tool == null ? "" : tool, setBy, reason).update();
            changes.raise();
        });
    }

    public void delete(String serverId, String tool) {
        transactions.executeWithoutResult(status -> {
            jdbc.sql("DELETE FROM kill_switches WHERE server_id = ? AND tool = ?").params(serverId, tool == null ? "" : tool).update();
            changes.raise();
        });
    }
}
