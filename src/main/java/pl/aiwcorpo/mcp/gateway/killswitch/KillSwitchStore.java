package pl.aiwcorpo.mcp.gateway.killswitch;

import java.time.Instant;
import java.util.List;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import pl.aiwcorpo.mcp.gateway.registry.ChangeCounter;

/**
 * Tables {@code kill_switches} (server and tool, CC-194) and {@code kill_switches_primitive} (resource and prompt, CC-265): written with the
 * change counter in one transaction, read as a whole.
 */
public class KillSwitchStore {

    /**
     * The fields are those of {@code KillSwitch} in the contract: at most one of {@code tool}, {@code resource} and {@code prompt} is set,
     * and none for the switch of a whole server.
     */
    public record Entry(String serverId, String tool, String setBy, Instant setAt, String reason, String resource, String prompt) {

        public Entry(String serverId, String tool, String setBy, Instant setAt, String reason) {
            this(serverId, tool, setBy, setAt, reason, null, null);
        }

        public String scope() {
            return resource != null ? "resource" : prompt != null ? "prompt" : tool == null ? "server" : "tool";
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
        List<Entry> all = new java.util.ArrayList<>(jdbc.sql("SELECT server_id, tool, set_by, set_at, reason FROM kill_switches "
                        + "ORDER BY set_at, server_id, tool")
                .query((rs, row) -> new Entry(rs.getString("server_id"), rs.getString("tool").isEmpty() ? null : rs.getString("tool"),
                        rs.getString("set_by"), rs.getTimestamp("set_at").toInstant(), rs.getString("reason")))
                .list());
        all.addAll(jdbc.sql("SELECT server_id, kind, name, set_by, set_at, reason FROM kill_switches_primitive ORDER BY set_at, server_id, name")
                .query((rs, row) -> new Entry(rs.getString("server_id"), null, rs.getString("set_by"), rs.getTimestamp("set_at").toInstant(),
                        rs.getString("reason"), "resource".equals(rs.getString("kind")) ? rs.getString("name") : null,
                        "prompt".equals(rs.getString("kind")) ? rs.getString("name") : null))
                .list());
        all.sort(java.util.Comparator.comparing(Entry::setAt).thenComparing(Entry::serverId)
                .thenComparing(e -> e.tool() != null ? e.tool() : e.resource() != null ? e.resource() : e.prompt() != null ? e.prompt() : ""));
        return all;
    }

    /** A switch that is on stays on; only the reason changes, who put it first and when stay (the audit event has the actor of every putting). */
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

    /** The switch of a resource or a template ({@code kind} resource) or of a prompt; same rule as {@link #put}. */
    public void putNamed(String serverId, String kind, String name, String setBy, String reason) {
        transactions.executeWithoutResult(status -> {
            jdbc.sql("INSERT INTO kill_switches_primitive (server_id, kind, name, set_by, reason) VALUES (?, ?, ?, ?, ?) "
                    + "ON CONFLICT (server_id, kind, name) DO UPDATE SET reason = EXCLUDED.reason").params(serverId, kind, name, setBy, reason).update();
            changes.raise();
        });
    }

    public void deleteNamed(String serverId, String kind, String name) {
        transactions.executeWithoutResult(status -> {
            jdbc.sql("DELETE FROM kill_switches_primitive WHERE server_id = ? AND kind = ? AND name = ?").params(serverId, kind, name).update();
            changes.raise();
        });
    }
}
