package pl.aiwcorpo.mcp.gateway.registry;

import org.springframework.jdbc.core.simple.JdbcClient;

/**
 * The counter of changes of the registry and of the emergency switches (table {@code registry_changes}). A writer raises it in the
 * transaction of the change; every instance reads it on a timer and re-reads the data only when it moved, which is how a change made on
 * one instance reaches the others without a message channel that could lose it.
 */
public class ChangeCounter {

    private final JdbcClient jdbc;

    public ChangeCounter(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    public long read() {
        return jdbc.sql("SELECT version FROM registry_changes WHERE id = 1").query(Long.class).single();
    }

    /** Must run inside the transaction that makes the change, so that nobody sees the new version before the data. */
    public void raise() {
        jdbc.sql("UPDATE registry_changes SET version = version + 1 WHERE id = 1").update();
    }
}
