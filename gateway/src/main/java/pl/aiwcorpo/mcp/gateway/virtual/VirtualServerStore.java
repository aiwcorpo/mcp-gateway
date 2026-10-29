package pl.aiwcorpo.mcp.gateway.virtual;

import java.sql.Timestamp;
import java.util.List;
import java.util.Optional;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;

/** PostgreSQL table {@code virtual_servers} (Flyway V1). Every statement is parameterised. */
public class VirtualServerStore {

    private static final TypeReference<List<String>> STRINGS = new TypeReference<>() {
    };

    private final JdbcClient jdbc;
    private final JsonMapper json;
    private final TransactionTemplate transactions;

    public VirtualServerStore(JdbcClient jdbc, JsonMapper json, PlatformTransactionManager transactionManager) {
        this.jdbc = jdbc;
        this.json = json;
        this.transactions = new TransactionTemplate(transactionManager);
    }

    public enum Inserted { CREATED, SLUG_TAKEN, LIMIT_REACHED }

    /**
     * Inserts the link unless the slug is taken (by anyone) or the owner already has {@code maxPerOwner} links.
     * The count and the insert run under a per-owner advisory lock, so concurrent requests cannot overshoot.
     */
    public Inserted insert(VirtualServer server, int maxPerOwner) {
        try {
            return transactions.execute(status -> {
                jdbc.sql("SELECT pg_advisory_xact_lock(hashtextextended(?, 0))").param(server.ownerSub()).query().singleRow();
                int rows = jdbc.sql("INSERT INTO virtual_servers (slug, owner_sub, display_name, tools) "
                                + "SELECT ?, ?, ?, ?::jsonb WHERE (SELECT count(*) FROM virtual_servers WHERE owner_sub = ?) < ?")
                        .params(server.slug(), server.ownerSub(), server.displayName(), json.writeValueAsString(server.tools()),
                                server.ownerSub(), maxPerOwner)
                        .update();
                return rows == 1 ? Inserted.CREATED : Inserted.LIMIT_REACHED;
            });
        } catch (DuplicateKeyException e) {
            return Inserted.SLUG_TAKEN;
        }
    }

    public Optional<VirtualServer> find(String slug) {
        return jdbc.sql("SELECT slug, owner_sub, display_name, tools::text AS tools, created_at FROM virtual_servers WHERE slug = ?")
                .param(slug).query((rs, row) -> map(rs.getString("slug"), rs.getString("owner_sub"),
                        rs.getString("display_name"), rs.getString("tools"), rs.getTimestamp("created_at")))
                .optional();
    }

    public List<VirtualServer> listByOwner(String ownerSub) {
        return jdbc.sql("SELECT slug, owner_sub, display_name, tools::text AS tools, created_at FROM virtual_servers "
                        + "WHERE owner_sub = ? ORDER BY created_at, slug")
                .param(ownerSub).query((rs, row) -> map(rs.getString("slug"), rs.getString("owner_sub"),
                        rs.getString("display_name"), rs.getString("tools"), rs.getTimestamp("created_at")))
                .list();
    }

    /** True when a link of this owner was removed; someone else's slug and a missing one look the same. */
    public boolean delete(String slug, String ownerSub) {
        return jdbc.sql("DELETE FROM virtual_servers WHERE slug = ? AND owner_sub = ?").params(slug, ownerSub).update() > 0;
    }

    /** Removes every link of the owner (offboarding) and returns their slugs; none is a normal answer. */
    public List<String> deleteAllOf(String ownerSub) {
        return jdbc.sql("DELETE FROM virtual_servers WHERE owner_sub = ? RETURNING slug").param(ownerSub)
                .query((rs, row) -> rs.getString("slug")).list();
    }

    private VirtualServer map(String slug, String owner, String name, String tools, Timestamp createdAt) {
        return new VirtualServer(slug, owner, name, json.readValue(tools, STRINGS), createdAt.toInstant());
    }
}
