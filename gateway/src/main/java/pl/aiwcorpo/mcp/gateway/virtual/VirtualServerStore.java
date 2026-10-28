package pl.aiwcorpo.mcp.gateway.virtual;

import java.sql.Timestamp;
import java.util.List;
import java.util.Optional;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.simple.JdbcClient;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;

/** PostgreSQL table {@code virtual_servers} (Flyway V1). Every statement is parameterised. */
public class VirtualServerStore {

    private static final TypeReference<List<String>> STRINGS = new TypeReference<>() {
    };

    private final JdbcClient jdbc;
    private final JsonMapper json;

    public VirtualServerStore(JdbcClient jdbc, JsonMapper json) {
        this.jdbc = jdbc;
        this.json = json;
    }

    /** False when the slug is taken (by anyone). */
    public boolean insert(VirtualServer server) {
        try {
            jdbc.sql("INSERT INTO virtual_servers (slug, owner_sub, display_name, tools) VALUES (?, ?, ?, ?::jsonb)")
                    .params(server.slug(), server.ownerSub(), server.displayName(), json.writeValueAsString(server.tools()))
                    .update();
            return true;
        } catch (DuplicateKeyException e) {
            return false;
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

    private VirtualServer map(String slug, String owner, String name, String tools, Timestamp createdAt) {
        return new VirtualServer(slug, owner, name, json.readValue(tools, STRINGS), createdAt.toInstant());
    }
}
