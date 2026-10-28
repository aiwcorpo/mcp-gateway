package pl.aiwcorpo.mcp.gateway.registry;

import java.util.List;

import org.springframework.jdbc.core.simple.JdbcClient;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** PostgreSQL table {@code registry_servers} (Flyway V3). */
public class RegistryStore {

    public record Stored(String serverId, JsonNode manifest, String source) {
    }

    private final JdbcClient jdbc;
    private final JsonMapper json;

    public RegistryStore(JdbcClient jdbc, JsonMapper json) {
        this.jdbc = jdbc;
        this.json = json;
    }

    public void save(String serverId, JsonNode manifest, String source) {
        jdbc.sql("INSERT INTO registry_servers (server_id, manifest, source) VALUES (?, ?::jsonb, ?) "
                        + "ON CONFLICT (server_id) DO UPDATE SET manifest = EXCLUDED.manifest, source = EXCLUDED.source, registered_at = now()")
                .params(serverId, json.writeValueAsString(manifest), source).update();
    }

    public List<Stored> all() {
        return jdbc.sql("SELECT server_id, manifest::text AS manifest, source FROM registry_servers")
                .query((rs, row) -> new Stored(rs.getString("server_id"), json.readTree(rs.getString("manifest")), rs.getString("source")))
                .list();
    }
}
