package pl.aiwcorpo.mcp.gateway.activity;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.jdbc.core.simple.JdbcClient;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** PostgreSQL table {@code activity_events} (Flyway V2). Every statement is parameterised and scoped to one {@code sub}. */
public class ActivityStore {

    /** First event of a call: where the call sits in the newest-first order. */
    public record CallHead(String callKey, Instant ts, String requestId) {
    }

    private final JdbcClient jdbc;
    private final JsonMapper json;

    public ActivityStore(JdbcClient jdbc, JsonMapper json) {
        this.jdbc = jdbc;
        this.json = json;
    }

    public void insert(String sub, String callKey, Instant ts, String requestId, Map<String, Object> event) {
        jdbc.sql("INSERT INTO activity_events (sub, call_key, ts, request_id, event) VALUES (?, ?, ?, ?, ?::jsonb)")
                .params(sub, callKey, Timestamp.from(ts), requestId, json.writeValueAsString(event)).update();
    }

    /**
     * The calls of {@code sub} newest first, strictly after the position ({@code beforeTs}, {@code beforeRequestId}) when
     * given, inside [from, to] and not older than {@code notBefore}.
     */
    public List<CallHead> heads(String sub, Instant notBefore, Instant from, Instant to, Instant beforeTs, String beforeRequestId,
                                int limit) {
        StringBuilder sql = new StringBuilder("SELECT call_key, ts, request_id FROM (SELECT DISTINCT ON (call_key) call_key, ts, "
                + "request_id FROM activity_events WHERE sub = ? AND ts >= ? ORDER BY call_key, ts, id) heads WHERE true");
        List<Object> params = new ArrayList<>(List.of(sub, Timestamp.from(notBefore)));
        if (from != null) {
            sql.append(" AND ts >= ?");
            params.add(Timestamp.from(from));
        }
        if (to != null) {
            sql.append(" AND ts <= ?");
            params.add(Timestamp.from(to));
        }
        if (beforeTs != null) {
            sql.append(" AND (ts, request_id) < (?, ?)");
            params.add(Timestamp.from(beforeTs));
            params.add(beforeRequestId);
        }
        sql.append(" ORDER BY ts DESC, request_id DESC LIMIT ?");
        params.add(limit);
        return jdbc.sql(sql.toString()).params(params)
                .query((rs, row) -> new CallHead(rs.getString("call_key"), rs.getTimestamp("ts").toInstant(), rs.getString("request_id")))
                .list();
    }

    /** The events of the given calls in the order they happened, grouped by call. */
    public Map<String, List<JsonNode>> events(String sub, List<String> callKeys) {
        Map<String, List<JsonNode>> byCall = new LinkedHashMap<>();
        jdbc.sql("SELECT call_key, event::text AS event FROM activity_events WHERE sub = ? AND call_key = ANY(?) ORDER BY ts, id")
                .params(sub, callKeys.toArray(new String[0]))
                .query((rs, row) -> {
                    byCall.computeIfAbsent(rs.getString("call_key"), k -> new ArrayList<>()).add(json.readTree(rs.getString("event")));
                    return null;
                }).list();
        return byCall;
    }

    /** The newest events of a user, newest first (GET /admin/v1/activity). */
    public List<JsonNode> recent(String sub, Instant notBefore, int limit) {
        return jdbc.sql("SELECT event::text AS event FROM activity_events WHERE sub = ? AND ts >= ? ORDER BY ts DESC, id DESC LIMIT ?")
                .params(sub, Timestamp.from(notBefore), limit).query((rs, row) -> json.readTree(rs.getString("event"))).list();
    }

    public int deleteOlderThan(Instant cutoff) {
        return jdbc.sql("DELETE FROM activity_events WHERE ts < ?").param(Timestamp.from(cutoff)).update();
    }
}
