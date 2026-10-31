package pl.aiwcorpo.mcp.gateway.activity;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

/** The calls of one user as rows (CC-095): one row per call, newest first, filtered after the aggregation. */
public final class ActivityService {

    /** Default retention of the activity table (CC-134); the deployment decides, this is not a constant of the contract. */
    public static final Duration DEFAULT_RETENTION = Duration.ofDays(30);
    private static final int BATCH = 100;
    private static final int MAX_BATCHES = 50;
    /** {@code denied_link_scope} is the result of 4.x rows; it is read as the {@code denied_filter_scope} that replaced it (CC-188). */
    private static final Set<String> DENIED = Set.of("denied_not_granted", "denied_filter_scope", "denied_link_scope", "denied_policy",
            "tool_disabled", "step_up_required", "rate_limited");
    private static final Set<String> FAILED = Set.of("error", "credential_required");

    /** What the caller asked for; the user is always the caller's own sub. */
    public record Query(String sub, int limit, Instant from, Instant to, String resultGroup, String q, ActivityCursor.Position after) {
    }

    public record Page(List<ObjectNode> rows, ActivityCursor.Position next) {
    }

    private final ActivityStore store;
    private final ActivityAggregator aggregator;
    private final Clock clock;
    private final Duration retention;

    public ActivityService(ActivityStore store, ActivityAggregator aggregator, Clock clock, Duration retention) {
        this.store = store;
        this.aggregator = aggregator;
        this.clock = clock;
        this.retention = retention;
    }

    public Page calls(Query query) {
        Instant now = clock.instant();
        Instant notBefore = now.minus(retention);
        List<ObjectNode> rows = new ArrayList<>();
        Instant afterTs = query.after() == null ? null : Instant.parse(query.after().ts());
        String afterRequestId = query.after() == null ? null : query.after().requestId();
        ActivityCursor.Position last = null;
        boolean more = false;
        for (int batch = 0; batch < MAX_BATCHES && !more; batch++) {
            List<ActivityStore.CallHead> heads = store.heads(query.sub(), notBefore, query.from(), query.to(), afterTs, afterRequestId, BATCH);
            if (heads.isEmpty()) {
                break;
            }
            Map<String, List<JsonNode>> events = store.events(query.sub(), heads.stream().map(ActivityStore.CallHead::callKey).toList());
            for (ActivityStore.CallHead head : heads) {
                ObjectNode row = aggregator.aggregate(events.getOrDefault(head.callKey(), List.of()), now.toEpochMilli());
                if (row == null || !matches(row, query)) {
                    continue;
                }
                if (rows.size() == query.limit()) {
                    more = true;
                    break;
                }
                rows.add(row);
                last = new ActivityCursor.Position(row.path("ts").asString(), row.path("requestId").asString());
            }
            ActivityStore.CallHead tail = heads.getLast();
            afterTs = tail.ts();
            afterRequestId = tail.requestId();
            if (heads.size() < BATCH) {
                break;
            }
        }
        return new Page(rows, more ? last : null);
    }

    private static boolean matches(ObjectNode row, Query query) {
        String result = row.path("result").asString();
        if (query.resultGroup() != null && !group(result).equals(query.resultGroup())) {
            return false;
        }
        if (query.q() != null) {
            String needle = query.q().toLowerCase(Locale.ROOT);
            return row.path("tool").asString().toLowerCase(Locale.ROOT).contains(needle)
                    || row.path("resource").path("id").asString("").toLowerCase(Locale.ROOT).contains(needle);
        }
        return true;
    }

    /** The filter groups of the API: ok, denied, error and everything that concerns a confirmation. */
    static String group(String result) {
        if ("ok".equals(result)) {
            return "ok";
        }
        if (DENIED.contains(result)) {
            return "denied";
        }
        if (FAILED.contains(result)) {
            return "error";
        }
        return "confirmation";
    }

    public List<JsonNode> recentEvents(String sub, int limit) {
        return store.recent(sub, clock.instant().minus(retention), limit);
    }
}
