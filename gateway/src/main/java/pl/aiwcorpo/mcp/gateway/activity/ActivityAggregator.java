package pl.aiwcorpo.mcp.gateway.activity;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * The audit events of one call (the first request and its retries with a code) as one {@code ActivityCall} row (CC-095;
 * the Java form of {@code scripts/lib/activity-calls.mjs} of mcp-contracts, whose vectors it passes). The result comes from
 * the reason of the last event, never from its errorCode. The gateway writes no event when the 120 s run out, so a call that
 * waits for a code is {@code expired} once {@code now} is past its TTL.
 *
 * <p>Two additions to the reference, both outside what the vectors cover: a denied call leaves a {@code policy_decision}
 * and a {@code tool_call} that both say "denied", and the first one decides; a {@code tool_call} that failed before the
 * system was reached carries its reason ({@code credential_required}, {@code rate_limited}), which names the result.
 */
public final class ActivityAggregator {

    public static final long TTL_MILLIS = 120_000;
    private static final Set<String> TERMINAL = Set.of("user_confirmed", "user_confirmed_no_preview", "attempts_exhausted",
            "superseded", "pending_exists", "confirmation_expired", "cancelled_by_owner");
    private static final Set<String> WAITING_REASONS = Set.of("code_burned", "authenticator_disabled", "authenticator_not_registered",
            "upstream_unavailable");
    private static final Map<String, String> DENIED_RESULTS = Map.ofEntries(
            Map.entry("not_granted", "denied_not_granted"), Map.entry("link_scope", "denied_link_scope"),
            Map.entry("policy_forbid", "denied_policy"), Map.entry("tool_disabled", "tool_disabled"),
            Map.entry("definition_changed", "tool_disabled"), Map.entry("tool_not_served", "tool_disabled"),
            Map.entry("credential_required", "credential_required"), Map.entry("rate_limited", "rate_limited"),
            Map.entry("rate_limited_user", "rate_limited"), Map.entry("rate_limited_client", "rate_limited"),
            Map.entry("rate_limited_tool", "rate_limited"), Map.entry("step_up_required", "step_up_required"),
            Map.entry("exchange_denied", "denied_not_granted"));
    private static final Map<String, String> CONFIRMATION_RESULTS = Map.of("superseded", "superseded",
            "attempts_exhausted", "confirmation_failed", "pending_exists", "blocked_by_pending", "cancelled_by_owner", "cancelled");

    private final JsonMapper json;

    public ActivityAggregator(JsonMapper json) {
        this.json = json;
    }

    /** Null when the call has no tool to show (a call to a tool the gateway does not know). */
    public ObjectNode aggregate(List<JsonNode> allEvents, long nowMillis) {
        List<JsonNode> all = dropDuplicateDenial(allEvents);
        if (all.isEmpty()) {
            return null;
        }
        int cut = -1;
        for (int i = 0; i < all.size(); i++) {
            JsonNode e = all.get(i);
            if ("confirmation".equals(e.path("event").asString()) && TERMINAL.contains(e.path("reason").asString(""))) {
                cut = i;
                break;
            }
        }
        List<JsonNode> events = cut < 0 ? all : all.subList(0, cut + 1);
        if (cut >= 0 && Set.of("user_confirmed", "user_confirmed_no_preview").contains(all.get(cut).path("reason").asString(""))) {
            for (int i = cut + 1; i < all.size(); i++) {
                if ("tool_call".equals(all.get(i).path("event").asString())) {
                    events = all.subList(0, i + 1);
                    break;
                }
            }
        }
        JsonNode first = events.getFirst();
        ObjectNode row = json.createObjectNode();
        row.put("requestId", first.path("requestId").asString());
        row.put("ts", first.path("ts").asString());
        copy(first, row, "client");
        copy(first, row, "virtualServer");
        Optional<JsonNode> withTool = events.stream().filter(e -> e.has("tool") && e.has("server")).findFirst();
        if (withTool.isEmpty()) {
            return null;
        }
        row.put("tool", withTool.get().path("server").asString().replaceFirst("^mcp-", "") + "__" + withTool.get().path("tool").asString());
        events.stream().filter(e -> e.has("risk")).findFirst().ifPresent(e -> row.put("risk", e.path("risk").asString()));
        events.stream().filter(e -> e.has("resource")).findFirst().ifPresent(e -> row.set("resource", e.get("resource")));

        List<JsonNode> confirmations = events.stream().filter(e -> "confirmation".equals(e.path("event").asString())).toList();
        JsonNode last = events.getLast();
        boolean blocked = "confirmation".equals(last.path("event").asString()) && "pending_exists".equals(last.path("reason").asString());
        long wrongCodes = confirmations.stream().filter(e -> "confirmation_failed".equals(e.path("errorCode").asString(null))
                && (!e.has("reason") || "attempts_exhausted".equals(e.path("reason").asString()))).count();
        if (!confirmations.isEmpty() && !blocked) {
            row.put("wrongCodeCount", (int) Math.min(3, wrongCodes));
        }

        String result;
        String errorCode = null;
        String lastEvent = last.path("event").asString();
        String reason = last.path("reason").asString(null);
        if ("confirmation".equals(lastEvent)) {
            JsonNode started = events.stream().filter(e -> "confirmation_pending".equals(e.path("decision").asString())).findFirst().orElse(first);
            long startedAt = Instant.parse(started.path("ts").asString()).toEpochMilli();
            boolean timedOut = nowMillis - startedAt > TTL_MILLIS;
            boolean waiting = "confirmation_pending".equals(last.path("decision").asString()) || reason == null || WAITING_REASONS.contains(reason);
            if ("confirmation_expired".equals(reason)) {
                result = "expired";
            } else if (waiting) {
                result = timedOut ? "expired" : "confirmation_pending";
            } else {
                result = CONFIRMATION_RESULTS.getOrDefault(reason, "confirmation_failed");
                errorCode = last.path("errorCode").asString(null);
            }
            if ("expired".equals(result) || "confirmation_pending".equals(result)) {
                errorCode = null;
            }
        } else if ("tool_call".equals(lastEvent)) {
            boolean confirmed = confirmations.stream().anyMatch(e -> Set.of("user_confirmed", "user_confirmed_no_preview")
                    .contains(e.path("reason").asString("")));
            if ("ok".equals(last.path("outcome").asString())) {
                result = confirmed ? "confirmed" : "ok";
            } else {
                result = reason != null && DENIED_RESULTS.containsKey(reason) ? DENIED_RESULTS.get(reason) : "error";
                errorCode = last.path("errorCode").asString(null);
            }
        } else {
            result = DENIED_RESULTS.getOrDefault(reason == null ? "" : reason, "error");
            errorCode = last.path("errorCode").asString(null);
        }
        row.put("result", result);
        if (errorCode == null) {
            row.putNull("errorCode");
        } else {
            row.put("errorCode", errorCode);
        }
        return row;
    }

    /** A denied call has a policy_decision and a tool_call that both say deny; only the first is kept. */
    private static List<JsonNode> dropDuplicateDenial(List<JsonNode> events) {
        boolean denied = events.stream().anyMatch(e -> "policy_decision".equals(e.path("event").asString())
                && "deny".equals(e.path("decision").asString()));
        if (!denied) {
            return events;
        }
        return events.stream().filter(e -> !("tool_call".equals(e.path("event").asString())
                && "deny".equals(e.path("decision").asString()))).toList();
    }

    private static void copy(JsonNode from, ObjectNode to, String field) {
        if (from.has(field)) {
            to.set(field, from.get(field));
        }
    }
}
