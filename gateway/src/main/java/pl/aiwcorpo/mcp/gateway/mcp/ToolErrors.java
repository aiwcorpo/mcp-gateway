package pl.aiwcorpo.mcp.gateway.mcp;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/** Tool results with {@code isError: true} carrying the C10 JSON (tool-error.schema.json). */
public final class ToolErrors {

    public static final Set<String> CODES = Set.of("unauthenticated", "access_denied", "tool_disabled",
            "confirmation_required", "confirmation_failed", "confirmation_declined", "credential_required",
            "not_found_or_denied", "invalid_argument", "rate_limited", "step_up_required", "upstream_unavailable",
            "internal_error");

    private final JsonMapper json;

    public ToolErrors(JsonMapper json) {
        this.json = json;
    }

    public ObjectNode error(String code, String message) {
        return error(code, message, Map.of());
    }

    public ObjectNode error(String code, String message, Map<String, Object> extra) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("error", code);
        payload.put("message", message);
        payload.putAll(extra);
        ObjectNode result = json.createObjectNode();
        result.putArray("content").addObject().put("type", "text").put("text", json.writeValueAsString(payload));
        result.put("isError", true);
        return result;
    }

    /** C10 code of an error result (from the gateway or the server), or null. */
    public String codeOf(JsonNode result) {
        if (!result.path("isError").asBoolean(false)) {
            return null;
        }
        try {
            String code = json.readTree(result.path("content").path(0).path("text").asString("{}")).path("error").asString(null);
            return CODES.contains(code) ? code : null;
        } catch (RuntimeException e) {
            return null;
        }
    }
}
