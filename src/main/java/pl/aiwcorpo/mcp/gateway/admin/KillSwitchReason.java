package pl.aiwcorpo.mcp.gateway.admin;

import java.util.Optional;

import pl.aiwcorpo.mcp.gateway.confirm.TextHygiene;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** The body of every emergency switch that is put (KillSwitchRequest): exactly {@code {"reason": <1 to 200 characters>}}. */
final class KillSwitchReason {

    static final int MAX_BODY = 2048;

    private KillSwitchReason() {
    }

    /** Empty for anything else, including the characters CC-121 forbids. */
    static Optional<String> parse(JsonMapper json, byte[] raw) {
        if (raw.length > MAX_BODY) {
            return Optional.empty();
        }
        try {
            JsonNode body = json.readTree(raw);
            if (body == null || !body.isObject() || body.size() != 1 || !body.path("reason").isString()) {
                return Optional.empty();
            }
            String reason = body.path("reason").asString();
            int length = reason.codePointCount(0, reason.length());
            if (length < 1 || length > 200 || TextHygiene.containsForbidden(reason)) {
                return Optional.empty();
            }
            return Optional.of(reason);
        } catch (JacksonException e) {
            return Optional.empty();
        }
    }
}
