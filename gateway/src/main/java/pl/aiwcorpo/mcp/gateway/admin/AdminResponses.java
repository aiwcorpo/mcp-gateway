package pl.aiwcorpo.mcp.gateway.admin;

import java.util.regex.Pattern;

import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import jakarta.servlet.http.HttpServletRequest;
import pl.aiwcorpo.mcp.gateway.jwt.UuidV7;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/** The shapes of answer the controllers of C5 share: JSON, never cached, the request id in {@code X-Request-Id}. */
final class AdminResponses {

    private static final Pattern REQUEST_ID = Pattern.compile("^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$");

    private final JsonMapper json;

    AdminResponses(JsonMapper json) {
        this.json = json;
    }

    /** The BFF's UUIDv7 (CC-047) when it is one, else a fresh one. */
    static String requestId(HttpServletRequest request) {
        String offered = request.getHeader("X-Request-Id");
        return offered != null && REQUEST_ID.matcher(offered).matches() ? offered : UuidV7.next();
    }

    ResponseEntity<String> ok(String requestId, JsonNode body) {
        return ResponseEntity.ok().header("X-Request-Id", requestId).cacheControl(CacheControl.noStore())
                .contentType(MediaType.APPLICATION_JSON).body(json.writeValueAsString(body));
    }

    ResponseEntity<String> noContent(String requestId) {
        return ResponseEntity.noContent().header("X-Request-Id", requestId).cacheControl(CacheControl.noStore()).build();
    }

    ResponseEntity<String> error(HttpStatus status, String requestId, String code, String reason, String message) {
        ObjectNode body = json.createObjectNode();
        body.put("error", code);
        if (reason != null) {
            body.put("reason", reason);
        }
        if (message != null) {
            body.put("message", message.length() > 500 ? message.substring(0, 500) : message);
        }
        return ResponseEntity.status(status).header("X-Request-Id", requestId).cacheControl(CacheControl.noStore())
                .contentType(MediaType.APPLICATION_JSON).body(json.writeValueAsString(body));
    }

    /** The store the answer depends on does not answer; the caller repeats later (nothing was changed). */
    ResponseEntity<String> unavailable(String requestId, int retryAfterSeconds) {
        ObjectNode body = json.createObjectNode();
        body.put("error", "upstream_unavailable");
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).header("X-Request-Id", requestId)
                .header(HttpHeaders.RETRY_AFTER, Integer.toString(retryAfterSeconds)).cacheControl(CacheControl.noStore())
                .contentType(MediaType.APPLICATION_JSON).body(json.writeValueAsString(body));
    }
}
