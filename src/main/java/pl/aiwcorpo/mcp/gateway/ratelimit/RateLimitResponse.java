package pl.aiwcorpo.mcp.gateway.ratelimit;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

/**
 * The answer to an MCP request that is not a tool call and is over a limit (CC-156): 429 with {@code Retry-After}, the C10 body, no
 * challenge (the client waits, it does not sign in again) and no {@code X-RateLimit-*} headers (the settings are not shown).
 * The gateway-authentication vectors of mcp-contracts hold the exact form.
 */
public final class RateLimitResponse {

    private RateLimitResponse() {
    }

    public static ResponseEntity<String> of(String requestId, int retryAfterSeconds) {
        int seconds = Math.max(1, retryAfterSeconds);
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .header("Content-Type", "application/json; charset=utf-8")
                .header("Cache-Control", "no-store")
                .header("Retry-After", Integer.toString(seconds))
                .header("X-Request-Id", requestId)
                .body("{\"error\":\"rate_limited\",\"message\":\"Too many requests. Try again later.\",\"retryAfterSeconds\":" + seconds + "}");
    }

    /** Redis did not answer, so nothing can be counted: the request is refused, not let through. */
    public static ResponseEntity<String> unavailable(String requestId, int retryAfterSeconds) {
        int seconds = Math.max(1, retryAfterSeconds);
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .header("Content-Type", "application/json; charset=utf-8")
                .header("Cache-Control", "no-store")
                .header("Retry-After", Integer.toString(seconds))
                .header("X-Request-Id", requestId)
                .body("{\"error\":\"upstream_unavailable\",\"message\":\"Request limits are temporarily unavailable. Try again in a few seconds.\"}");
    }

    /** More requests in flight than the gateway serves at once: refused at the door with the code of C10 for a service that cannot answer now. */
    public static ResponseEntity<String> overloaded(String requestId, int retryAfterSeconds) {
        int seconds = Math.max(1, retryAfterSeconds);
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .header("Content-Type", "application/json; charset=utf-8")
                .header("Cache-Control", "no-store")
                .header("Retry-After", Integer.toString(seconds))
                .header("X-Request-Id", requestId)
                .body("{\"error\":\"upstream_unavailable\",\"message\":\"The gateway is busy. Try again in a few seconds.\"}");
    }

    /** The store of the MCP sessions does not answer: the session is not unknown, it cannot be read, so not a 404 (CC-199). */
    public static ResponseEntity<String> sessionStoreUnavailable(String requestId, int retryAfterSeconds) {
        int seconds = Math.max(1, retryAfterSeconds);
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .header("Content-Type", "application/json; charset=utf-8")
                .header("Cache-Control", "no-store")
                .header("Retry-After", Integer.toString(seconds))
                .header("X-Request-Id", requestId)
                .body("{\"error\":\"upstream_unavailable\",\"message\":\"Sessions are temporarily unavailable. Try again in a few seconds.\"}");
    }
}
