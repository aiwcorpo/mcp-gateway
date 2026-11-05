package pl.aiwcorpo.mcp.gateway.admin;

import java.time.Clock;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

import org.springframework.dao.DataAccessException;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import pl.aiwcorpo.mcp.gateway.activity.ActivityCursor;
import pl.aiwcorpo.mcp.gateway.activity.ActivityService;
import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.jwt.UuidV7;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * C5 activity of the caller: {@code /activity} (recent audit events) and {@code /activity/calls} (one row per call). The
 * user is the {@code sub} of the BFF token and nothing else: not the cursor, not a parameter, also for an administrator.
 */
@RestController
@RequestMapping("/admin/v1/activity")
public class ActivityController {

    private static final Pattern REQUEST_ID = Pattern.compile("^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$");
    private static final Set<String> GROUPS = Set.of("ok", "denied", "error", "confirmation");

    private final ActivityService activity;
    private final ActivityCursor cursors;
    private final Clock clock;
    private final JsonMapper json;

    public ActivityController(ActivityService activity, ActivityCursor cursors, Clock clock, JsonMapper json) {
        this.activity = activity;
        this.cursors = cursors;
        this.clock = clock;
        this.json = json;
    }

    @GetMapping
    public ResponseEntity<String> events(@AuthenticationPrincipal Jwt token, HttpServletRequest request,
                                         @RequestParam(name = "limit", defaultValue = "50") int limit) {
        String requestId = requestId(request);
        if (limit < 1 || limit > 200) {
            return error(HttpStatus.BAD_REQUEST, requestId, "invalid_request");
        }
        ArrayNode body = json.createArrayNode();
        activity.recentEvents(GatewayUser.from(token).sub(), limit).forEach(body::add);
        return ok(requestId, body, null);
    }

    @GetMapping("/calls")
    public ResponseEntity<String> calls(@AuthenticationPrincipal Jwt token, HttpServletRequest request,
                                        @RequestParam(name = "limit", defaultValue = "50") int limit,
                                        @RequestParam(name = "from", required = false) String from,
                                        @RequestParam(name = "to", required = false) String to,
                                        @RequestParam(name = "result", required = false) String result,
                                        @RequestParam(name = "q", required = false) String q,
                                        @RequestParam(name = "cursor", required = false) String cursor) {
        String requestId = requestId(request);
        String sub = GatewayUser.from(token).sub();
        Instant fromInstant;
        Instant toInstant;
        try {
            fromInstant = from == null ? null : Instant.parse(from);
            toInstant = to == null ? null : Instant.parse(to);
        } catch (DateTimeParseException e) {
            return error(HttpStatus.BAD_REQUEST, requestId, "invalid_request");
        }
        if (limit < 1 || limit > 200 || (result != null && !GROUPS.contains(result)) || (q != null && (q.isEmpty() || q.length() > 64))
                || (cursor != null && cursor.length() > 256)) {
            return error(HttpStatus.BAD_REQUEST, requestId, "invalid_request");
        }
        ActivityCursor.Position after = null;
        if (cursor != null) {
            Optional<ActivityCursor.Position> position = cursors.open(sub, cursor, clock.instant().getEpochSecond());
            if (position.isEmpty()) {
                return error(HttpStatus.BAD_REQUEST, requestId, "invalid_request");
            }
            try {
                Instant.parse(position.get().ts());
            } catch (DateTimeParseException e) {
                return error(HttpStatus.BAD_REQUEST, requestId, "invalid_request");
            }
            after = position.get();
        }
        ActivityService.Page page = activity.calls(new ActivityService.Query(sub, limit, fromInstant, toInstant, result, q, after));
        ArrayNode body = json.createArrayNode();
        page.rows().forEach(body::add);
        String next = page.next() == null ? null : cursors.issue(sub, page.next(), clock.instant().getEpochSecond());
        return ok(requestId, body, next);
    }

    @ExceptionHandler(DataAccessException.class)
    ResponseEntity<String> database(DataAccessException e, HttpServletRequest request) {
        org.slf4j.LoggerFactory.getLogger(ActivityController.class).error("activity database error: {}", e.getClass().getName());
        return error(HttpStatus.SERVICE_UNAVAILABLE, requestId(request), "upstream_unavailable");
    }

    private ResponseEntity<String> ok(String requestId, ArrayNode body, String nextCursor) {
        ResponseEntity.BodyBuilder builder = ResponseEntity.ok().header("X-Request-Id", requestId).cacheControl(CacheControl.noStore())
                .contentType(MediaType.APPLICATION_JSON);
        if (nextCursor != null) {
            builder.header("X-Next-Cursor", nextCursor);
        }
        return builder.body(json.writeValueAsString(body));
    }

    private ResponseEntity<String> error(HttpStatus status, String requestId, String code) {
        ObjectNode body = json.createObjectNode();
        body.put("error", code);
        return ResponseEntity.status(status).header("X-Request-Id", requestId).cacheControl(CacheControl.noStore())
                .contentType(MediaType.APPLICATION_JSON).body(json.writeValueAsString(body));
    }

    private static String requestId(HttpServletRequest request) {
        String offered = request.getHeader("X-Request-Id");
        return offered != null && REQUEST_ID.matcher(offered).matches() ? offered : UuidV7.next();
    }
}
