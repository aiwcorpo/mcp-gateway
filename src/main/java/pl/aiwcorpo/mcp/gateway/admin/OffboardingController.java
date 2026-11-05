package pl.aiwcorpo.mcp.gateway.admin;

import java.util.regex.Pattern;

import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import pl.aiwcorpo.mcp.gateway.jwt.UuidV7;
import pl.aiwcorpo.mcp.gateway.offboarding.UserPurge;

/** C5 purgeUser: the offboarding process (certificate {@code mcp-offboarding}, no token) removes what the gateway keeps about a user. */
@RestController
@RequestMapping("/admin/v1/users")
public class OffboardingController {

    private static final Pattern REQUEST_ID = Pattern.compile("^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$");

    private final UserPurge purge;

    public OffboardingController(UserPurge purge) {
        this.purge = purge;
    }

    @PostMapping("/{sub}/purge")
    public ResponseEntity<String> purge(@PathVariable String sub, HttpServletRequest request) {
        String offered = request.getHeader("X-Request-Id");
        String requestId = offered != null && REQUEST_ID.matcher(offered).matches() ? offered : UuidV7.next();
        if (sub.isEmpty() || sub.length() > 255) {
            return answer(HttpStatus.BAD_REQUEST, requestId, "{\"error\":\"invalid_request\"}");
        }
        if (!purge.purge(requestId, sub)) {
            return answer(HttpStatus.SERVICE_UNAVAILABLE, requestId, "{\"error\":\"upstream_unavailable\"}");
        }
        return ResponseEntity.noContent().header("X-Request-Id", requestId).cacheControl(CacheControl.noStore()).build();
    }

    private static ResponseEntity<String> answer(HttpStatus status, String requestId, String body) {
        return ResponseEntity.status(status).header("X-Request-Id", requestId).cacheControl(CacheControl.noStore())
                .contentType(MediaType.APPLICATION_JSON).body(body);
    }
}
