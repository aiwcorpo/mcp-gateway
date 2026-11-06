package pl.aiwcorpo.mcp.gateway.admin;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.regex.Pattern;

import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.confirm.ConfirmationRules;
import pl.aiwcorpo.mcp.gateway.confirm.ConfirmationService;
import pl.aiwcorpo.mcp.gateway.confirm.ConfirmationStore.StoreUnavailableException;
import pl.aiwcorpo.mcp.gateway.confirm.PendingCall;
import pl.aiwcorpo.mcp.gateway.jwt.UuidV7;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * C5 for the owner of a pending confirmation (C11): the read-only preview, the record that it was viewed and the cancel.
 * "Owner" is the {@code sub} of the BFF's user token: the state is per user, so a foreign, unknown, expired, replaced or
 * executed id is one and the same 404 (invariant 8). Nothing here approves anything; the code is typed in the MCP client.
 */
@RestController
@RequestMapping("/admin/v1/confirmations")
public class ConfirmationAdminController {

    private static final Pattern ID = Pattern.compile("^[A-Za-z0-9_-]{16,128}$");
    private static final Pattern REQUEST_ID = Pattern.compile("^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$");

    private final ConfirmationService confirmations;
    private final JsonMapper json;

    public ConfirmationAdminController(ConfirmationService confirmations, JsonMapper json) {
        this.confirmations = confirmations;
        this.json = json;
    }

    @GetMapping("/{confirmationId}")
    public ResponseEntity<String> view(@PathVariable String confirmationId, @AuthenticationPrincipal Jwt token,
                                       HttpServletRequest request) {
        String requestId = requestId(request);
        if (!ID.matcher(confirmationId).matches()) {
            return error(HttpStatus.BAD_REQUEST, requestId, "invalid_request");
        }
        try {
            Optional<PendingCall> call = confirmations.view(GatewayUser.from(token).sub(), confirmationId);
            if (call.isEmpty()) {
                return error(HttpStatus.NOT_FOUND, requestId, "not_found_or_denied");
            }
            ResponseEntity.BodyBuilder ok = ResponseEntity.ok().header("X-Request-Id", requestId)
                    .cacheControl(CacheControl.noStore()).header("Pragma", "no-cache").contentType(MediaType.APPLICATION_JSON);
            return ok.body(json.writeValueAsString(body(call.get())));
        } catch (StoreUnavailableException e) {
            return error(HttpStatus.SERVICE_UNAVAILABLE, requestId, "upstream_unavailable");
        }
    }

    @PostMapping("/{confirmationId}/viewed")
    public ResponseEntity<String> viewed(@PathVariable String confirmationId, @AuthenticationPrincipal Jwt token,
                                         HttpServletRequest request) {
        String requestId = requestId(request);
        if (!ID.matcher(confirmationId).matches()) {
            return error(HttpStatus.BAD_REQUEST, requestId, "invalid_request");
        }
        try {
            return confirmations.markViewed(GatewayUser.from(token).sub(), confirmationId) ? noContent(requestId)
                    : error(HttpStatus.NOT_FOUND, requestId, "not_found_or_denied");
        } catch (StoreUnavailableException e) {
            return error(HttpStatus.SERVICE_UNAVAILABLE, requestId, "upstream_unavailable");
        }
    }

    @PostMapping("/{confirmationId}/cancel")
    public ResponseEntity<String> cancel(@PathVariable String confirmationId, @AuthenticationPrincipal Jwt token,
                                         HttpServletRequest request) {
        String requestId = requestId(request);
        if (!ID.matcher(confirmationId).matches()) {
            return error(HttpStatus.BAD_REQUEST, requestId, "invalid_request");
        }
        return switch (confirmations.cancel(GatewayUser.from(token), requestId, confirmationId)) {
            case ConfirmationService.CancelResult.Cancelled c -> noContent(requestId);
            case ConfirmationService.CancelResult.NotFound n -> error(HttpStatus.NOT_FOUND, requestId, "not_found_or_denied");
            case ConfirmationService.CancelResult.Unavailable u -> error(HttpStatus.SERVICE_UNAVAILABLE, requestId, "upstream_unavailable");
        };
    }

    private ObjectNode body(PendingCall call) {
        PendingCall.Display display = call.display();
        ObjectNode view = json.createObjectNode();
        view.put("confirmationId", call.confirmationId());
        view.put("tool", display.qualifiedTool());
        view.put("system", display.system());
        if (display.resource() != null) {
            ObjectNode resource = view.putObject("resource");
            resource.put("type", display.resource().type());
            resource.put("id", display.resource().id());
            if (display.resource().parent() != null) {
                resource.put("parent", display.resource().parent());
            }
        }
        ArrayNode arguments = view.putArray("arguments");
        for (PendingCall.Argument argument : display.arguments()) {
            ObjectNode item = arguments.addObject();
            item.put("name", argument.name());
            item.put("value", argument.value());
            item.put("truncated", argument.truncated());
        }
        view.put("expiresAt", Instant.ofEpochMilli(call.expiresAt(ConfirmationRules.TTL_MILLIS)).truncatedTo(ChronoUnit.SECONDS).toString());
        return view;
    }

    private static String requestId(HttpServletRequest request) {
        String offered = request.getHeader("X-Request-Id");
        return offered != null && REQUEST_ID.matcher(offered).matches() ? offered : UuidV7.next();
    }

    private static ResponseEntity<String> noContent(String requestId) {
        return ResponseEntity.noContent().header("X-Request-Id", requestId).cacheControl(CacheControl.noStore()).build();
    }

    private ResponseEntity<String> error(HttpStatus status, String requestId, String code) {
        ObjectNode body = json.createObjectNode();
        body.put("error", code);
        return ResponseEntity.status(status).header("X-Request-Id", requestId).cacheControl(CacheControl.noStore())
                .contentType(MediaType.APPLICATION_JSON).body(json.writeValueAsString(body));
    }
}
