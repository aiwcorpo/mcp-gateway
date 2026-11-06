package pl.aiwcorpo.mcp.gateway.admin;

import java.io.IOException;
import java.net.URI;
import java.util.regex.Pattern;

import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.registry.Outcome;
import pl.aiwcorpo.mcp.gateway.registry.ServerAdmin;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;

/**
 * C5 registry of servers: {@code GET}, {@code POST /admin/v1/servers} and {@code GET}, {@code PATCH}, {@code DELETE
 * /admin/v1/servers/{serverId}}. Group {@code mcp-platform-admin}; the document has an {@code ETag} that {@code PATCH} sends back in
 * {@code If-Match}.
 */
@RestController
@RequestMapping("/admin/v1/servers")
public class ServerController {

    private static final int MAX_BODY = 16 * 1024;
    private static final Pattern SERVER_ID = Pattern.compile("^mcp-[a-z][a-z0-9]{1,30}$");

    private final FreshMfa mfa;
    private final ServerAdmin servers;
    private final AdminResponses responses;
    private final JsonMapper json;

    public ServerController(ServerAdmin servers, JsonMapper json, FreshMfa mfa) {
        this.mfa = mfa;
        this.servers = servers;
        this.responses = new AdminResponses(json);
        this.json = json;
    }

    @GetMapping
    public ResponseEntity<String> list(@AuthenticationPrincipal Jwt token, HttpServletRequest request) {
        String requestId = AdminResponses.requestId(request);
        if (!RegistryController.administrator(token)) {
            return responses.error(HttpStatus.FORBIDDEN, requestId, "access_denied", null, null);
        }
        ArrayNode body = json.createArrayNode();
        servers.list().forEach(item -> body.add(servers.view(item.config())));
        return responses.ok(requestId, body);
    }

    @PostMapping
    public ResponseEntity<String> create(@AuthenticationPrincipal Jwt token, HttpServletRequest request) throws IOException {
        String requestId = AdminResponses.requestId(request);
        if (!RegistryController.administrator(token)) {
            return responses.error(HttpStatus.FORBIDDEN, requestId, "access_denied", null, null);
        }
        if (!mfa.fresh(token)) {
            mfa.refused(token, requestId, "createServer");
            return responses.error(HttpStatus.UNAUTHORIZED, requestId, "step_up_required", null, null);
        }
        JsonNode body = body(request);
        Outcome<ServerAdmin.Item> outcome = servers.create(requestId, body, GatewayUser.from(token));
        if (outcome.status() == Outcome.Status.CREATED) {
            return withEtag(HttpStatus.CREATED, requestId, outcome.value()).header(HttpHeaders.LOCATION,
                    URI.create("/admin/v1/servers/" + outcome.value().config().serverId()).toString()).body(json.writeValueAsString(
                            servers.view(outcome.value().config())));
        }
        return failure(outcome, requestId);
    }

    @GetMapping("/{serverId}")
    public ResponseEntity<String> get(@PathVariable String serverId, @AuthenticationPrincipal Jwt token, HttpServletRequest request) {
        String requestId = AdminResponses.requestId(request);
        if (!RegistryController.administrator(token)) {
            return responses.error(HttpStatus.FORBIDDEN, requestId, "access_denied", null, null);
        }
        return (SERVER_ID.matcher(serverId).matches() ? servers.get(serverId) : java.util.Optional.<ServerAdmin.Item>empty())
                .map(item -> withEtag(HttpStatus.OK, requestId, item).contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                        .body(json.writeValueAsString(servers.view(item.config()))))
                .orElseGet(() -> responses.error(HttpStatus.NOT_FOUND, requestId, "not_found_or_denied", null, null));
    }

    @PatchMapping("/{serverId}")
    public ResponseEntity<String> update(@PathVariable String serverId, @AuthenticationPrincipal Jwt token, HttpServletRequest request)
            throws IOException {
        String requestId = AdminResponses.requestId(request);
        if (!RegistryController.administrator(token)) {
            return responses.error(HttpStatus.FORBIDDEN, requestId, "access_denied", null, null);
        }
        String ifMatch = request.getHeader(HttpHeaders.IF_MATCH);
        if (ifMatch != null && !pl.aiwcorpo.mcp.gateway.policy.PolicyService.wellFormedEtag(ifMatch)) {
            return responses.error(HttpStatus.BAD_REQUEST, requestId, "invalid_request", null, null);
        }
        if (!SERVER_ID.matcher(serverId).matches()) {
            return responses.error(HttpStatus.NOT_FOUND, requestId, "not_found_or_denied", null, null);
        }
        JsonNode body = body(request);
        if (!FreshMfa.onlyDisables(body) && !mfa.fresh(token)) {
            mfa.refused(token, requestId, "updateServer");
            return responses.error(HttpStatus.UNAUTHORIZED, requestId, "step_up_required", null, null);
        }
        Outcome<ServerAdmin.Item> outcome = servers.update(requestId, serverId, ifMatch, body, GatewayUser.from(token));
        if (outcome.status() == Outcome.Status.OK) {
            return withEtag(HttpStatus.OK, requestId, outcome.value()).contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                    .body(json.writeValueAsString(servers.view(outcome.value().config())));
        }
        return failure(outcome, requestId);
    }

    @DeleteMapping("/{serverId}")
    public ResponseEntity<String> delete(@PathVariable String serverId, @AuthenticationPrincipal Jwt token, HttpServletRequest request) {
        String requestId = AdminResponses.requestId(request);
        if (!RegistryController.administrator(token)) {
            return responses.error(HttpStatus.FORBIDDEN, requestId, "access_denied", null, null);
        }
        if (!SERVER_ID.matcher(serverId).matches()) {
            return responses.error(HttpStatus.NOT_FOUND, requestId, "not_found_or_denied", null, null);
        }
        if (!mfa.fresh(token)) {
            mfa.refused(token, requestId, "deleteServer");
            return responses.error(HttpStatus.UNAUTHORIZED, requestId, "step_up_required", null, null);
        }
        Outcome<Void> outcome = servers.delete(requestId, serverId, GatewayUser.from(token));
        return outcome.succeeded() ? responses.noContent(requestId) : failure(outcome, requestId);
    }

    private ResponseEntity.BodyBuilder withEtag(HttpStatus status, String requestId, ServerAdmin.Item item) {
        return ResponseEntity.status(status).header("X-Request-Id", requestId).header(HttpHeaders.CACHE_CONTROL, "no-store")
                .header(HttpHeaders.ETAG, item.etag()).contentType(org.springframework.http.MediaType.APPLICATION_JSON);
    }

    private <T> ResponseEntity<String> failure(Outcome<T> outcome, String requestId) {
        return switch (outcome.status()) {
            case NOT_FOUND -> responses.error(HttpStatus.NOT_FOUND, requestId, "not_found_or_denied", null, null);
            case EXISTS -> responses.error(HttpStatus.CONFLICT, requestId, "server_exists", null, null);
            case PRECONDITION_FAILED -> responses.error(HttpStatus.PRECONDITION_FAILED, requestId, "precondition_failed", null, null);
            case PRECONDITION_REQUIRED -> responses.error(HttpStatus.PRECONDITION_REQUIRED, requestId, "precondition_required", null, null);
            case REJECTED -> "invalid_request".equals(outcome.reason())
                    ? responses.error(HttpStatus.BAD_REQUEST, requestId, "invalid_request", null, null)
                    : responses.error(HttpStatus.UNPROCESSABLE_ENTITY, requestId, "server_rejected", outcome.reason(), outcome.message());
            default -> responses.error(HttpStatus.INTERNAL_SERVER_ERROR, requestId, "internal_error", null, null);
        };
    }

    /** The JSON body, or null when it is too large or not JSON: the operation answers 400. */
    private JsonNode body(HttpServletRequest request) throws IOException {
        byte[] raw = request.getInputStream().readNBytes(MAX_BODY + 1);
        if (raw.length > MAX_BODY) {
            return null;
        }
        try {
            return json.readTree(raw);
        } catch (JacksonException e) {
            return null;
        }
    }

    @ExceptionHandler(DataAccessException.class)
    ResponseEntity<String> database(DataAccessException e, HttpServletRequest request) {
        org.slf4j.LoggerFactory.getLogger(ServerController.class).error("registry database error: {}", e.getClass().getName());
        return responses.unavailable(AdminResponses.requestId(request), 10);
    }
}
