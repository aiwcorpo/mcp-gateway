package pl.aiwcorpo.mcp.gateway.admin;

import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import pl.aiwcorpo.mcp.gateway.agent.AgentAdmin;
import pl.aiwcorpo.mcp.gateway.agent.AgentClient;
import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.policy.PolicyService;
import pl.aiwcorpo.mcp.gateway.registry.Outcome;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;

/**
 * C5 registry of agents (CC-266): {@code /admin/v1/agent-clients} with list, create, get, change, delete, the record of a key rotation and the
 * suspension of an agent (its emergency switch). Group {@code mcp-platform-admin}, with these exceptions: the owner of an agent (the
 * {@code sub} of the token equals {@code ownerSub}) lists their own agents ({@code owner=me}), reads one and suspends it, and for anyone else
 * without the group an agent does not exist. Create, change, key rotation, delete and lifting a suspension need a fresh MFA; suspending does
 * not, because an incident does not wait for a second factor. The document has an {@code ETag} that {@code PATCH} sends back in {@code If-Match}.
 */
@RestController
@RequestMapping("/admin/v1/agent-clients")
public class AgentClientController {

    private static final Logger log = LoggerFactory.getLogger(AgentClientController.class);
    private static final int MAX_BODY = 16 * 1024;
    private static final int RETRY_AFTER_SECONDS = 10;
    /** maxItems of the list in the contract. */
    private static final int MAX_LISTED = 1000;

    private final AgentAdmin agents;
    private final FreshMfa mfa;
    private final AdminResponses responses;
    private final JsonMapper json;

    public AgentClientController(AgentAdmin agents, JsonMapper json, FreshMfa mfa) {
        this.agents = agents;
        this.mfa = mfa;
        this.responses = new AdminResponses(json);
        this.json = json;
    }

    @GetMapping
    public ResponseEntity<String> list(@RequestParam(name = "owner", required = false) List<String> owner, @AuthenticationPrincipal Jwt token,
                                       HttpServletRequest request) {
        String requestId = AdminResponses.requestId(request);
        boolean mine = owner != null;
        if (mine && !(owner.size() == 1 && "me".equals(owner.getFirst()))) {
            return responses.error(HttpStatus.BAD_REQUEST, requestId, "invalid_request", null, null);
        }
        if (!mine && !RegistryController.administrator(token)) {
            return responses.error(HttpStatus.FORBIDDEN, requestId, "access_denied", null, null);
        }
        List<AgentClient> found = mine ? agents.ownedBy(GatewayUser.from(token).sub()) : agents.list();
        ArrayNode body = json.createArrayNode();
        found.stream().limit(MAX_LISTED).forEach(agent -> body.add(agents.view(agent)));
        return responses.ok(requestId, body);
    }

    @PostMapping
    public ResponseEntity<String> create(@AuthenticationPrincipal Jwt token, HttpServletRequest request) throws IOException {
        String requestId = AdminResponses.requestId(request);
        if (!RegistryController.administrator(token)) {
            return responses.error(HttpStatus.FORBIDDEN, requestId, "access_denied", null, null);
        }
        if (!mfa.fresh(token)) {
            mfa.refused(token, requestId, "createAgentClient");
            return responses.error(HttpStatus.UNAUTHORIZED, requestId, "step_up_required", null, null);
        }
        Outcome<AgentAdmin.Item> outcome = agents.create(requestId, body(request), GatewayUser.from(token));
        if (outcome.status() == Outcome.Status.CREATED) {
            return withEtag(HttpStatus.CREATED, requestId, outcome.value()).header(HttpHeaders.LOCATION,
                    URI.create("/admin/v1/agent-clients/" + outcome.value().agent().clientId()).toString())
                    .body(json.writeValueAsString(agents.view(outcome.value().agent())));
        }
        return failure(outcome, requestId);
    }

    @GetMapping("/{clientId}")
    public ResponseEntity<String> get(@PathVariable String clientId, @AuthenticationPrincipal Jwt token, HttpServletRequest request) {
        String requestId = AdminResponses.requestId(request);
        if (!AgentClient.CLIENT_ID.matcher(clientId).matches() || clientId.length() > 64) {
            return responses.error(HttpStatus.BAD_REQUEST, requestId, "invalid_request", null, null);
        }
        return agents.get(clientId).filter(item -> mayRead(token, item.agent()))
                .map(item -> withEtag(HttpStatus.OK, requestId, item).body(json.writeValueAsString(agents.view(item.agent()))))
                .orElseGet(() -> responses.error(HttpStatus.NOT_FOUND, requestId, "not_found_or_denied", null, null));
    }

    @PatchMapping("/{clientId}")
    public ResponseEntity<String> update(@PathVariable String clientId, @AuthenticationPrincipal Jwt token, HttpServletRequest request)
            throws IOException {
        String requestId = AdminResponses.requestId(request);
        if (!RegistryController.administrator(token)) {
            return responses.error(HttpStatus.FORBIDDEN, requestId, "access_denied", null, null);
        }
        String ifMatch = request.getHeader(HttpHeaders.IF_MATCH);
        if ((ifMatch != null && !PolicyService.wellFormedEtag(ifMatch)) || !validId(clientId)) {
            return responses.error(HttpStatus.BAD_REQUEST, requestId, "invalid_request", null, null);
        }
        if (!mfa.fresh(token)) {
            mfa.refused(token, requestId, "updateAgentClient");
            return responses.error(HttpStatus.UNAUTHORIZED, requestId, "step_up_required", null, null);
        }
        Outcome<AgentAdmin.Item> outcome = agents.update(requestId, clientId, ifMatch, body(request), GatewayUser.from(token));
        if (outcome.status() == Outcome.Status.OK) {
            return withEtag(HttpStatus.OK, requestId, outcome.value()).body(json.writeValueAsString(agents.view(outcome.value().agent())));
        }
        return failure(outcome, requestId);
    }

    @DeleteMapping("/{clientId}")
    public ResponseEntity<String> delete(@PathVariable String clientId, @AuthenticationPrincipal Jwt token, HttpServletRequest request) {
        String requestId = AdminResponses.requestId(request);
        if (!RegistryController.administrator(token)) {
            return responses.error(HttpStatus.FORBIDDEN, requestId, "access_denied", null, null);
        }
        if (!mfa.fresh(token)) {
            mfa.refused(token, requestId, "deleteAgentClient");
            return responses.error(HttpStatus.UNAUTHORIZED, requestId, "step_up_required", null, null);
        }
        if (!validId(clientId)) {
            return responses.error(HttpStatus.BAD_REQUEST, requestId, "invalid_request", null, null);
        }
        return answer(agents.delete(requestId, clientId, GatewayUser.from(token)), requestId);
    }

    @PostMapping("/{clientId}/key-rotated")
    public ResponseEntity<String> keyRotated(@PathVariable String clientId, @AuthenticationPrincipal Jwt token, HttpServletRequest request) {
        String requestId = AdminResponses.requestId(request);
        if (!RegistryController.administrator(token)) {
            return responses.error(HttpStatus.FORBIDDEN, requestId, "access_denied", null, null);
        }
        if (!mfa.fresh(token)) {
            mfa.refused(token, requestId, "recordAgentClientKeyRotation");
            return responses.error(HttpStatus.UNAUTHORIZED, requestId, "step_up_required", null, null);
        }
        if (!validId(clientId)) {
            return responses.error(HttpStatus.BAD_REQUEST, requestId, "invalid_request", null, null);
        }
        return answer(agents.recordKeyRotation(requestId, clientId, GatewayUser.from(token)), requestId);
    }

    @PutMapping("/{clientId}/kill-switch")
    public ResponseEntity<String> suspend(@PathVariable String clientId, @AuthenticationPrincipal Jwt token, HttpServletRequest request)
            throws IOException {
        String requestId = AdminResponses.requestId(request);
        if (!validId(clientId)) {
            return responses.error(HttpStatus.BAD_REQUEST, requestId, "invalid_request", null, null);
        }
        java.util.Optional<String> reason = KillSwitchReason.parse(json, request.getInputStream().readNBytes(KillSwitchReason.MAX_BODY + 1));
        if (reason.isEmpty()) {
            return responses.error(HttpStatus.BAD_REQUEST, requestId, "invalid_request", null, null);
        }
        return answer(agents.suspend(requestId, clientId, reason.get(), GatewayUser.from(token), RegistryController.administrator(token)),
                requestId);
    }

    @DeleteMapping("/{clientId}/kill-switch")
    public ResponseEntity<String> resume(@PathVariable String clientId, @AuthenticationPrincipal Jwt token, HttpServletRequest request) {
        String requestId = AdminResponses.requestId(request);
        if (!RegistryController.administrator(token)) {
            return responses.error(HttpStatus.FORBIDDEN, requestId, "access_denied", null, null);
        }
        if (!mfa.fresh(token)) {
            mfa.refused(token, requestId, "deleteAgentClientKillSwitch");
            return responses.error(HttpStatus.UNAUTHORIZED, requestId, "step_up_required", null, null);
        }
        if (!validId(clientId)) {
            return responses.error(HttpStatus.BAD_REQUEST, requestId, "invalid_request", null, null);
        }
        return answer(agents.resume(requestId, clientId, GatewayUser.from(token)), requestId);
    }

    private static boolean validId(String clientId) {
        return clientId.length() <= 64 && AgentClient.CLIENT_ID.matcher(clientId).matches();
    }

    private static boolean mayRead(Jwt token, AgentClient agent) {
        return RegistryController.administrator(token) || agent.ownerSub().equals(GatewayUser.from(token).sub());
    }

    private ResponseEntity<String> answer(Outcome<Void> outcome, String requestId) {
        return outcome.succeeded() ? responses.noContent(requestId) : failure(outcome, requestId);
    }

    private ResponseEntity.BodyBuilder withEtag(HttpStatus status, String requestId, AgentAdmin.Item item) {
        return ResponseEntity.status(status).header("X-Request-Id", requestId).header(HttpHeaders.CACHE_CONTROL, "no-store")
                .header(HttpHeaders.ETAG, item.etag()).contentType(MediaType.APPLICATION_JSON);
    }

    private <T> ResponseEntity<String> failure(Outcome<T> outcome, String requestId) {
        return switch (outcome.status()) {
            case NOT_FOUND -> responses.error(HttpStatus.NOT_FOUND, requestId, "not_found_or_denied", null, null);
            case EXISTS -> responses.error(HttpStatus.CONFLICT, requestId, "agent_exists", null, null);
            case PRECONDITION_FAILED -> responses.error(HttpStatus.PRECONDITION_FAILED, requestId, "precondition_failed", null, null);
            case PRECONDITION_REQUIRED -> responses.error(HttpStatus.PRECONDITION_REQUIRED, requestId, "precondition_required", null, null);
            case REJECTED -> "invalid_request".equals(outcome.reason())
                    ? responses.error(HttpStatus.BAD_REQUEST, requestId, "invalid_request", null, null)
                    : responses.error(HttpStatus.UNPROCESSABLE_ENTITY, requestId, "agent_rejected", outcome.reason(), outcome.message());
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
        log.error("agent registry database error: {}", e.getClass().getName());
        return responses.unavailable(AdminResponses.requestId(request), RETRY_AFTER_SECONDS);
    }
}
