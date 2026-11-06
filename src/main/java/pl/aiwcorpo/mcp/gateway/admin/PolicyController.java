package pl.aiwcorpo.mcp.gateway.admin;

import java.io.IOException;
import java.util.Optional;
import java.util.regex.Pattern;

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
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.policy.PolicyOverride;
import pl.aiwcorpo.mcp.gateway.policy.PolicyService;
import pl.aiwcorpo.mcp.gateway.registry.Outcome;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * C5 policy data of the administrator: the scope mapping ({@code GET}, {@code PUT /admin/v1/policy/scope-mapping}, the whole document
 * with {@code ETag} and {@code If-Match}) and the emergency overrides ({@code /admin/v1/policy/overrides}). Group {@code mcp-platform-admin}.
 * Fresh MFA for the writes that widen access is asked by the BFF; the gateway sees the user token of the call, nothing more.
 */
@RestController
@RequestMapping("/admin/v1/policy")
public class PolicyController {

    private static final int MAX_BODY = 1024 * 1024;
    private static final Pattern OVERRIDE_ID = Pattern.compile("^override-[a-z0-9][a-z0-9-]{0,54}$");

    private final FreshMfa mfa;
    private final PolicyService policies;
    private final AdminResponses responses;
    private final JsonMapper json;

    public PolicyController(PolicyService policies, JsonMapper json, FreshMfa mfa) {
        this.mfa = mfa;
        this.policies = policies;
        this.responses = new AdminResponses(json);
        this.json = json;
    }

    @GetMapping("/scope-mapping")
    public ResponseEntity<String> mapping(@AuthenticationPrincipal Jwt token, HttpServletRequest request) {
        String requestId = AdminResponses.requestId(request);
        if (!RegistryController.administrator(token)) {
            return responses.error(HttpStatus.FORBIDDEN, requestId, "access_denied", null, null);
        }
        return document(HttpStatus.OK, requestId, policies.mapping());
    }

    @PutMapping("/scope-mapping")
    public ResponseEntity<String> putMapping(@AuthenticationPrincipal Jwt token, HttpServletRequest request) throws IOException {
        String requestId = AdminResponses.requestId(request);
        if (!RegistryController.administrator(token)) {
            return responses.error(HttpStatus.FORBIDDEN, requestId, "access_denied", null, null);
        }
        String ifMatch = request.getHeader(HttpHeaders.IF_MATCH);
        if (ifMatch != null && !PolicyService.wellFormedEtag(ifMatch)) {
            return responses.error(HttpStatus.BAD_REQUEST, requestId, "invalid_request", null, null);
        }
        if (!mfa.fresh(token)) {
            mfa.refused(token, requestId, "putScopeMapping");
            return responses.error(HttpStatus.UNAUTHORIZED, requestId, "step_up_required", null, null);
        }
        Outcome<PolicyService.MappingDocument> outcome = policies.putMapping(requestId, ifMatch, body(request), GatewayUser.from(token));
        if (outcome.succeeded()) {
            return document(HttpStatus.OK, requestId, outcome.value());
        }
        return failure(outcome, requestId, "scope_mapping_rejected");
    }

    private ResponseEntity<String> document(HttpStatus status, String requestId, PolicyService.MappingDocument document) {
        return ResponseEntity.status(status).header("X-Request-Id", requestId).header(HttpHeaders.CACHE_CONTROL, "no-store")
                .header(HttpHeaders.ETAG, document.etag()).contentType(MediaType.APPLICATION_JSON)
                .body(json.writeValueAsString(document.document()));
    }

    @GetMapping("/overrides")
    public ResponseEntity<String> overrides(@AuthenticationPrincipal Jwt token, HttpServletRequest request) {
        String requestId = AdminResponses.requestId(request);
        if (!RegistryController.administrator(token)) {
            return responses.error(HttpStatus.FORBIDDEN, requestId, "access_denied", null, null);
        }
        ArrayNode body = json.createArrayNode();
        policies.overrides().forEach(override -> body.add(view(override)));
        return responses.ok(requestId, body);
    }

    @GetMapping("/overrides/{id}")
    public ResponseEntity<String> override(@PathVariable String id, @AuthenticationPrincipal Jwt token, HttpServletRequest request) {
        String requestId = AdminResponses.requestId(request);
        if (!RegistryController.administrator(token)) {
            return responses.error(HttpStatus.FORBIDDEN, requestId, "access_denied", null, null);
        }
        Optional<PolicyOverride> found = OVERRIDE_ID.matcher(id).matches() ? policies.override(id) : Optional.empty();
        return found.map(override -> withEtag(HttpStatus.OK, requestId, override)).orElseGet(
                () -> responses.error(HttpStatus.NOT_FOUND, requestId, "not_found_or_denied", null, null));
    }

    @PutMapping("/overrides/{id}")
    public ResponseEntity<String> putOverride(@PathVariable String id, @AuthenticationPrincipal Jwt token, HttpServletRequest request)
            throws IOException {
        String requestId = AdminResponses.requestId(request);
        if (!RegistryController.administrator(token)) {
            return responses.error(HttpStatus.FORBIDDEN, requestId, "access_denied", null, null);
        }
        String ifMatch = request.getHeader(HttpHeaders.IF_MATCH);
        String ifNoneMatch = request.getHeader(HttpHeaders.IF_NONE_MATCH);
        if ((ifMatch != null && !PolicyService.wellFormedEtag(ifMatch)) || (ifNoneMatch != null && !"*".equals(ifNoneMatch))
                || !OVERRIDE_ID.matcher(id).matches()) {
            return responses.error(HttpStatus.BAD_REQUEST, requestId, "invalid_request", null, null);
        }
        Outcome<PolicyOverride> outcome = policies.putOverride(requestId, id, ifMatch, ifNoneMatch != null, body(request),
                GatewayUser.from(token));
        if (outcome.succeeded()) {
            return withEtag(HttpStatus.OK, requestId, outcome.value());
        }
        return failure(outcome, requestId, "override_rejected");
    }

    @DeleteMapping("/overrides/{id}")
    public ResponseEntity<String> deleteOverride(@PathVariable String id, @AuthenticationPrincipal Jwt token, HttpServletRequest request) {
        String requestId = AdminResponses.requestId(request);
        if (!RegistryController.administrator(token)) {
            return responses.error(HttpStatus.FORBIDDEN, requestId, "access_denied", null, null);
        }
        String ifMatch = request.getHeader(HttpHeaders.IF_MATCH);
        if ((ifMatch != null && !PolicyService.wellFormedEtag(ifMatch)) || !OVERRIDE_ID.matcher(id).matches()) {
            return responses.error(HttpStatus.BAD_REQUEST, requestId, "invalid_request", null, null);
        }
        if (!mfa.fresh(token)) {
            mfa.refused(token, requestId, "deleteOverride");
            return responses.error(HttpStatus.UNAUTHORIZED, requestId, "step_up_required", null, null);
        }
        Outcome<Void> outcome = policies.deleteOverride(requestId, id, ifMatch, GatewayUser.from(token));
        return outcome.succeeded() ? responses.noContent(requestId) : failure(outcome, requestId, "override_rejected");
    }

    private ObjectNode view(PolicyOverride override) {
        ObjectNode node = json.createObjectNode();
        node.put("id", override.id());
        node.put("target", override.target());
        node.put("text", override.text());
        node.put("setBy", override.setBy());
        node.put("setAt", override.setAt().toString());
        return node;
    }

    private ResponseEntity<String> withEtag(HttpStatus status, String requestId, PolicyOverride override) {
        return ResponseEntity.status(status).header("X-Request-Id", requestId).header(HttpHeaders.CACHE_CONTROL, "no-store")
                .header(HttpHeaders.ETAG, policies.etag(override)).contentType(MediaType.APPLICATION_JSON)
                .body(json.writeValueAsString(view(override)));
    }

    private <T> ResponseEntity<String> failure(Outcome<T> outcome, String requestId, String rejectionCode) {
        return switch (outcome.status()) {
            case NOT_FOUND -> responses.error(HttpStatus.NOT_FOUND, requestId, "not_found_or_denied", null, null);
            case PRECONDITION_FAILED -> responses.error(HttpStatus.PRECONDITION_FAILED, requestId, "precondition_failed", null, null);
            case PRECONDITION_REQUIRED -> responses.error(HttpStatus.PRECONDITION_REQUIRED, requestId, "precondition_required", null, null);
            case REJECTED -> "invalid_request".equals(outcome.reason())
                    ? responses.error(HttpStatus.BAD_REQUEST, requestId, "invalid_request", null, null)
                    : responses.error(HttpStatus.UNPROCESSABLE_ENTITY, requestId, rejectionCode, outcome.reason(), outcome.message());
            default -> responses.error(HttpStatus.INTERNAL_SERVER_ERROR, requestId, "internal_error", null, null);
        };
    }

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
        org.slf4j.LoggerFactory.getLogger(PolicyController.class).error("policy database error: {}", e.getClass().getName());
        return responses.unavailable(AdminResponses.requestId(request), 10);
    }
}
