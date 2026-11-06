package pl.aiwcorpo.mcp.gateway.admin;

import java.util.Optional;

import org.springframework.dao.DataAccessException;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import pl.aiwcorpo.mcp.gateway.policy.PolicyService;
import pl.aiwcorpo.mcp.gateway.server.ServerRegistry;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * {@code GET /internal/v1/policy-data} (C5, C7) on the internal TLS port, for servers: the administrator data a server evaluates its own
 * policies with. The certificate comes from the internal CA ({@link ServerCertificateFilter}) and its CN must be the {@code serverId} of a
 * server in the registry; any other is 403, and so is the certificate of a server that was removed. The scope mapping is reduced to the
 * namespace of the asking server, so a server never learns the grants of another system. {@code ETag} is the quoted revision.
 */
@RestController
public class PolicyDataController {

    private final PolicyService policies;
    private final ServerRegistry servers;
    private final AdminResponses responses;
    private final JsonMapper json;

    public PolicyDataController(PolicyService policies, ServerRegistry servers, JsonMapper json) {
        this.policies = policies;
        this.servers = servers;
        this.responses = new AdminResponses(json);
        this.json = json;
    }

    @GetMapping("/internal/v1/policy-data")
    public ResponseEntity<String> policyData(HttpServletRequest request) {
        String requestId = AdminResponses.requestId(request);
        Object caller = request.getAttribute(ServerCertificateFilter.CALLER);
        if (!(caller instanceof String serverId) || servers.find(serverId).isEmpty()) {
            return responses.error(HttpStatus.FORBIDDEN, requestId, "access_denied", null, null);
        }
        Optional<PolicyService.ServerData> data = policies.dataFor(serverId);
        if (data.isEmpty()) {
            return responses.unavailable(requestId, 10);
        }
        String etag = "\"" + data.get().revision() + "\"";
        if (etag.equals(request.getHeader(HttpHeaders.IF_NONE_MATCH))) {
            return ResponseEntity.status(HttpStatus.NOT_MODIFIED).header("X-Request-Id", requestId).header(HttpHeaders.ETAG, etag)
                    .cacheControl(CacheControl.noStore()).build();
        }
        ObjectNode body = json.createObjectNode();
        body.put("revision", data.get().revision());
        if (data.get().approvedPoliciesHash() != null) {
            body.put("approvedPoliciesHash", data.get().approvedPoliciesHash());
        }
        ArrayNode mapping = body.putArray("scopeMapping");
        data.get().scopeMapping().asMap().forEach((group, scopes) -> {
            ObjectNode entry = mapping.addObject();
            entry.put("group", group);
            ArrayNode list = entry.putArray("scopes");
            scopes.forEach(list::add);
        });
        ArrayNode clients = body.putArray("allowedClients");
        data.get().allowedClients().forEach(clients::add);
        ArrayNode overrides = body.putArray("overrides");
        data.get().overrides().forEach(override -> overrides.addObject().put("id", override.id()).put("text", override.text()));
        return ResponseEntity.ok().header("X-Request-Id", requestId).header(HttpHeaders.ETAG, etag).cacheControl(CacheControl.noStore())
                .contentType(MediaType.APPLICATION_JSON).body(json.writeValueAsString(body));
    }

    @org.springframework.web.bind.annotation.ExceptionHandler(DataAccessException.class)
    ResponseEntity<String> database(DataAccessException e, HttpServletRequest request) {
        return responses.unavailable(AdminResponses.requestId(request), 10);
    }
}
