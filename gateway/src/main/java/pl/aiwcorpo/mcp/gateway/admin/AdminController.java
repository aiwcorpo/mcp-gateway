package pl.aiwcorpo.mcp.gateway.admin;

import java.util.regex.Pattern;

import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.authz.ToolAuthorizer;
import pl.aiwcorpo.mcp.gateway.authz.ToolDecision;
import pl.aiwcorpo.mcp.gateway.jwt.UuidV7;
import pl.aiwcorpo.mcp.gateway.registry.DefinitionGuard;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.server.ServerRegistry;
import pl.aiwcorpo.mcp.gateway.server.ToolDefinition;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * C5 for the portal BFF on the internal TLS port: the catalog with the caller's access and the policy status.
 * "Caller" is the {@code sub} of the BFF's user token (aud mcp-gateway-admin); the mTLS client name was checked by
 * {@link AdminClientCertificateFilter}. Registry writes and approvals, activity and confirmations are not served yet.
 */
@RestController
@RequestMapping("/admin/v1")
public class AdminController {

    private static final Pattern REQUEST_ID = Pattern.compile("^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$");

    private final ServerRegistry registry;
    private final ToolAuthorizer authorizer;
    private final JsonMapper json;
    private final String componentId;
    private final DefinitionGuard definitionGuard;

    public AdminController(ServerRegistry registry, ToolAuthorizer authorizer, JsonMapper json, String componentId,
                           DefinitionGuard definitionGuard) {
        this.registry = registry;
        this.authorizer = authorizer;
        this.json = json;
        this.componentId = componentId;
        this.definitionGuard = definitionGuard;
    }

    @GetMapping("/catalog")
    public ResponseEntity<String> catalog(@AuthenticationPrincipal Jwt token, HttpServletRequest request) {
        GatewayUser user = GatewayUser.from(token);
        ObjectNode body = json.createObjectNode();
        ArrayNode servers = body.putArray("servers");
        for (McpServer server : registry.all()) {
            ObjectNode entry = servers.addObject();
            entry.put("serverId", server.serverId());
            entry.put("system", server.system());
            entry.put("version", server.version());
            ArrayNode tools = entry.putArray("tools");
            for (ToolDefinition tool : server.tools().values()) {
                ToolDecision decision = authorizer.decide(user, server, tool);
                ObjectNode item = tools.addObject();
                item.put("name", server.qualifiedName(tool));
                if (tool.title() != null) {
                    item.put("title", tool.title());
                }
                item.put("description", tool.description());
                item.put("risk", tool.risk().name());
                item.put("action", tool.action());
                item.put("access", decision.allowed() ? "granted" : "denied");
                item.set("requiredEntitlements", json.valueToTree(authorizer.requiredEntitlements(server, tool)));
                item.put("disabled", (!decision.allowed() && "tool_disabled".equals(decision.reason()))
                        || (server.approvalRequired() && !definitionGuard.lastKnownIntact(server.serverId(), tool.name())));
                item.put("requiresConfirmation", tool.requiresConfirmation());
            }
        }
        return respond(HttpStatus.OK, requestId(request), body);
    }

    /** The revision of the main bundle in force on this instance (C5 getPolicyStatus); other instances report themselves. */
    @GetMapping("/policy/status")
    public ResponseEntity<String> policyStatus(HttpServletRequest request) {
        ObjectNode body = json.createObjectNode();
        ObjectNode instance = body.putArray("instances").addObject();
        instance.put("instanceId", componentId + "-" + instanceName());
        instance.put("revision", authorizer.policyRevision() == null ? "00000000000000-0000000" : authorizer.policyRevision());
        return respond(HttpStatus.OK, requestId(request), body);
    }

    private static String instanceName() {
        String host = System.getenv("HOSTNAME");
        return host == null || host.isBlank() ? "0" : host.replaceAll("[^A-Za-z0-9.-]", "");
    }

    /** The BFF's UUIDv7 (CC-047) when it is one, else a fresh one; always returned in X-Request-Id. */
    private static String requestId(HttpServletRequest request) {
        String offered = request.getHeader("X-Request-Id");
        return offered != null && REQUEST_ID.matcher(offered).matches() ? offered : UuidV7.next();
    }

    private ResponseEntity<String> respond(HttpStatus status, String requestId, JsonNode body) {
        return ResponseEntity.status(status).header("X-Request-Id", requestId).cacheControl(CacheControl.noStore())
                .contentType(MediaType.APPLICATION_JSON).body(json.writeValueAsString(body));
    }
}
