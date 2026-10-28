package pl.aiwcorpo.mcp.gateway.admin;

import java.io.IOException;
import java.util.List;
import java.util.regex.Pattern;

import org.springframework.dao.DataAccessException;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import pl.aiwcorpo.mcp.gateway.audit.AuditEvent;
import pl.aiwcorpo.mcp.gateway.audit.AuditLog;
import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.auth.PublicUrls;
import pl.aiwcorpo.mcp.gateway.authz.ToolAuthorizer;
import pl.aiwcorpo.mcp.gateway.authz.ToolDecision;
import pl.aiwcorpo.mcp.gateway.jwt.UuidV7;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.server.ServerRegistry;
import pl.aiwcorpo.mcp.gateway.server.ToolDefinition;
import pl.aiwcorpo.mcp.gateway.virtual.VirtualServer;
import pl.aiwcorpo.mcp.gateway.virtual.VirtualServerService;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * C5 for the portal BFF on the internal TLS port: the catalog with the caller's access, and the caller's links.
 * "Caller" is the {@code sub} of the BFF's user token (aud mcp-gateway-admin); the mTLS client name was checked by
 * {@link AdminClientCertificateFilter}. Registry writes and approvals, activity and confirmations are not served yet.
 */
@RestController
@RequestMapping("/admin/v1")
public class AdminController {

    private static final Pattern REQUEST_ID = Pattern.compile("^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$");
    private static final int MAX_BODY = 64 * 1024;

    private final ServerRegistry registry;
    private final ToolAuthorizer authorizer;
    private final VirtualServerService virtualServers;
    private final PublicUrls urls;
    private final AuditLog audit;
    private final JsonMapper json;
    private final String componentId;

    public AdminController(ServerRegistry registry, ToolAuthorizer authorizer, VirtualServerService virtualServers,
                           PublicUrls urls, AuditLog audit, JsonMapper json, String componentId) {
        this.registry = registry;
        this.authorizer = authorizer;
        this.virtualServers = virtualServers;
        this.urls = urls;
        this.audit = audit;
        this.json = json;
        this.componentId = componentId;
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
                item.put("disabled", !decision.allowed() && "tool_disabled".equals(decision.reason()));
                item.put("requiresConfirmation", tool.requiresConfirmation());
            }
        }
        return respond(HttpStatus.OK, requestId(request), body);
    }

    @GetMapping("/virtual-servers")
    public ResponseEntity<String> list(@AuthenticationPrincipal Jwt token, HttpServletRequest request) {
        ArrayNode body = json.createArrayNode();
        for (VirtualServer link : virtualServers.list(GatewayUser.from(token))) {
            body.add(view(link));
        }
        return respond(HttpStatus.OK, requestId(request), body);
    }

    @PostMapping("/virtual-servers")
    public ResponseEntity<String> create(@AuthenticationPrincipal Jwt token, HttpServletRequest request) throws IOException {
        String requestId = requestId(request);
        GatewayUser user = GatewayUser.from(token);
        byte[] raw = request.getInputStream().readNBytes(MAX_BODY + 1);
        String slug = null;
        VirtualServer link;
        try {
            JsonNode body;
            try {
                if (raw.length > MAX_BODY) {
                    throw new AdminException(HttpStatus.BAD_REQUEST, "invalid_request");
                }
                body = json.readTree(raw);
            } catch (JacksonException e) {
                throw new AdminException(HttpStatus.BAD_REQUEST, "invalid_request");
            }
            slug = body != null && body.isObject() && body.get("slug") != null && body.get("slug").isString()
                    ? body.get("slug").asString() : null;
            link = virtualServers.create(user, virtualServers.parse(body));
        } catch (AdminException e) {
            audit.emit(change(requestId, user, slug).decision("deny", e.auditReason()).outcome("denied", errorCode(e)));
            throw e;
        }
        audit.emit(change(requestId, user, link.slug()).decision("allow", "vs_created").outcome("ok", null));
        ObjectNode created = json.createObjectNode();
        created.put("slug", link.slug());
        created.put("url", urls.virtualServerUrl(link.slug()));
        return respond(HttpStatus.CREATED, requestId, created);
    }

    @DeleteMapping("/virtual-servers/{slug}")
    public ResponseEntity<String> delete(@PathVariable String slug, @AuthenticationPrincipal Jwt token,
                                         HttpServletRequest request) {
        String requestId = requestId(request);
        GatewayUser user = GatewayUser.from(token);
        try {
            virtualServers.delete(user, slug);
        } catch (AdminException e) {
            audit.emit(change(requestId, user, slug).decision("deny", e.auditReason()).outcome("denied", errorCode(e)));
            throw e;
        }
        audit.emit(change(requestId, user, slug).decision("allow", "vs_deleted").outcome("ok", null));
        return ResponseEntity.noContent().header("X-Request-Id", requestId).cacheControl(CacheControl.noStore()).build();
    }

    @ExceptionHandler(AdminException.class)
    ResponseEntity<String> failure(AdminException e, HttpServletRequest request) {
        ObjectNode body = json.createObjectNode();
        body.put("error", e.code());
        return respond(e.status(), requestId(request), body);
    }

    @ExceptionHandler(DataAccessException.class)
    ResponseEntity<String> database(DataAccessException e, HttpServletRequest request) {
        org.slf4j.LoggerFactory.getLogger(AdminController.class).error("admin database error: {}", e.getClass().getName());
        ObjectNode body = json.createObjectNode();
        body.put("error", "upstream_unavailable");
        return respond(HttpStatus.SERVICE_UNAVAILABLE, requestId(request), body);
    }

    private ObjectNode view(VirtualServer link) {
        ObjectNode item = json.createObjectNode();
        item.put("slug", link.slug());
        item.put("displayName", link.displayName());
        item.set("tools", json.valueToTree(List.copyOf(link.tools())));
        item.put("url", urls.virtualServerUrl(link.slug()));
        return item;
    }

    /** C10 code for the audit event; a taken slug has none there. */
    private static String errorCode(AdminException e) {
        return switch (e.status()) {
            case FORBIDDEN -> "access_denied";
            case NOT_FOUND -> "not_found_or_denied";
            case BAD_REQUEST -> "invalid_argument";
            default -> null;
        };
    }

    private AuditEvent change(String requestId, GatewayUser user, String slug) {
        return AuditEvent.of("admin_change", requestId, componentId).user(user)
                .virtualServer(VirtualServer.validSlug(slug) ? slug : null);
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
