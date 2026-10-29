package pl.aiwcorpo.mcp.gateway.admin;

import java.io.IOException;
import java.util.Optional;
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
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.jwt.UuidV7;
import pl.aiwcorpo.mcp.gateway.registry.RegisteredServer;
import pl.aiwcorpo.mcp.gateway.registry.RegisteredTool;
import pl.aiwcorpo.mcp.gateway.registry.RegistryService;
import pl.aiwcorpo.mcp.gateway.server.ServerRegistry;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * C5 registry. The pipeline of a reviewed commit registers a manifest ({@code PUT}, certificate alone, CN bound to the server);
 * the administrators of the portal list the registry, look at a pending definition against the approved one and approve it
 * (group {@code mcp-platform-admin}, hash of the pending entry).
 */
@RestController
@RequestMapping("/admin/v1/registry/servers")
public class RegistryController {

    public static final String ADMIN_GROUP = "mcp-platform-admin";
    private static final int MAX_BODY = 1024 * 1024;
    private static final Pattern REQUEST_ID = Pattern.compile("^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$");
    private static final Pattern DEFINITION_HASH = Pattern.compile("^sha256:[0-9a-f]{64}$");
    private static final Pattern TOOL_NAME = Pattern.compile("^[a-z][a-z0-9]*(_[a-z0-9]+)*$");

    private final RegistryService registry;
    private final ServerRegistry servers;
    private final JsonMapper json;

    public RegistryController(RegistryService registry, ServerRegistry servers, JsonMapper json) {
        this.registry = registry;
        this.servers = servers;
        this.json = json;
    }

    @PutMapping("/{serverId}")
    public ResponseEntity<String> register(@PathVariable String serverId, HttpServletRequest request) throws IOException {
        String requestId = requestId(request);
        byte[] raw = request.getInputStream().readNBytes(MAX_BODY + 1);
        JsonNode manifest;
        try {
            if (raw.length > MAX_BODY) {
                return error(HttpStatus.BAD_REQUEST, requestId, "invalid_request", null, null);
            }
            manifest = json.readTree(raw);
        } catch (JacksonException e) {
            return error(HttpStatus.BAD_REQUEST, requestId, "invalid_request", null, null);
        }
        if (manifest == null || !manifest.isObject() || !serverId.equals(manifest.path("serverId").asString(null))) {
            return error(HttpStatus.BAD_REQUEST, requestId, "invalid_request", null, null);
        }
        return switch (registry.register(requestId, serverId, manifest, "ci")) {
            case RegistryService.Result.Accepted accepted -> ok(requestId, view(accepted.server()));
            case RegistryService.Result.Rejected rejected -> error(HttpStatus.UNPROCESSABLE_ENTITY, requestId, "manifest_rejected",
                    rejected.reason(), rejected.message());
            case RegistryService.Result.UnknownServer unknown -> error(HttpStatus.UNPROCESSABLE_ENTITY, requestId, "manifest_rejected",
                    null, "unknown server");
        };
    }

    @GetMapping
    public ResponseEntity<String> list(@AuthenticationPrincipal Jwt token, HttpServletRequest request) {
        String requestId = requestId(request);
        if (!administrator(token)) {
            return error(HttpStatus.FORBIDDEN, requestId, "access_denied", null, null);
        }
        ArrayNode body = json.createArrayNode();
        servers.all().forEach(server -> {
            ObjectNode item;
            Optional<RegisteredServer> registered = registry.registered(server.serverId());
            if (registered.isPresent()) {
                item = view(registered.get());
            } else {
                item = json.createObjectNode();
                item.put("serverId", server.serverId());
                item.put("system", server.system());
                item.put("version", server.version());
                item.putArray("tools");
            }
            if (!server.enabled()) {
                item.put("enabled", false);
            }
            body.add(item);
        });
        return ok(requestId, body);
    }

    @GetMapping("/{serverId}/tools/{tool}/pending")
    public ResponseEntity<String> pending(@PathVariable String serverId, @PathVariable String tool,
                                          @AuthenticationPrincipal Jwt token, HttpServletRequest request) {
        String requestId = requestId(request);
        if (!administrator(token)) {
            return error(HttpStatus.FORBIDDEN, requestId, "access_denied", null, null);
        }
        Optional<RegistryService.PendingView> pending = TOOL_NAME.matcher(tool).matches() ? registry.pending(serverId, tool) : Optional.empty();
        if (pending.isEmpty()) {
            return error(HttpStatus.NOT_FOUND, requestId, "not_found_or_denied", null, null);
        }
        RegisteredTool.Approved approved = pending.get().approved();
        RegisteredTool.Pending waiting = pending.get().pending();
        ObjectNode body = json.createObjectNode();
        if (approved == null) {
            body.putNull("approvedEntry");
            body.putNull("approvedInVersion");
        } else {
            body.set("approvedEntry", approved.entry());
            body.put("approvedInVersion", approved.version());
        }
        body.set("pendingEntry", waiting.entry());
        body.put("pendingHash", waiting.hash());
        body.put("pendingVersion", waiting.version());
        body.put("source", waiting.source());
        if (waiting.riskLowered()) {
            body.put("riskLowered", true);
        }
        return ok(requestId, body);
    }

    @PostMapping("/{serverId}/tools/{tool}/approve")
    public ResponseEntity<String> approve(@PathVariable String serverId, @PathVariable String tool,
                                          @AuthenticationPrincipal Jwt token, HttpServletRequest request) throws IOException {
        String requestId = requestId(request);
        if (!administrator(token)) {
            return error(HttpStatus.FORBIDDEN, requestId, "access_denied", null, null);
        }
        byte[] raw = request.getInputStream().readNBytes(4097);
        String hash;
        boolean acceptRiskLowering = false;
        try {
            JsonNode body = raw.length > 4096 ? null : json.readTree(raw);
            boolean shape = body != null && body.isObject() && body.has("definitionHash")
                    && (body.size() == 1 || (body.size() == 2 && body.path("acceptRiskLowering").isBoolean()));
            hash = shape ? body.path("definitionHash").asString(null) : null;
            acceptRiskLowering = shape && body.path("acceptRiskLowering").asBoolean(false);
        } catch (JacksonException e) {
            hash = null;
        }
        if (hash == null || !DEFINITION_HASH.matcher(hash).matches()) {
            return error(HttpStatus.BAD_REQUEST, requestId, "invalid_request", null, null);
        }
        if (!TOOL_NAME.matcher(tool).matches()) {
            return error(HttpStatus.NOT_FOUND, requestId, "not_found_or_denied", null, null);
        }
        return switch (registry.approve(requestId, serverId, tool, hash, acceptRiskLowering, GatewayUser.from(token))) {
            case RegistryService.Approval.Approved approved -> ResponseEntity.noContent().header("X-Request-Id", requestId)
                    .cacheControl(CacheControl.noStore()).build();
            case RegistryService.Approval.NotFound notFound -> error(HttpStatus.NOT_FOUND, requestId, "not_found_or_denied", null, null);
            case RegistryService.Approval.HashMismatch mismatch -> error(HttpStatus.CONFLICT, requestId, "hash_mismatch", null, null);
            case RegistryService.Approval.RiskLowered lowered -> error(HttpStatus.UNPROCESSABLE_ENTITY, requestId, "manifest_rejected",
                    "risk_lowered", lowered.message());
        };
    }

    private static boolean administrator(Jwt token) {
        return token != null && GatewayUser.from(token).hasGroup(ADMIN_GROUP);
    }

    /**
     * RegistryServer: one row per tool. A tool with a pending entry shows that entry (status pending_approval, with the change and
     * its source); the definition in force is available through the pending endpoint for the diff.
     */
    private ObjectNode view(RegisteredServer server) {
        ObjectNode view = json.createObjectNode();
        view.put("serverId", server.serverId());
        view.put("system", server.system());
        view.put("version", server.version());
        ArrayNode tools = view.putArray("tools");
        server.tools().values().forEach(tool -> {
            RegisteredTool.Approved approved = tool.approved();
            RegisteredTool.Pending pending = tool.pending();
            ObjectNode entry = ((ObjectNode) (pending != null ? pending.entry() : approved.entry())).deepCopy();
            if (pending != null) {
                entry.put("status", "pending_approval");
                entry.put("change", pending.change());
                entry.put("source", pending.source());
                if (pending.riskLowered()) {
                    entry.put("riskLowered", true);
                }
            } else {
                entry.put("status", "approved");
            }
            if (approved != null) {
                entry.put("approvedInVersion", approved.version());
            } else {
                entry.putNull("approvedInVersion");
            }
            tools.add(entry);
        });
        return view;
    }

    @ExceptionHandler(DataAccessException.class)
    ResponseEntity<String> database(DataAccessException e, HttpServletRequest request) {
        org.slf4j.LoggerFactory.getLogger(RegistryController.class).error("registry database error: {}", e.getClass().getName());
        return error(HttpStatus.SERVICE_UNAVAILABLE, requestId(request), "upstream_unavailable", null, null);
    }

    private ResponseEntity<String> ok(String requestId, JsonNode body) {
        return ResponseEntity.ok().header("X-Request-Id", requestId).cacheControl(CacheControl.noStore())
                .contentType(MediaType.APPLICATION_JSON).body(json.writeValueAsString(body));
    }

    private ResponseEntity<String> error(HttpStatus status, String requestId, String code, String reason, String message) {
        ObjectNode body = json.createObjectNode();
        body.put("error", code);
        if (reason != null) {
            body.put("reason", reason);
        }
        if (message != null) {
            body.put("message", message.length() > 500 ? message.substring(0, 500) : message);
        }
        return ResponseEntity.status(status).header("X-Request-Id", requestId).cacheControl(CacheControl.noStore())
                .contentType(MediaType.APPLICATION_JSON).body(json.writeValueAsString(body));
    }

    private static String requestId(HttpServletRequest request) {
        String offered = request.getHeader("X-Request-Id");
        return offered != null && REQUEST_ID.matcher(offered).matches() ? offered : UuidV7.next();
    }
}
