package pl.aiwcorpo.mcp.gateway.admin;

import java.io.IOException;
import java.util.List;
import java.util.regex.Pattern;

import org.springframework.dao.DataAccessException;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import pl.aiwcorpo.mcp.gateway.jwt.UuidV7;
import pl.aiwcorpo.mcp.gateway.registry.ApprovedServer;
import pl.aiwcorpo.mcp.gateway.registry.RegistryService;
import pl.aiwcorpo.mcp.gateway.server.ServerRegistry;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * C5 registry, M3 form: CI registers the manifest of a server ({@code PUT}, the approval), the portal lists what is approved.
 * Pending entries, their diff and the approval by an administrator are M4 (CC-097), so every listed tool is {@code approved}.
 */
@RestController
@RequestMapping("/admin/v1/registry/servers")
public class RegistryController {

    private static final int MAX_BODY = 1024 * 1024;
    private static final Pattern REQUEST_ID = Pattern.compile("^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$");

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
                return error(HttpStatus.BAD_REQUEST, requestId, "invalid_request", null);
            }
            manifest = json.readTree(raw);
        } catch (JacksonException e) {
            return error(HttpStatus.BAD_REQUEST, requestId, "invalid_request", null);
        }
        if (manifest == null || !manifest.isObject() || !serverId.equals(manifest.path("serverId").asString(null))) {
            return error(HttpStatus.BAD_REQUEST, requestId, "invalid_request", null);
        }
        return switch (registry.register(serverId, manifest, "ci")) {
            case RegistryService.Result.Accepted accepted -> ok(requestId, view(accepted.server()));
            case RegistryService.Result.Rejected rejected -> error(HttpStatus.UNPROCESSABLE_ENTITY, requestId, "manifest_rejected",
                    String.join("; ", rejected.reasons()));
            case RegistryService.Result.UnknownServer unknown -> error(HttpStatus.UNPROCESSABLE_ENTITY, requestId, "manifest_rejected",
                    "unknown server");
        };
    }

    @GetMapping
    public ResponseEntity<String> list(HttpServletRequest request) {
        ArrayNode body = json.createArrayNode();
        servers.all().forEach(server -> {
            ObjectNode item;
            if (registry.approved(server.serverId()).isPresent()) {
                item = view(registry.approved(server.serverId()).get());
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
        return ok(requestId(request), body);
    }

    /** RegistryServer: the manifest entries with their status; the whole approved set is {@code approved}. */
    private ObjectNode view(ApprovedServer server) {
        ObjectNode view = json.createObjectNode();
        view.put("serverId", server.serverId());
        view.put("system", server.system());
        view.put("version", server.version());
        ArrayNode tools = view.putArray("tools");
        server.tools().values().forEach(tool -> {
            ObjectNode entry = ((ObjectNode) tool.entry()).deepCopy();
            entry.put("status", "approved");
            tools.add(entry);
        });
        return view;
    }

    @ExceptionHandler(DataAccessException.class)
    ResponseEntity<String> database(DataAccessException e, HttpServletRequest request) {
        org.slf4j.LoggerFactory.getLogger(RegistryController.class).error("registry database error: {}", e.getClass().getName());
        return error(HttpStatus.SERVICE_UNAVAILABLE, requestId(request), "upstream_unavailable", null);
    }

    private ResponseEntity<String> ok(String requestId, JsonNode body) {
        return ResponseEntity.ok().header("X-Request-Id", requestId).cacheControl(CacheControl.noStore())
                .contentType(MediaType.APPLICATION_JSON).body(json.writeValueAsString(body));
    }

    private ResponseEntity<String> error(HttpStatus status, String requestId, String code, String message) {
        ObjectNode body = json.createObjectNode();
        body.put("error", code);
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
