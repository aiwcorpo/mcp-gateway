package pl.aiwcorpo.mcp.gateway.admin;

import java.io.IOException;

import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import pl.aiwcorpo.mcp.gateway.registry.RegistryService;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * The channel of an adapter (C5 submitAdapterManifest, CC-206): the sidecar of a foreign MCP server submits its manifest at the start.
 * The certificate (CN {@code mcp-adapter-<serverId>}, the whole name against the path) was checked before; here the body against the path
 * comes first (400), then the mode of the server and the {@code source} of the manifest (422), then the checks of any manifest (422).
 * Nothing the call stores is approved.
 */
@RestController
@RequestMapping("/admin/v1/registry/adapters")
public class AdapterRegistryController {

    private static final int MAX_BODY = 1024 * 1024;

    private final RegistryService registry;
    private final JsonMapper json;
    private final AdminResponses answers;

    public AdapterRegistryController(RegistryService registry, JsonMapper json) {
        this.registry = registry;
        this.json = json;
        this.answers = new AdminResponses(json);
    }

    @PutMapping("/{serverId}")
    public ResponseEntity<String> submit(@PathVariable String serverId, HttpServletRequest request) throws IOException {
        String requestId = AdminResponses.requestId(request);
        byte[] raw = request.getInputStream().readNBytes(MAX_BODY + 1);
        JsonNode manifest;
        try {
            if (raw.length > MAX_BODY) {
                return answers.error(HttpStatus.BAD_REQUEST, requestId, "invalid_request", null, null);
            }
            manifest = json.readTree(raw);
        } catch (JacksonException e) {
            return answers.error(HttpStatus.BAD_REQUEST, requestId, "invalid_request", null, null);
        }
        if (manifest == null || !manifest.isObject() || !serverId.equals(manifest.path("serverId").asString(null))) {
            return answers.error(HttpStatus.BAD_REQUEST, requestId, "invalid_request", null, null);
        }
        return switch (registry.submitAdapter(requestId, serverId, manifest)) {
            case RegistryService.Result.Accepted accepted -> answers.ok(requestId, RegistryViews.server(json, accepted.server(), true));
            case RegistryService.Result.Rejected rejected -> answers.error(HttpStatus.UNPROCESSABLE_ENTITY, requestId, "manifest_rejected",
                    rejected.reason(), rejected.message());
            case RegistryService.Result.UnknownServer unknown -> answers.error(HttpStatus.UNPROCESSABLE_ENTITY, requestId, "manifest_rejected",
                    null, "unknown server");
        };
    }

    @ExceptionHandler(DataAccessException.class)
    ResponseEntity<String> database(DataAccessException e, HttpServletRequest request) {
        org.slf4j.LoggerFactory.getLogger(AdapterRegistryController.class).error("registry database error: {}", e.getClass().getName());
        return answers.unavailable(AdminResponses.requestId(request), 10);
    }
}
