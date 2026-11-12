package pl.aiwcorpo.mcp.gateway.admin;

import java.io.IOException;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import pl.aiwcorpo.mcp.gateway.audit.AuditEvent;
import pl.aiwcorpo.mcp.gateway.audit.AuditLog;
import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.confirm.TextHygiene;
import pl.aiwcorpo.mcp.gateway.killswitch.KillSwitchStore;
import pl.aiwcorpo.mcp.gateway.killswitch.KillSwitches;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.server.ServerRegistry;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * The emergency switch of a server or a tool (C5, CC-194, A9): put and lifted by an administrator of the portal, listed for the portal.
 * The switch is stored first, then the counter of changes moves and every instance reads it within its cache time; a switch that could
 * not be stored is a 503, never a 204. Putting needs no fresh MFA (an incident must not wait for a second factor); lifting widens access
 * again, so the BFF asks for one and the gateway checks it on the token it gets.
 */
@RestController
public class KillSwitchController {

    private static final Logger log = LoggerFactory.getLogger(KillSwitchController.class);
    private static final Pattern SERVER_ID = Pattern.compile("^mcp-[a-z][a-z0-9]{1,30}$");
    private static final Pattern TOOL_NAME = Pattern.compile("^[a-z][a-z0-9]*(_[a-z0-9]+)*$");
    private static final int RETRY_AFTER_SECONDS = 10;

    private final KillSwitchStore store;
    private final KillSwitches switches;
    private final ServerRegistry servers;
    private final AuditLog audit;
    private final String componentId;
    private final JsonMapper json;
    private final AdminResponses answers;
    private final Runnable changed;
    private final FreshMfa mfa;

    /** @param changed told after a switch was stored, so that this instance reads it and its streams are checked at once */
    public KillSwitchController(KillSwitchStore store, KillSwitches switches, ServerRegistry servers, AuditLog audit, String componentId,
                                JsonMapper json, Runnable changed, FreshMfa mfa) {
        this.store = store;
        this.switches = switches;
        this.servers = servers;
        this.audit = audit;
        this.componentId = componentId;
        this.json = json;
        this.answers = new AdminResponses(json);
        this.changed = changed;
        this.mfa = mfa;
    }

    @GetMapping("/admin/v1/kill-switches")
    public ResponseEntity<String> list(@AuthenticationPrincipal Jwt token, HttpServletRequest request) {
        String requestId = AdminResponses.requestId(request);
        if (!administrator(token)) {
            return answers.error(HttpStatus.FORBIDDEN, requestId, "access_denied", null, null);
        }
        Optional<List<KillSwitchStore.Entry>> entries = switches.entries();
        if (entries.isEmpty()) {
            return answers.unavailable(requestId, RETRY_AFTER_SECONDS);
        }
        ObjectNode body = json.createObjectNode();
        ArrayNode out = body.putArray("switches");
        entries.get().forEach(entry -> {
            ObjectNode item = out.addObject();
            item.put("scope", entry.scope());
            item.put("serverId", entry.serverId());
            if (entry.tool() != null) {
                item.put("tool", entry.tool());
            }
            item.put("setBy", entry.setBy());
            item.put("setAt", entry.setAt().truncatedTo(ChronoUnit.SECONDS).toString());
            item.put("reason", entry.reason());
        });
        return answers.ok(requestId, body);
    }

    @PutMapping("/admin/v1/registry/servers/{serverId}/kill-switch")
    public ResponseEntity<String> putServer(@PathVariable String serverId, @AuthenticationPrincipal Jwt token, HttpServletRequest request)
            throws IOException {
        return put(serverId, null, token, request);
    }

    @DeleteMapping("/admin/v1/registry/servers/{serverId}/kill-switch")
    public ResponseEntity<String> deleteServer(@PathVariable String serverId, @AuthenticationPrincipal Jwt token, HttpServletRequest request) {
        return delete(serverId, null, token, request);
    }

    @PutMapping("/admin/v1/registry/servers/{serverId}/tools/{tool}/kill-switch")
    public ResponseEntity<String> putTool(@PathVariable String serverId, @PathVariable String tool, @AuthenticationPrincipal Jwt token,
                                          HttpServletRequest request) throws IOException {
        return put(serverId, tool, token, request);
    }

    @DeleteMapping("/admin/v1/registry/servers/{serverId}/tools/{tool}/kill-switch")
    public ResponseEntity<String> deleteTool(@PathVariable String serverId, @PathVariable String tool, @AuthenticationPrincipal Jwt token,
                                             HttpServletRequest request) {
        return delete(serverId, tool, token, request);
    }

    private ResponseEntity<String> put(String serverId, String tool, Jwt token, HttpServletRequest request) throws IOException {
        String requestId = AdminResponses.requestId(request);
        if (!administrator(token)) {
            return answers.error(HttpStatus.FORBIDDEN, requestId, "access_denied", null, null);
        }
        if (!SERVER_ID.matcher(serverId).matches() || (tool != null && !TOOL_NAME.matcher(tool).matches())) {
            return answers.error(HttpStatus.BAD_REQUEST, requestId, "invalid_request", null, null);
        }
        Optional<McpServer> server = servers.find(serverId);
        if (server.isEmpty() || (tool != null && !knows(server.get(), tool))) {
            return answers.error(HttpStatus.NOT_FOUND, requestId, "not_found_or_denied", null, null);
        }
        Optional<String> reason = reasonOf(request.getInputStream().readNBytes(2049));
        if (reason.isEmpty()) {
            return answers.error(HttpStatus.BAD_REQUEST, requestId, "invalid_request", null, null);
        }
        GatewayUser administrator = GatewayUser.from(token);
        try {
            store.put(serverId, tool, administrator.sub(), reason.get());
        } catch (DataAccessException e) {
            log.error("emergency switch of {} not stored: {}", serverId, e.getClass().getName());
            return answers.unavailable(requestId, RETRY_AFTER_SECONDS);
        }
        changed.run();
        // The text of the administrator stays in the registry; the event carries who, what and when only.
        audit.emit(AuditEvent.of("admin_change", requestId, componentId).userWithoutClient(administrator).server(serverId).tool(tool)
                .reason("kill_switch_set").outcome("ok"));
        return answers.noContent(requestId);
    }

    private ResponseEntity<String> delete(String serverId, String tool, Jwt token, HttpServletRequest request) {
        String requestId = AdminResponses.requestId(request);
        if (!administrator(token)) {
            return answers.error(HttpStatus.FORBIDDEN, requestId, "access_denied", null, null);
        }
        if (!mfa.fresh(token)) {
            mfa.refused(token, requestId, tool == null ? "deleteServerKillSwitch" : "deleteToolKillSwitch");
            return answers.error(HttpStatus.UNAUTHORIZED, requestId, "step_up_required", null, null);
        }
        // The switch of a tool that left the manifest can still be lifted: the address is checked, the tool is not.
        if (!SERVER_ID.matcher(serverId).matches() || (tool != null && !TOOL_NAME.matcher(tool).matches())) {
            return answers.error(HttpStatus.BAD_REQUEST, requestId, "invalid_request", null, null);
        }
        if (servers.find(serverId).isEmpty()) {
            return answers.error(HttpStatus.NOT_FOUND, requestId, "not_found_or_denied", null, null);
        }
        GatewayUser administrator = GatewayUser.from(token);
        try {
            store.delete(serverId, tool);
        } catch (DataAccessException e) {
            log.error("emergency switch of {} not lifted: {}", serverId, e.getClass().getName());
            return answers.unavailable(requestId, RETRY_AFTER_SECONDS);
        }
        changed.run();
        audit.emit(AuditEvent.of("admin_change", requestId, componentId).userWithoutClient(administrator).server(serverId).tool(tool)
                .reason("kill_switch_cleared").outcome("ok"));
        return answers.noContent(requestId);
    }

    /** The registry knows the tool in any state: approved, waiting for approval, or served from the configuration. */
    private boolean knows(McpServer server, String tool) {
        return TOOL_NAME.matcher(tool).matches() && servers.resolveForCall(server.system() + "__" + tool).isPresent();
    }

    /** The body is exactly {@code {"reason": <1 to 200 characters>}}, without the characters CC-121 forbids. */
    private Optional<String> reasonOf(byte[] raw) {
        if (raw.length > 2048) {
            return Optional.empty();
        }
        try {
            JsonNode body = json.readTree(raw);
            if (body == null || !body.isObject() || body.size() != 1 || !body.path("reason").isString()) {
                return Optional.empty();
            }
            String reason = body.path("reason").asString();
            int length = reason.codePointCount(0, reason.length());
            if (length < 1 || length > 200 || TextHygiene.containsForbidden(reason)) {
                return Optional.empty();
            }
            return Optional.of(reason);
        } catch (JacksonException e) {
            return Optional.empty();
        }
    }

    private static boolean administrator(Jwt token) {
        return token != null && GatewayUser.from(token).hasGroup(RegistryController.ADMIN_GROUP);
    }
}
