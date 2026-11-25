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
import pl.aiwcorpo.mcp.gateway.agent.AgentClient;
import pl.aiwcorpo.mcp.gateway.agent.AgentRegistry;
import pl.aiwcorpo.mcp.gateway.audit.AuditEvent;
import pl.aiwcorpo.mcp.gateway.audit.AuditLog;
import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.killswitch.KillSwitchStore;
import pl.aiwcorpo.mcp.gateway.killswitch.KillSwitches;
import pl.aiwcorpo.mcp.gateway.registry.PrimitiveKind;
import pl.aiwcorpo.mcp.gateway.registry.RegisteredServer;
import pl.aiwcorpo.mcp.gateway.registry.RegistryService;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.server.ServerRegistry;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * The emergency switch of a server, a tool, a resource or a prompt (C5, CC-194, CC-265, A9): put and lifted by an administrator of the portal, listed for the portal.
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
    private final RegistryService registry;
    private final AuditLog audit;
    private final String componentId;
    private final JsonMapper json;
    private final AdminResponses answers;
    private final Runnable changed;
    private final FreshMfa mfa;
    private final AgentRegistry agents;

    /** @param changed told after a switch was stored, so that this instance reads it and its streams are checked at once */
    public KillSwitchController(KillSwitchStore store, KillSwitches switches, ServerRegistry servers, RegistryService registry, AuditLog audit,
                                String componentId, JsonMapper json, Runnable changed, FreshMfa mfa) {
        this(store, switches, servers, registry, audit, componentId, json, changed, mfa, AgentRegistry.empty());
    }

    /** @param agents the suspensions of agents, listed next to the switches of servers, tools, resources and prompts (CC-266) */
    public KillSwitchController(KillSwitchStore store, KillSwitches switches, ServerRegistry servers, RegistryService registry, AuditLog audit,
                                String componentId, JsonMapper json, Runnable changed, FreshMfa mfa, AgentRegistry agents) {
        this.agents = agents;
        this.store = store;
        this.switches = switches;
        this.servers = servers;
        this.registry = registry;
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
        Optional<List<AgentClient>> registered = agents.all();
        if (entries.isEmpty() || registered.isEmpty()) {
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
            if (entry.resource() != null) {
                item.put("resource", entry.resource());
            }
            if (entry.prompt() != null) {
                item.put("prompt", entry.prompt());
            }
            item.put("setBy", entry.setBy());
            item.put("setAt", entry.setAt().truncatedTo(ChronoUnit.SECONDS).toString());
            item.put("reason", entry.reason());
        });
        List<AgentClient> suspended = registered.get().stream().filter(AgentClient::suspended)
                .sorted(java.util.Comparator.comparing((AgentClient agent) -> agent.suspension().at()).thenComparing(AgentClient::clientId)).toList();
        if (!suspended.isEmpty()) {
            ArrayNode agentSwitches = body.putArray("agentSwitches");
            suspended.forEach(agent -> {
                ObjectNode item = agentSwitches.addObject();
                item.put("clientId", agent.clientId());
                item.put("setBy", agent.suspension().by());
                item.put("setAt", agent.suspension().at().truncatedTo(ChronoUnit.SECONDS).toString());
                item.put("reason", agent.suspension().reason());
            });
        }
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

    @PutMapping("/admin/v1/registry/servers/{serverId}/resources/{name}/kill-switch")
    public ResponseEntity<String> putResource(@PathVariable String serverId, @PathVariable String name, @AuthenticationPrincipal Jwt token,
                                              HttpServletRequest request) throws IOException {
        return putNamed(serverId, PrimitiveKind.RESOURCE, name, token, request);
    }

    @DeleteMapping("/admin/v1/registry/servers/{serverId}/resources/{name}/kill-switch")
    public ResponseEntity<String> deleteResource(@PathVariable String serverId, @PathVariable String name, @AuthenticationPrincipal Jwt token,
                                                 HttpServletRequest request) {
        return deleteNamed(serverId, PrimitiveKind.RESOURCE, name, token, request);
    }

    @PutMapping("/admin/v1/registry/servers/{serverId}/prompts/{name}/kill-switch")
    public ResponseEntity<String> putPrompt(@PathVariable String serverId, @PathVariable String name, @AuthenticationPrincipal Jwt token,
                                            HttpServletRequest request) throws IOException {
        return putNamed(serverId, PrimitiveKind.PROMPT, name, token, request);
    }

    @DeleteMapping("/admin/v1/registry/servers/{serverId}/prompts/{name}/kill-switch")
    public ResponseEntity<String> deletePrompt(@PathVariable String serverId, @PathVariable String name, @AuthenticationPrincipal Jwt token,
                                               HttpServletRequest request) {
        return deleteNamed(serverId, PrimitiveKind.PROMPT, name, token, request);
    }

    /** {@code kind} is RESOURCE for a static resource and for a template: they share one name, so one switch covers either. */
    private ResponseEntity<String> putNamed(String serverId, PrimitiveKind kind, String name, Jwt token, HttpServletRequest request)
            throws IOException {
        String requestId = AdminResponses.requestId(request);
        if (!administrator(token)) {
            return answers.error(HttpStatus.FORBIDDEN, requestId, "access_denied", null, null);
        }
        if (!SERVER_ID.matcher(serverId).matches() || !validName(name)) {
            return answers.error(HttpStatus.BAD_REQUEST, requestId, "invalid_request", null, null);
        }
        if (servers.find(serverId).isEmpty() || !knowsEntry(serverId, kind, name)) {
            return answers.error(HttpStatus.NOT_FOUND, requestId, "not_found_or_denied", null, null);
        }
        Optional<String> reason = KillSwitchReason.parse(json, request.getInputStream().readNBytes(2049));
        if (reason.isEmpty()) {
            return answers.error(HttpStatus.BAD_REQUEST, requestId, "invalid_request", null, null);
        }
        GatewayUser administrator = GatewayUser.from(token);
        try {
            store.putNamed(serverId, switchKind(kind), name, administrator.sub(), reason.get());
        } catch (DataAccessException e) {
            log.error("emergency switch of {} not stored: {}", serverId, e.getClass().getName());
            return answers.unavailable(requestId, RETRY_AFTER_SECONDS);
        }
        changed.run();
        audit.emit(namedEvent(requestId, serverId, kind, name).userWithoutClient(administrator).reason("kill_switch_set").outcome("ok"));
        return answers.noContent(requestId);
    }

    private ResponseEntity<String> deleteNamed(String serverId, PrimitiveKind kind, String name, Jwt token, HttpServletRequest request) {
        String requestId = AdminResponses.requestId(request);
        if (!administrator(token)) {
            return answers.error(HttpStatus.FORBIDDEN, requestId, "access_denied", null, null);
        }
        if (!mfa.fresh(token)) {
            mfa.refused(token, requestId, kind == PrimitiveKind.PROMPT ? "deletePromptKillSwitch" : "deleteResourceKillSwitch");
            return answers.error(HttpStatus.UNAUTHORIZED, requestId, "step_up_required", null, null);
        }
        // The switch of an entry that left the manifest can still be lifted: the address is checked, the name is not looked up.
        if (!SERVER_ID.matcher(serverId).matches() || !validName(name)) {
            return answers.error(HttpStatus.BAD_REQUEST, requestId, "invalid_request", null, null);
        }
        if (servers.find(serverId).isEmpty()) {
            return answers.error(HttpStatus.NOT_FOUND, requestId, "not_found_or_denied", null, null);
        }
        GatewayUser administrator = GatewayUser.from(token);
        try {
            store.deleteNamed(serverId, switchKind(kind), name);
        } catch (DataAccessException e) {
            log.error("emergency switch of {} not lifted: {}", serverId, e.getClass().getName());
            return answers.unavailable(requestId, RETRY_AFTER_SECONDS);
        }
        changed.run();
        audit.emit(namedEvent(requestId, serverId, kind, name).userWithoutClient(administrator).reason("kill_switch_cleared").outcome("ok"));
        return answers.noContent(requestId);
    }

    private AuditEvent namedEvent(String requestId, String serverId, PrimitiveKind kind, String name) {
        AuditEvent event = AuditEvent.of("admin_change", requestId, componentId).server(serverId);
        return kind == PrimitiveKind.PROMPT ? event.prompt(name) : event.resourceTemplate(name);
    }

    /** The value of {@code kill_switches_primitive.kind}: templates are covered by the switch of their name, like static resources. */
    private static String switchKind(PrimitiveKind kind) {
        return kind == PrimitiveKind.PROMPT ? "prompt" : "resource";
    }

    private static boolean validName(String name) {
        return name.length() <= 64 && TOOL_NAME.matcher(name).matches();
    }

    /** A resource switch is for a name the registry has as a static resource or as a template, in any state; a prompt switch for a prompt. */
    private boolean knowsEntry(String serverId, PrimitiveKind kind, String name) {
        RegisteredServer registered = registry.registered(serverId).orElse(null);
        if (registered == null) {
            return false;
        }
        return kind == PrimitiveKind.PROMPT ? registered.entries(PrimitiveKind.PROMPT).containsKey(name)
                : registered.entries(PrimitiveKind.RESOURCE).containsKey(name)
                || registered.entries(PrimitiveKind.RESOURCE_TEMPLATE).containsKey(name);
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
        Optional<String> reason = KillSwitchReason.parse(json, request.getInputStream().readNBytes(2049));
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

    private static boolean administrator(Jwt token) {
        return token != null && GatewayUser.from(token).hasGroup(RegistryController.ADMIN_GROUP);
    }
}
