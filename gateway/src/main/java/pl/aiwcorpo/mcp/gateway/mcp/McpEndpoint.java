package pl.aiwcorpo.mcp.gateway.mcp;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

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
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import io.micrometer.core.instrument.MeterRegistry;
import jakarta.servlet.http.HttpServletRequest;
import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.config.GatewayProperties;
import pl.aiwcorpo.mcp.gateway.edge.JsonErrorController;
import pl.aiwcorpo.mcp.gateway.jwt.UuidV7;
import pl.aiwcorpo.mcp.gateway.ratelimit.RateLimiter;
import pl.aiwcorpo.mcp.gateway.ratelimit.RateLimitResponse;
import pl.aiwcorpo.mcp.gateway.server.ServerRegistry;
import pl.aiwcorpo.mcp.gateway.upstream.UpstreamSessions;
import pl.aiwcorpo.mcp.gateway.virtual.VirtualServerService;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * Client side of the gateway: Streamable HTTP on {@code /s/<serverId>/mcp} and {@code /v/<slug>/mcp} (C5) for
 * modern clients (2026-07-28, per-request {@code _meta}, no sessions) and legacy clients (2025-03-26 ..
 * 2025-11-25, initialize and Mcp-Session-Id bound to the token's sub). Responses are always application/json,
 * errors included. Every request gets a UUIDv7 requestId, returned in {@code X-Request-Id}. A link belongs to
 * its owner: anyone else gets the 404 of a missing slug.
 */
@RestController
public class McpEndpoint {

    private static final Logger log = LoggerFactory.getLogger(McpEndpoint.class);
    private static final int MAX_BODY = 1024 * 1024;
    private static final String META_VERSION = "io.modelcontextprotocol/protocolVersion";
    private static final String META_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities";
    private static final String META_SERVER_INFO = "io.modelcontextprotocol/serverInfo";

    private enum Kind { SERVER, VIRTUAL }

    private final ServerRegistry servers;
    private final VirtualServerService virtualServers;
    private final McpGatewayService service;
    private final ClientSessionStore sessions;
    private final UpstreamSessions upstream;
    private final JsonMapper json;
    private final MeterRegistry meters;
    private final List<String> allowedOrigins;
    private final String name;
    private final String version;

    public McpEndpoint(ServerRegistry servers, VirtualServerService virtualServers, McpGatewayService service,
                       ClientSessionStore sessions, UpstreamSessions upstream, JsonMapper json, MeterRegistry meters,
                       GatewayProperties properties) {
        this.servers = servers;
        this.virtualServers = virtualServers;
        this.service = service;
        this.sessions = sessions;
        this.upstream = upstream;
        this.json = json;
        this.meters = meters;
        this.allowedOrigins = properties.allowedOrigins();
        this.name = properties.componentId();
        this.version = properties.version();
    }

    @PostMapping("/s/{serverId}/mcp")
    public ResponseEntity<String> post(@PathVariable String serverId, @AuthenticationPrincipal Jwt token,
                                       HttpServletRequest request) throws IOException {
        return post(Kind.SERVER, serverId, token, request);
    }

    @PostMapping("/v/{slug}/mcp")
    public ResponseEntity<String> postVirtual(@PathVariable String slug, @AuthenticationPrincipal Jwt token,
                                              HttpServletRequest request) throws IOException {
        return post(Kind.VIRTUAL, slug, token, request);
    }

    private ResponseEntity<String> post(Kind kind, String endpointId, Jwt token, HttpServletRequest request)
            throws IOException {
        String requestId = UuidV7.next();
        GatewayUser user = GatewayUser.from(token);
        Optional<Target> target;
        try {
            target = resolve(kind, endpointId, user);
        } catch (DataAccessException e) {
            log.error("virtual server lookup failed rid={}: {}", requestId, e.getClass().getName());
            return error(HttpStatus.SERVICE_UNAVAILABLE, requestId, null, -32603, "Virtual servers are unavailable.", null, false);
        }
        if (target.isEmpty()) {
            return plain(HttpStatus.NOT_FOUND, requestId);
        }
        if (!originAllowed(request)) {
            return plain(HttpStatus.FORBIDDEN, requestId);
        }
        byte[] body = request.getInputStream().readNBytes(MAX_BODY + 1);
        if (body.length > MAX_BODY) {
            return error(HttpStatus.PAYLOAD_TOO_LARGE, requestId, null, -32600, "Request too large.", null, false);
        }
        JsonNode message;
        try {
            message = json.readTree(body);
        } catch (JacksonException e) {
            return error(HttpStatus.BAD_REQUEST, requestId, null, -32700, "Parse error.", null, false);
        }
        if (message == null || !message.isObject() || !"2.0".equals(message.path("jsonrpc").asString(null))
                || !message.path("method").isString()) {
            return error(HttpStatus.BAD_REQUEST, requestId, null, -32600,
                    "Expected a single JSON-RPC request or notification.", null, false);
        }
        String method = message.get("method").asString();
        JsonNode id = message.get("id");
        String clientRequestId = request.getHeader("X-Request-Id");
        JsonNode meta = message.path("params").path("_meta");

        if (!"tools/call".equals(method)) {
            Optional<RateLimiter.Limited> limited = service.limitRequest(user, target.get(), requestId, clientRequestId);
            if (limited.isPresent()) {
                return limited.get().unavailable() ? RateLimitResponse.unavailable(requestId, limited.get().retryAfterSeconds())
                        : RateLimitResponse.of(requestId, limited.get().retryAfterSeconds());
            }
        }
        if ("initialize".equals(method)) {
            return initialize(target.get(), user, message, requestId);
        }
        if (meta.has(META_VERSION)) {
            return modern(target.get(), user, message, meta, request, requestId, clientRequestId);
        }
        return legacy(target.get(), user, message, request, requestId, clientRequestId, method, id);
    }

    @GetMapping({"/s/{serverId}/mcp", "/v/{slug}/mcp"})
    public ResponseEntity<String> get(HttpServletRequest request) {
        if (!originAllowed(request)) {
            return plain(HttpStatus.FORBIDDEN, UuidV7.next());
        }
        // No standalone SSE stream: legacy clients may get 405 (2025-03-26+), modern ones must (2026-07-28).
        return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED).header(HttpHeaders.ALLOW, "POST, DELETE")
                .contentType(MediaType.APPLICATION_JSON).body(JsonErrorController.body(405));
    }

    @DeleteMapping("/s/{serverId}/mcp")
    public ResponseEntity<String> delete(@PathVariable String serverId, @AuthenticationPrincipal Jwt token,
                                         HttpServletRequest request) {
        return delete(Kind.SERVER, serverId, token, request);
    }

    @DeleteMapping("/v/{slug}/mcp")
    public ResponseEntity<String> deleteVirtual(@PathVariable String slug, @AuthenticationPrincipal Jwt token,
                                                HttpServletRequest request) {
        return delete(Kind.VIRTUAL, slug, token, request);
    }

    private ResponseEntity<String> delete(Kind kind, String id, Jwt token, HttpServletRequest request) {
        String requestId = UuidV7.next();
        String sessionId = request.getHeader("Mcp-Session-Id");
        GatewayUser user = GatewayUser.from(token);
        Optional<Target> target;
        try {
            target = resolve(kind, id, user);
        } catch (DataAccessException e) {
            log.error("virtual server lookup failed rid={}: {}", requestId, e.getClass().getName());
            return plain(HttpStatus.SERVICE_UNAVAILABLE, requestId);
        }
        if (target.isEmpty()) {
            return plain(HttpStatus.NOT_FOUND, requestId);
        }
        if (!originAllowed(request)) {
            return plain(HttpStatus.FORBIDDEN, requestId);
        }
        if (sessionId == null) {
            return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED).header(HttpHeaders.ALLOW, "POST")
                    .header("X-Request-Id", requestId).contentType(MediaType.APPLICATION_JSON)
                    .body(JsonErrorController.body(405));
        }
        Optional<ClientSession> session = sessions.find(sessionId).filter(s -> s.sub().equals(user.sub()));
        if (session.isEmpty()) {
            return plain(HttpStatus.NOT_FOUND, requestId);
        }
        sessions.delete(sessionId);
        upstream.close(legacyConversation(user, sessionId, null), user, requestId, target.get().virtualSlug());
        return plain(HttpStatus.NO_CONTENT, requestId);
    }

    private Optional<Target> resolve(Kind kind, String id, GatewayUser user) {
        return switch (kind) {
            case SERVER -> servers.find(id).map(Target::of);
            case VIRTUAL -> virtualServers.usableBy(user, id).map(Target::of);
        };
    }

    private ResponseEntity<String> initialize(Target target, GatewayUser user, JsonNode message, String requestId) {
        JsonNode id = message.get("id");
        if (id == null || id.isNull()) {
            return error(HttpStatus.BAD_REQUEST, requestId, null, -32600, "initialize must be a request.", null, false);
        }
        String negotiated = ProtocolVersions.negotiateLegacy(message.path("params").path("protocolVersion").asString(""));
        ClientSession session = sessions.create(user.sub(), user.client(), negotiated);
        ObjectNode result = json.createObjectNode();
        result.put("protocolVersion", negotiated);
        result.putObject("capabilities").putObject("tools").put("listChanged", false);
        result.putObject("serverInfo").put("name", name + "/" + target.label()).put("version", version);
        count("initialize", false);
        return ResponseEntity.ok().header("Mcp-Session-Id", session.id()).header("X-Request-Id", requestId)
                .contentType(MediaType.APPLICATION_JSON).body(result(id, result, false));
    }

    private ResponseEntity<String> legacy(Target target, GatewayUser user, JsonNode message, HttpServletRequest request,
                                          String requestId, String clientRequestId, String method, JsonNode id) {
        String headerVersion = request.getHeader("MCP-Protocol-Version");
        if (headerVersion != null && ProtocolVersions.isModern(headerVersion)) {
            return error(HttpStatus.BAD_REQUEST, requestId, id, -32602,
                    "Missing _meta " + META_VERSION + " for protocol " + headerVersion + ".", null, false);
        }
        String sessionId = request.getHeader("Mcp-Session-Id");
        if (sessionId == null) {
            return error(HttpStatus.BAD_REQUEST, requestId, id, -32600,
                    "Missing Mcp-Session-Id: initialize first, or send per-request _meta (" + ProtocolVersions.MODERN + ").",
                    null, false);
        }
        Optional<ClientSession> session = sessions.find(sessionId).filter(s -> s.sub().equals(user.sub()));
        if (session.isEmpty()) {
            // Unknown, expired, or belonging to another user: indistinguishable on purpose; the client re-initializes.
            return plain(HttpStatus.NOT_FOUND, requestId);
        }
        String version = session.get().protocolVersion();
        if (headerVersion != null && !headerVersion.equals(version)) {
            return error(HttpStatus.BAD_REQUEST, requestId, id, -32600,
                    "MCP-Protocol-Version does not match the session.", null, false);
        }
        if (id == null) {
            return plain(HttpStatus.ACCEPTED, requestId);
        }
        CallContext ctx = new CallContext(requestId, clientRequestId, user, target, version,
                legacyConversation(user, sessionId, target));
        return dispatch(ctx, message, method, id, false);
    }

    private ResponseEntity<String> modern(Target target, GatewayUser user, JsonNode message, JsonNode meta,
                                          HttpServletRequest request, String requestId, String clientRequestId) {
        String method = message.get("method").asString();
        JsonNode id = message.get("id");
        String bodyVersion = meta.path(META_VERSION).asString(null);
        String headerVersion = request.getHeader("MCP-Protocol-Version");
        if (bodyVersion == null || headerVersion == null || !headerVersion.equals(bodyVersion)) {
            return error(HttpStatus.BAD_REQUEST, requestId, id, -32020,
                    "Header mismatch: MCP-Protocol-Version must equal _meta " + META_VERSION + ".", null, true);
        }
        if (!ProtocolVersions.isModern(bodyVersion)) {
            ObjectNode data = json.createObjectNode();
            data.set("supported", json.valueToTree(ProtocolVersions.ALL));
            data.put("requested", bodyVersion);
            return error(HttpStatus.BAD_REQUEST, requestId, id, -32022, "Unsupported protocol version", data, true);
        }
        if (!meta.path(META_CAPABILITIES).isObject()) {
            return error(HttpStatus.BAD_REQUEST, requestId, id, -32602,
                    "Missing _meta " + META_CAPABILITIES + ".", null, true);
        }
        if (!method.equals(request.getHeader("Mcp-Method"))) {
            return error(HttpStatus.BAD_REQUEST, requestId, id, -32020,
                    "Header mismatch: Mcp-Method must equal the request method.", null, true);
        }
        if ("tools/call".equals(method)) {
            String bodyName = message.path("params").path("name").asString(null);
            String headerName = decodeHeaderValue(request.getHeader("Mcp-Name"));
            if (bodyName == null || !bodyName.equals(headerName)) {
                return error(HttpStatus.BAD_REQUEST, requestId, id, -32020,
                        "Header mismatch: Mcp-Name must equal params.name.", null, true);
            }
        }
        if (id == null) {
            return plain(HttpStatus.ACCEPTED, requestId);
        }
        CallContext ctx = new CallContext(requestId, clientRequestId, user, target, bodyVersion,
                "m|" + user.sub() + "|" + user.client() + "|" + target.label());
        if ("server/discover".equals(method)) {
            count(method, true);
            ObjectNode result = json.createObjectNode();
            result.set("supportedVersions", json.valueToTree(ProtocolVersions.ALL));
            result.putObject("capabilities").putObject("tools");
            return ok(requestId, result(id, result, true));
        }
        return dispatch(ctx, message, method, id, true);
    }

    private ResponseEntity<String> dispatch(CallContext ctx, JsonNode message, String method, JsonNode id, boolean modern) {
        count(method, modern);
        try {
            ObjectNode result = switch (method) {
                case "ping" -> json.createObjectNode();
                case "tools/list" -> service.listTools(ctx);
                case "tools/call" -> service.callTool(ctx, message.path("params"));
                default -> null;
            };
            if (result == null) {
                return error(modern ? HttpStatus.NOT_FOUND : HttpStatus.OK, ctx.requestId(), id, -32601,
                        "Method not found", null, modern);
            }
            return ok(ctx.requestId(), result(id, result, modern));
        } catch (RpcFailure failure) {
            HttpStatus status = modern && failure.httpStatus() == 400 ? HttpStatus.BAD_REQUEST : HttpStatus.OK;
            return error(status, ctx.requestId(), id, failure.code(), failure.getMessage(), null, modern);
        }
    }

    private String result(JsonNode id, ObjectNode result, boolean modern) {
        if (modern) {
            result.put("resultType", "complete");
            result.putObject("_meta").putObject(META_SERVER_INFO).put("name", name).put("version", version);
        }
        ObjectNode response = json.createObjectNode();
        response.put("jsonrpc", "2.0");
        response.set("id", id);
        response.set("result", result);
        return json.writeValueAsString(response);
    }

    private ResponseEntity<String> error(HttpStatus status, String requestId, JsonNode id, int code, String message,
                                         JsonNode data, boolean modern) {
        ObjectNode response = json.createObjectNode();
        response.put("jsonrpc", "2.0");
        if (id != null) {
            response.set("id", id);
        }
        ObjectNode error = response.putObject("error");
        error.put("code", code);
        error.put("message", message);
        if (data != null) {
            error.set("data", data);
        }
        return ResponseEntity.status(status).header("X-Request-Id", requestId).contentType(MediaType.APPLICATION_JSON)
                .body(json.writeValueAsString(response));
    }

    private static ResponseEntity<String> ok(String requestId, String body) {
        return ResponseEntity.ok().header("X-Request-Id", requestId).contentType(MediaType.APPLICATION_JSON).body(body);
    }

    private static ResponseEntity<String> plain(HttpStatus status, String requestId) {
        ResponseEntity.BodyBuilder builder = ResponseEntity.status(status).header("X-Request-Id", requestId);
        if (status.value() < 400) {
            return builder.build();
        }
        return builder.contentType(MediaType.APPLICATION_JSON).body(JsonErrorController.body(status.value()));
    }

    private boolean originAllowed(HttpServletRequest request) {
        String origin = request.getHeader(HttpHeaders.ORIGIN);
        return origin == null || allowedOrigins.contains(origin);
    }

    private void count(String method, boolean modern) {
        String tag = switch (method) {
            case "initialize", "ping", "tools/list", "tools/call", "server/discover" -> method;
            default -> "other";
        };
        meters.counter("mcp.gateway.requests", "method", tag, "era", modern ? "modern" : "legacy").increment();
    }

    /**
     * Upstream sessions are per endpoint: a server that keeps something from {@code initialize} (the link's
     * {@code vs} and {@code vsc}) must never apply it to calls that came through another link or through /s/.
     * A null target gives the prefix shared by every endpoint of the session (used to close them all).
     */
    private static String legacyConversation(GatewayUser user, String sessionId, Target target) {
        String prefix = "l|" + user.sub() + "|" + sessionId + "|";
        return target == null ? prefix : prefix + target.label();
    }

    /** Mcp-Name may use the Base64 sentinel {@code =?base64?...?=} (2026-07-28 transport). */
    static String decodeHeaderValue(String value) {
        if (value == null) {
            return null;
        }
        if (value.startsWith("=?base64?") && value.endsWith("?=") && value.length() >= 11) {
            try {
                return new String(Base64.getDecoder().decode(value.substring(9, value.length() - 2)), StandardCharsets.UTF_8);
            } catch (IllegalArgumentException e) {
                return null;
            }
        }
        return value;
    }
}
