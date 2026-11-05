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
import jakarta.servlet.http.HttpServletResponse;
import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.config.GatewayProperties;
import pl.aiwcorpo.mcp.gateway.edge.ConcurrencyLimitFilter;
import pl.aiwcorpo.mcp.gateway.edge.JsonErrorController;
import pl.aiwcorpo.mcp.gateway.stream.ToolStreams;
import pl.aiwcorpo.mcp.gateway.jwt.UuidV7;
import pl.aiwcorpo.mcp.gateway.ratelimit.RateLimiter;
import pl.aiwcorpo.mcp.gateway.ratelimit.RateLimitResponse;
import pl.aiwcorpo.mcp.gateway.server.ServerRegistry;
import pl.aiwcorpo.mcp.gateway.upstream.UpstreamSessions;
import pl.aiwcorpo.mcp.manifest.EndpointFilter;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * Client side of the gateway: Streamable HTTP on {@code /mcp} (every system) and {@code /s/<serverId>/mcp} (one system), both with an
 * optional filter in the query (CC-170), for modern clients (2026-07-28, per-request {@code _meta}, no sessions) and legacy clients
 * (2025-03-26 .. 2025-11-25, initialize and Mcp-Session-Id bound to the token's sub, the route and the filter). Responses are always
 * application/json, errors included. Every request gets a UUIDv7 requestId, returned in {@code X-Request-Id}. The order of the
 * checks is the one of CC-184: token (the security chain), syntax of the query, then the session (owner, route, filter).
 */
@RestController
public class McpEndpoint {

    private static final Logger log = LoggerFactory.getLogger(McpEndpoint.class);
    private static final int MAX_BODY = 1024 * 1024;
    private static final String META_VERSION = "io.modelcontextprotocol/protocolVersion";
    private static final String META_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities";
    private static final String META_SERVER_INFO = "io.modelcontextprotocol/serverInfo";
    private static final java.util.regex.Pattern EVENT_STREAM = java.util.regex.Pattern.compile("(^|,)\\s*text/event-stream\\s*(;|,|$)");
    private static final String INVALID_FILTER_BODY = "{\"error\":\"invalid_request\",\"reason\":\"invalid_filter\","
            + "\"message\":\"The query of the address is not a valid filter.\"}";

    private final ServerRegistry servers;
    private final McpGatewayService service;
    private final ClientSessionStore sessions;
    private final UpstreamSessions upstream;
    private final JsonMapper json;
    private final MeterRegistry meters;
    private final List<String> allowedOrigins;
    private final String name;
    private final String version;
    private final int sessionStoreRetryAfter;
    private final int shedRetryAfter;
    private final ToolStreams streams;

    public McpEndpoint(ServerRegistry servers, McpGatewayService service, ClientSessionStore sessions, UpstreamSessions upstream,
                       JsonMapper json, MeterRegistry meters, GatewayProperties properties, ToolStreams streams) {
        this.servers = servers;
        this.service = service;
        this.sessions = sessions;
        this.upstream = upstream;
        this.json = json;
        this.meters = meters;
        this.allowedOrigins = properties.allowedOrigins();
        this.name = properties.componentId();
        this.version = properties.version();
        this.sessionStoreRetryAfter = properties.mcp().sessionStoreRetryAfterSeconds();
        this.shedRetryAfter = properties.mcp().shedRetryAfterSeconds();
        this.streams = streams;
    }

    @PostMapping("/mcp")
    public ResponseEntity<String> postAggregate(@AuthenticationPrincipal Jwt token, HttpServletRequest request,
                                                HttpServletResponse response) throws IOException {
        return post(Optional.of(Target.aggregate()), token, request, response);
    }

    @PostMapping("/s/{serverId}/mcp")
    public ResponseEntity<String> post(@PathVariable String serverId, @AuthenticationPrincipal Jwt token,
                                       HttpServletRequest request, HttpServletResponse response) throws IOException {
        return post(servers.find(serverId).map(Target::of), token, request, response);
    }

    private ResponseEntity<String> post(Optional<Target> addressed, Jwt token, HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String requestId = UuidV7.next();
        try {
            return post(addressed, token, request, response, requestId);
        } catch (DataAccessException failure) {
            return stateStoreUnavailable(GatewayUser.from(token), requestId, request.getHeader("X-Request-Id"), failure);
        }
    }

    private ResponseEntity<String> post(Optional<Target> addressed, Jwt token, HttpServletRequest request, HttpServletResponse response,
                                        String requestId) throws IOException {
        GatewayUser user = GatewayUser.from(token);
        if (addressed.isEmpty()) {
            return plain(HttpStatus.NOT_FOUND, requestId);
        }
        Target target = addressed.get();
        if (!originAllowed(request)) {
            return plain(HttpStatus.FORBIDDEN, requestId);
        }
        String clientRequestId = request.getHeader("X-Request-Id");
        EndpointFilter filter;
        try {
            filter = filterOf(request, target);
        } catch (EndpointFilter.Invalid invalid) {
            return invalidFilter(user, requestId, clientRequestId, invalid, request.getQueryString());
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
        JsonNode meta = message.path("params").path("_meta");

        // A request that names a session is a session request whatever _meta says (CC-184).
        String sessionId = request.getHeader("Mcp-Session-Id");
        Optional<ClientSession> session = Optional.empty();
        if (!"initialize".equals(method) && sessionId != null) {
            session = sessions.find(sessionId);
            ResponseEntity<String> refused = refuseSession(user, target, filter, session, requestId, clientRequestId);
            if (refused != null) {
                return refused;
            }
            // A token with other groups than the stream of this session holds: the list of the stream is computed with the new ones.
            streams.refreshUser(sessionId, user);
        }
        if (!"tools/call".equals(method)) {
            Optional<RateLimiter.Limited> limited = service.limitRequest(user, filter, requestId, clientRequestId);
            if (limited.isPresent()) {
                return limited.get().unavailable() ? RateLimitResponse.unavailable(requestId, limited.get().retryAfterSeconds())
                        : RateLimitResponse.of(requestId, limited.get().retryAfterSeconds());
            }
        }
        if ("initialize".equals(method)) {
            return initialize(target, filter, user, message, requestId);
        }
        if (meta.has(META_VERSION)) {
            return modern(target, filter, user, token, message, meta, request, response, requestId, clientRequestId);
        }
        return legacy(target, filter, user, message, request, session, requestId, clientRequestId, method, id);
    }

    /**
     * The stream of a legacy session (CC-192): {@code GET} with {@code Mcp-Session-Id} and {@code Accept: text/event-stream}. The token was
     * checked before; then, as for any request of a session (CC-184), the syntax of the query (400), the owner of the session, its
     * route and its filter (404, {@code filter_mismatch} for the last two). Without a session or without that {@code Accept} it is 405:
     * the stateless protocol opens its stream with {@code subscriptions/listen}.
     */
    @GetMapping({"/mcp", "/s/{serverId}/mcp"})
    public ResponseEntity<String> get(@PathVariable(required = false) String serverId, @AuthenticationPrincipal Jwt token,
                                      HttpServletRequest request, HttpServletResponse response) throws IOException {
        String requestId = UuidV7.next();
        Optional<Target> addressed = serverId == null ? Optional.of(Target.aggregate()) : servers.find(serverId).map(Target::of);
        try {
            return openStream(addressed, token, request, response, requestId);
        } catch (DataAccessException failure) {
            return stateStoreUnavailable(GatewayUser.from(token), requestId, request.getHeader("X-Request-Id"), failure);
        }
    }

    private ResponseEntity<String> openStream(Optional<Target> addressed, Jwt token, HttpServletRequest request, HttpServletResponse response,
                                              String requestId) throws IOException {
        GatewayUser user = GatewayUser.from(token);
        if (addressed.isEmpty()) {
            return plain(HttpStatus.NOT_FOUND, requestId);
        }
        Target target = addressed.get();
        if (!originAllowed(request)) {
            return plain(HttpStatus.FORBIDDEN, requestId);
        }
        String sessionId = request.getHeader("Mcp-Session-Id");
        if (sessionId == null || !EVENT_STREAM.matcher(String.valueOf(request.getHeader(HttpHeaders.ACCEPT))).find()) {
            return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED).header(HttpHeaders.ALLOW, "POST, DELETE, GET")
                    .header("X-Request-Id", requestId).contentType(MediaType.APPLICATION_JSON).body(JsonErrorController.body(405));
        }
        String clientRequestId = request.getHeader("X-Request-Id");
        EndpointFilter filter;
        try {
            filter = filterOf(request, target);
        } catch (EndpointFilter.Invalid invalid) {
            return invalidFilter(user, requestId, clientRequestId, invalid, request.getQueryString());
        }
        Optional<ClientSession> session = sessions.find(sessionId);
        ResponseEntity<String> refused = refuseSession(user, target, filter, session, requestId, clientRequestId);
        if (refused != null) {
            return refused;
        }
        // Opening a stream is a request like the others for the limits of the user and of the client (CC-135); the stream itself is not limited per user.
        Optional<RateLimiter.Limited> limited = service.limitRequest(user, filter, requestId, clientRequestId);
        if (limited.isPresent()) {
            return limited.get().unavailable() ? RateLimitResponse.unavailable(requestId, limited.get().retryAfterSeconds())
                    : RateLimitResponse.of(requestId, limited.get().retryAfterSeconds());
        }
        Optional<ToolStreams.Stream> opened = streams.open(ToolStreams.Kind.SESSION, user, sessionId, filter, target.routeSystem(), token.getExpiresAt(), null, true);
        if (opened.isEmpty()) {
            return RateLimitResponse.overloaded(requestId, shedRetryAfter);
        }
        count("GET", false);
        try {
            startEventStream(response, requestId);
            opened.get().serve(response.getOutputStream());
        } finally {
            opened.get().release();
        }
        return null;
    }

    /**
     * {@code subscriptions/listen} of the stateless protocol (CC-192, CC-206, CC-207): no session, the stream is bound to the filter of this
     * request, which was parsed before (400) and has nothing to be compared with. It gives its place in the limit of requests back as soon as it is
     * known to be a stream. The first message is the acknowledgement with the subset of the filter of the client that the gateway honours.
     */
    private ResponseEntity<String> listen(HttpServletRequest request, HttpServletResponse response, Jwt token, GatewayUser user,
                                          Target target, EndpointFilter filter, JsonNode message, JsonNode id, String requestId) {
        boolean tools = message.path("params").path("notifications").path("toolsListChanged").asBoolean(false);
        Optional<ToolStreams.Stream> opened = streams.open(ToolStreams.Kind.LISTEN, user, null, filter, target.routeSystem(), token.getExpiresAt(), id, tools);
        if (opened.isEmpty()) {
            return RateLimitResponse.overloaded(requestId, shedRetryAfter);
        }
        if (request.getAttribute(ConcurrencyLimitFilter.RELEASE_ATTRIBUTE) instanceof Runnable release) {
            release.run();
        }
        try {
            startEventStream(response, requestId);
            opened.get().serve(response.getOutputStream());
        } catch (IOException e) {
            log.debug("rid={}: the stream could not be started: {}", requestId, e.getClass().getName());
        } finally {
            opened.get().release();
        }
        return null;
    }

    private static void startEventStream(HttpServletResponse response, String requestId) throws IOException {
        response.setStatus(HttpStatus.OK.value());
        response.setContentType("text/event-stream");
        response.setCharacterEncoding("UTF-8");
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        // nginx: no buffering of this response, whatever its configuration says (the stream has to reach the client as it is written).
        response.setHeader("X-Accel-Buffering", "no");
        response.setHeader("X-Request-Id", requestId);
        response.flushBuffer();
    }

    @DeleteMapping("/mcp")
    public ResponseEntity<String> deleteAggregate(@AuthenticationPrincipal Jwt token, HttpServletRequest request) {
        return delete(Optional.of(Target.aggregate()), token, request);
    }

    @DeleteMapping("/s/{serverId}/mcp")
    public ResponseEntity<String> delete(@PathVariable String serverId, @AuthenticationPrincipal Jwt token,
                                         HttpServletRequest request) {
        return delete(servers.find(serverId).map(Target::of), token, request);
    }

    private ResponseEntity<String> delete(Optional<Target> addressed, Jwt token, HttpServletRequest request) {
        String requestId = UuidV7.next();
        try {
            return delete(addressed, token, request, requestId);
        } catch (DataAccessException failure) {
            return stateStoreUnavailable(GatewayUser.from(token), requestId, request.getHeader("X-Request-Id"), failure);
        }
    }

    private ResponseEntity<String> delete(Optional<Target> addressed, Jwt token, HttpServletRequest request, String requestId) {
        String sessionId = request.getHeader("Mcp-Session-Id");
        GatewayUser user = GatewayUser.from(token);
        if (addressed.isEmpty()) {
            return plain(HttpStatus.NOT_FOUND, requestId);
        }
        Target target = addressed.get();
        if (!originAllowed(request)) {
            return plain(HttpStatus.FORBIDDEN, requestId);
        }
        String clientRequestId = request.getHeader("X-Request-Id");
        EndpointFilter filter;
        try {
            filter = filterOf(request, target);
        } catch (EndpointFilter.Invalid invalid) {
            return invalidFilter(user, requestId, clientRequestId, invalid, request.getQueryString());
        }
        if (sessionId == null) {
            return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED).header(HttpHeaders.ALLOW, "POST")
                    .header("X-Request-Id", requestId).contentType(MediaType.APPLICATION_JSON)
                    .body(JsonErrorController.body(405));
        }
        Optional<ClientSession> session = sessions.find(sessionId);
        ResponseEntity<String> refused = refuseSession(user, target, filter, session, requestId, clientRequestId);
        if (refused != null) {
            return refused;
        }
        sessions.delete(sessionId);
        streams.closeSession(sessionId);
        upstream.close(legacyConversation(user, sessionId, null), user, requestId);
        return plain(HttpStatus.NO_CONTENT, requestId);
    }

    /** Redis holds the sessions: when it does not answer nothing is guessed, the request is refused (fail-closed) and the refusal is audited. */
    private ResponseEntity<String> stateStoreUnavailable(GatewayUser user, String requestId, String clientRequestId,
                                                         org.springframework.dao.DataAccessException failure) {
        log.error("session store unavailable rid={}: {}", requestId, failure.getClass().getName());
        meters.counter("mcp.gateway.requests.store_unavailable").increment();
        service.auditRefusedRequest(user, requestId, clientRequestId, "upstream_unavailable", "error", null, null);
        return RateLimitResponse.sessionStoreUnavailable(requestId, sessionStoreRetryAfter);
    }

    /** The filter of the query as the client wrote it, not decoded: a {@code %} is not part of its alphabet (CC-170). */
    private static EndpointFilter filterOf(HttpServletRequest request, Target target) {
        EndpointFilter filter = EndpointFilter.parse(request.getQueryString());
        filter.checkRoute(target.routeSystem());
        return filter;
    }

    private ResponseEntity<String> invalidFilter(GatewayUser user, String requestId, String clientRequestId,
                                                 EndpointFilter.Invalid invalid, String rawQuery) {
        log.debug("rid={}: the query is not a filter ({})", requestId, invalid.cause());
        service.auditRefusedRequest(user, requestId, clientRequestId, "invalid_filter", "error", null, rawQuery);
        meters.counter("mcp.gateway.requests.invalid_filter").increment();
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).header("X-Request-Id", requestId)
                .contentType(MediaType.APPLICATION_JSON).body(INVALID_FILTER_BODY);
    }

    /** Null when the session is the caller's, on this route, with this filter; else the 404 of an unknown session. */
    private ResponseEntity<String> refuseSession(GatewayUser user, Target target, EndpointFilter filter,
                                                 Optional<ClientSession> session, String requestId, String clientRequestId) {
        SessionCheck.Result result = SessionCheck.check(user.sub(), target.route(), filter.canonical(), session);
        if (result == SessionCheck.Result.MISMATCH) {
            service.auditRefusedRequest(user, requestId, clientRequestId, "filter_mismatch", "denied",
                    filter.isEmpty() ? null : filter.canonical(), target.route() + "?" + filter.canonical());
        }
        return result == SessionCheck.Result.CONTINUE ? null : plain(HttpStatus.NOT_FOUND, requestId);
    }

    private ResponseEntity<String> initialize(Target target, EndpointFilter filter, GatewayUser user, JsonNode message, String requestId) {
        JsonNode id = message.get("id");
        if (id == null || id.isNull()) {
            return error(HttpStatus.BAD_REQUEST, requestId, null, -32600, "initialize must be a request.", null, false);
        }
        String negotiated = ProtocolVersions.negotiateLegacy(message.path("params").path("protocolVersion").asString(""));
        ClientSession session = sessions.create(user.sub(), user.client(), negotiated, target.route(), filter.canonical());
        ObjectNode result = json.createObjectNode();
        result.put("protocolVersion", negotiated);
        result.putObject("capabilities").putObject("tools").put("listChanged", true);
        result.putObject("serverInfo").put("name", name).put("version", version);
        count("initialize", false);
        return ResponseEntity.ok().header("Mcp-Session-Id", session.id()).header("X-Request-Id", requestId)
                .contentType(MediaType.APPLICATION_JSON).body(result(id, result, false));
    }

    private ResponseEntity<String> legacy(Target target, EndpointFilter filter, GatewayUser user, JsonNode message,
                                          HttpServletRequest request, Optional<ClientSession> session, String requestId,
                                          String clientRequestId, String method, JsonNode id) {
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
        String version = session.orElseThrow().protocolVersion();
        if (headerVersion != null && !headerVersion.equals(version)) {
            return error(HttpStatus.BAD_REQUEST, requestId, id, -32600,
                    "MCP-Protocol-Version does not match the session.", null, false);
        }
        if (id == null) {
            return plain(HttpStatus.ACCEPTED, requestId);
        }
        CallContext ctx = new CallContext(requestId, clientRequestId, user, target, filter, version,
                legacyConversation(user, sessionId, target));
        return dispatch(ctx, message, method, id, false);
    }

    private ResponseEntity<String> modern(Target target, EndpointFilter filter, GatewayUser user, Jwt token, JsonNode message, JsonNode meta,
                                          HttpServletRequest request, HttpServletResponse response, String requestId, String clientRequestId) {
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
        CallContext ctx = new CallContext(requestId, clientRequestId, user, target, filter, bodyVersion,
                "m|" + user.sub() + "|" + user.client() + "|" + target.label());
        if ("server/discover".equals(method)) {
            count(method, true);
            ObjectNode result = json.createObjectNode();
            result.set("supportedVersions", json.valueToTree(ProtocolVersions.ALL));
            result.putObject("capabilities").putObject("tools").put("listChanged", true);
            return ok(requestId, result(id, result, true));
        }
        if ("subscriptions/listen".equals(method)) {
            count(method, true);
            return listen(request, response, token, user, target, filter, message, id, requestId);
        }
        return dispatch(ctx, message, method, id, true);
    }

    private ResponseEntity<String> dispatch(CallContext ctx, JsonNode message, String method, JsonNode id, boolean modern) {
        count(method, modern);
        try {
            ObjectNode result = switch (method) {
                case "ping" -> json.createObjectNode();
                case "tools/list" -> service.listTools(ctx, message.path("params").get("cursor"));
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
            case "initialize", "ping", "tools/list", "tools/call", "server/discover", "subscriptions/listen", "GET" -> method;
            default -> "other";
        };
        meters.counter("mcp.gateway.requests", "method", tag, "era", modern ? "modern" : "legacy").increment();
    }

    /**
     * Upstream sessions are per endpoint of the client session. A null target gives the prefix shared by every endpoint of the
     * session (used to close them all).
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
