package pl.aiwcorpo.mcp.testserver;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.regex.Pattern;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLPeerUnverifiedException;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsExchange;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * MCP server for gateway tests and the M1 demo in the place of mcp-jira: Streamable HTTP (2025-03-26 ..
 * 2025-11-25, sessions), mTLS with client CN mcp-gateway only, internal JWT (C2) on every HTTP request, the
 * credential from C3 forwarded to Jira, one C8 audit line per tools/call on stdout. Records every request for
 * assertions.
 */
public final class TestMcpServer implements AutoCloseable {

    public static final List<String> PROTOCOL_VERSIONS = List.of("2025-11-25", "2025-06-18", "2025-03-26");
    private static final Pattern UUID_V7 = Pattern.compile("^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$");
    private static final Pattern ISSUE_KEY = Pattern.compile("^[A-Z][A-Z0-9]{1,9}-[0-9]{1,9}$");
    private static final Pattern PROJECT_KEY = Pattern.compile("^[A-Z][A-Z0-9]{1,9}$");
    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final SecureRandom RANDOM = new SecureRandom();

    /** One HTTP request as the server saw it. Header names are lower case. */
    public record RecordedRequest(String httpMethod, Map<String, List<String>> headers, String body, String rpcMethod,
                                  String toolName, int status, String rejectReason, String sub, String sessionId) {
        public String header(String name) {
            List<String> values = headers.get(name.toLowerCase(Locale.ROOT));
            return values == null || values.isEmpty() ? null : values.getFirst();
        }
    }

    public record Config(String serverId, String path, String issuer, boolean allowTestKeys, URI jiraUrl,
                         InternalJwtVerifier.KeySource keys) {
    }

    private record Session(String sub, String protocolVersion) {
    }

    private final Config config;
    private final HttpsServer server;
    private final InternalJwtVerifier verifier;
    private final HttpClient jira;
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();
    private final List<RecordedRequest> recorded = new CopyOnWriteArrayList<>();

    public TestMcpServer(Config config, SSLContext sslContext, InetSocketAddress address) throws IOException {
        this.config = Objects.requireNonNull(config);
        this.verifier = new InternalJwtVerifier(config.issuer(), config.serverId(), config.allowTestKeys(),
                config.keys(), java.time.Clock.systemUTC());
        this.jira = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3))
                .followRedirects(HttpClient.Redirect.NEVER).build();
        this.server = HttpsServer.create(address, 0);
        server.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
            @Override
            public void configure(HttpsParameters params) {
                SSLParameters ssl = sslContext.getDefaultSSLParameters();
                ssl.setNeedClientAuth(true);
                params.setSSLParameters(ssl);
            }
        });
        server.createContext(config.path(), this::handle);
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
    }

    public TestMcpServer start() {
        server.start();
        return this;
    }

    public int port() {
        return server.getAddress().getPort();
    }

    public List<RecordedRequest> requests() {
        return List.copyOf(recorded);
    }

    public void clearRequests() {
        recorded.clear();
    }

    /** Forgets every session, as after a restart; clients must initialize again (404 on the old id). */
    public void dropSessions() {
        sessions.clear();
    }

    @Override
    public void close() {
        server.stop(0);
    }

    private void handle(HttpExchange exchange) throws IOException {
        try (exchange) {
            Map<String, List<String>> headers = lowerCase(exchange.getRequestHeaders());
            String body = new String(exchange.getRequestBody().readNBytes(1 << 20), StandardCharsets.UTF_8);
            if (!"mcp-gateway".equals(clientCommonName(exchange))) {
                record(exchange, headers, body, null, null, 403, "client_cn", null, null);
                send(exchange, 403, null, null);
                return;
            }
            switch (exchange.getRequestMethod()) {
                case "POST" -> post(exchange, headers, body);
                case "DELETE" -> delete(exchange, headers, body);
                case "GET" -> {
                    if ("/mcp-manifest".equals(exchange.getRequestURI().getPath())) {
                        manifest(exchange, headers, body);
                    } else {
                        record(exchange, headers, body, null, null, 405, null, null, null);
                        send(exchange, 405, null, null);
                    }
                }
                default -> {
                    record(exchange, headers, body, null, null, 405, null, null, null);
                    send(exchange, 405, null, null);
                }
            }
        }
    }

    private volatile Map<String, String> descriptionOverrides = Map.of();

    /** From now on {@code tools/list} describes the tool differently while the manifest stays: a server that drifted. */
    public void describeDifferently(String tool, String description) {
        Map<String, String> next = new java.util.HashMap<>(descriptionOverrides);
        next.put(tool, description);
        descriptionOverrides = Map.copyOf(next);
    }

    public void describeAsApproved() {
        descriptionOverrides = Map.of();
    }

    /** {@code GET /mcp-manifest} (C6): the definitions as they are approved, with their hashes. */
    private void manifest(HttpExchange exchange, Map<String, List<String>> headers, String body) throws IOException {
        InternalJwtVerifier.Result auth = verifier.verify(first(headers, "authorization"), first(headers, "x-request-id"),
                InternalJwtVerifier.RequestRule.forHttp("GET", "/mcp-manifest"));
        if (!auth.valid()) {
            record(exchange, headers, body, null, null, 401, auth.reason(), null, null);
            send(exchange, 401, null, null);
            return;
        }
        String system = config.serverId().replaceFirst("^mcp-", "");
        ObjectNode credential = JSON.createObjectNode();
        credential.put("required", true);
        credential.putArray("acceptedTypes").add("user-secret");
        ObjectNode manifest = JSON.createObjectNode();
        manifest.put("serverId", config.serverId());
        manifest.put("version", "1.0.0");
        manifest.put("system", system);
        manifest.put("internalUrl", "https://" + config.serverId() + ".internal:" + port() + config.path());
        manifest.set("credential", credential);
        ArrayNode types = manifest.putArray("resourceTypes");
        types.addObject().put("type", "Jira::Project").putArray("attributes").add("key");
        ObjectNode issue = types.addObject();
        issue.put("type", "Jira::Issue");
        issue.putArray("attributes").add("key");
        issue.put("parent", "Jira::Project");
        ArrayNode tools = manifest.putArray("tools");
        for (JsonNode definition : toolDefinitions(Map.of())) {
            String name = definition.path("name").asString();
            boolean destructive = "delete_issue".equals(name);
            ObjectNode entry = tools.addObject();
            entry.put("name", name);
            entry.put("risk", destructive ? "DESTRUCTIVE" : "READ_ONLY");
            entry.put("action", destructive ? "delete" : "read");
            entry.putArray("resourceRefs").addObject().put("argument", "search_issues".equals(name) ? "project" : "issueKey")
                    .put("type", "search_issues".equals(name) ? "Jira::Project" : "Jira::Issue");
            entry.set("definition", definition);
            entry.put("definitionHash", pl.aiwcorpo.mcp.manifest.DefinitionHash.compute(JSON.writeValueAsString(definition),
                    JSON.writeValueAsString(entry), system, JSON.writeValueAsString(credential)));
        }
        record(exchange, headers, body, null, null, 200, null, (String) auth.claims().get("sub"), null);
        send(exchange, 200, "application/json", JSON.writeValueAsString(manifest));
    }

    private void delete(HttpExchange exchange, Map<String, List<String>> headers, String body) throws IOException {
        String rid = first(headers, "x-request-id");
        InternalJwtVerifier.Result auth = verifier.verify(first(headers, "authorization"), rid,
                InternalJwtVerifier.RequestRule.forJsonRpc("session/delete", null));
        String sessionId = first(headers, "mcp-session-id");
        if (!auth.valid()) {
            record(exchange, headers, body, null, null, 401, auth.reason(), null, sessionId);
            send(exchange, 401, null, null);
            return;
        }
        String sub = (String) auth.claims().get("sub");
        Session session = sessionId == null ? null : sessions.get(sessionId);
        int status = session != null && session.sub().equals(sub) ? 204 : 404;
        if (status == 204) {
            sessions.remove(sessionId);
        }
        record(exchange, headers, body, null, null, status, null, sub, sessionId);
        send(exchange, status, null, null);
    }

    private void post(HttpExchange exchange, Map<String, List<String>> headers, String body) throws IOException {
        long started = System.nanoTime();
        JsonNode message;
        try {
            message = JSON.readTree(body);
        } catch (RuntimeException e) {
            record(exchange, headers, body, null, null, 400, "parse_error", null, null);
            send(exchange, 400, null, null);
            return;
        }
        String method = message.path("method").asString(null);
        String toolName = "tools/call".equals(method) ? message.path("params").path("name").asString(null) : null;
        String rid = first(headers, "x-request-id");
        InternalJwtVerifier.Result auth = verifier.verify(first(headers, "authorization"), rid,
                InternalJwtVerifier.RequestRule.forJsonRpc(method == null ? "" : method, toolName));
        String sessionId = first(headers, "mcp-session-id");
        if (!auth.valid()) {
            record(exchange, headers, body, method, toolName, 401, auth.reason(), null, sessionId);
            if ("tools/call".equals(method)) {
                audit(rid, Map.of(), toolName, "denied", "unauthenticated", started);
            }
            send(exchange, 401, null, null);
            return;
        }
        String sub = (String) auth.claims().get("sub");

        if ("initialize".equals(method)) {
            String requested = message.path("params").path("protocolVersion").asString("");
            String version = PROTOCOL_VERSIONS.contains(requested) ? requested : PROTOCOL_VERSIONS.getFirst();
            String newSession = randomId();
            sessions.put(newSession, new Session(sub, version));
            ObjectNode result = JSON.createObjectNode();
            result.put("protocolVersion", version);
            result.putObject("capabilities").putObject("tools").put("listChanged", false);
            result.putObject("serverInfo").put("name", config.serverId() + "-test").put("version", "0.1.0");
            record(exchange, headers, body, method, null, 200, null, sub, newSession);
            exchange.getResponseHeaders().add("Mcp-Session-Id", newSession);
            send(exchange, 200, "application/json", response(message.get("id"), result));
            return;
        }

        Session session = sessionId == null ? null : sessions.get(sessionId);
        if (sessionId == null) {
            record(exchange, headers, body, method, toolName, 400, "session_missing", sub, null);
            send(exchange, 400, null, null);
            return;
        }
        if (session == null || !session.sub().equals(sub)) {
            record(exchange, headers, body, method, toolName, 404, session == null ? "session_unknown" : "session_of_other_user",
                    sub, sessionId);
            send(exchange, 404, null, null);
            return;
        }
        String headerVersion = first(headers, "mcp-protocol-version");
        if (headerVersion != null && !headerVersion.equals(session.protocolVersion())) {
            record(exchange, headers, body, method, toolName, 400, "protocol_version_mismatch", sub, sessionId);
            send(exchange, 400, null, null);
            return;
        }

        if (!message.has("id")) {
            record(exchange, headers, body, method, null, 202, null, sub, sessionId);
            send(exchange, 202, null, null);
            return;
        }
        JsonNode id = message.get("id");
        switch (method == null ? "" : method) {
            case "ping" -> {
                record(exchange, headers, body, method, null, 200, null, sub, sessionId);
                send(exchange, 200, "application/json", response(id, JSON.createObjectNode()));
            }
            case "tools/list" -> {
                record(exchange, headers, body, method, null, 200, null, sub, sessionId);
                ObjectNode result = JSON.createObjectNode();
                result.set("tools", toolDefinitions(descriptionOverrides));
                send(exchange, 200, "application/json", response(id, result));
            }
            case "tools/call" -> {
                record(exchange, headers, body, method, toolName, 200, null, sub, sessionId);
                ObjectNode result = callTool(toolName, message.path("params").path("arguments"), headers);
                String errorCode = result.path("isError").asBoolean(false) ? errorCodeOf(result) : null;
                audit(rid, auth.claims(), toolName, errorCode == null ? "ok" : "error", errorCode, started);
                String accept = first(headers, "accept");
                if (accept != null && accept.contains("text/event-stream")) {
                    sendEventStream(exchange, id, result);
                } else {
                    send(exchange, 200, "application/json", response(id, result));
                }
            }
            default -> {
                record(exchange, headers, body, method, null, 200, null, sub, sessionId);
                ObjectNode error = JSON.createObjectNode();
                error.put("jsonrpc", "2.0");
                error.set("id", id);
                error.putObject("error").put("code", -32601).put("message", "Method not found");
                send(exchange, 200, "application/json", JSON.writeValueAsString(error));
            }
        }
    }

    private ObjectNode callTool(String name, JsonNode arguments, Map<String, List<String>> headers) {
        String credential = first(headers, "x-mcp-credential");
        String credentialType = first(headers, "x-mcp-credential-type");
        if (credential == null || credentialType == null) {
            return toolError("internal_error", "No credential was injected.");
        }
        return switch (name) {
            case "get_issue" -> {
                String key = arguments.path("issueKey").asString("");
                if (!ISSUE_KEY.matcher(key).matches()) {
                    yield toolError("invalid_argument", "issueKey must look like ABC-123.");
                }
                yield jiraGet("/rest/api/2/issue/" + key + "?fields=summary,status", credential, credentialType,
                        json -> {
                            ObjectNode out = JSON.createObjectNode();
                            out.put("key", json.path("key").asString(key));
                            out.put("summary", json.path("fields").path("summary").asString(""));
                            return out;
                        });
            }
            case "search_issues" -> {
                String project = arguments.path("project").asString("");
                if (!PROJECT_KEY.matcher(project).matches()) {
                    yield toolError("invalid_argument", "project must be a Jira project key.");
                }
                String jql = URLEncoder.encode("project = " + project, StandardCharsets.UTF_8);
                yield jiraGet("/rest/api/2/search?fields=summary&jql=" + jql, credential, credentialType, json -> {
                    ObjectNode out = JSON.createObjectNode();
                    ArrayNode keys = out.putArray("issues");
                    for (JsonNode issue : json.path("issues")) {
                        keys.addObject().put("key", issue.path("key").asString())
                                .put("summary", issue.path("fields").path("summary").asString(""));
                    }
                    return out;
                });
            }
            case "delete_issue" -> {
                String key = arguments.path("issueKey").asString("");
                if (arguments.has("confirmation_code")) {
                    yield toolError("internal_error", "The confirmation code reached the server.");
                }
                if (!ISSUE_KEY.matcher(key).matches()) {
                    yield toolError("invalid_argument", "issueKey must look like ABC-123.");
                }
                ObjectNode out = JSON.createObjectNode();
                out.put("deleted", key);
                yield toolResult(out, false);
            }
            default -> toolError("invalid_argument", "Unknown tool.");
        };
    }

    private ObjectNode jiraGet(String path, String credential, String credentialType,
                               java.util.function.Function<JsonNode, ObjectNode> mapper) {
        if (config.jiraUrl() == null) {
            ObjectNode out = JSON.createObjectNode();
            out.put("credentialType", credentialType);
            out.put("credentialScheme", credential.substring(0, Math.max(0, credential.indexOf(' '))));
            return toolResult(out, false);
        }
        String scheme = credential.substring(0, Math.max(0, credential.indexOf(' ')));
        if (!"Bearer".equals(scheme)) {
            return toolError("internal_error", "Unsupported credential scheme.");
        }
        try {
            HttpResponse<String> response = jira.send(HttpRequest.newBuilder(config.jiraUrl().resolve(path))
                    .timeout(Duration.ofSeconds(5)).header("Authorization", credential)
                    .header("Accept", "application/json").GET().build(), HttpResponse.BodyHandlers.ofString());
            return switch (response.statusCode()) {
                case 200 -> toolResult(mapper.apply(JSON.readTree(response.body())), false);
                case 401, 403, 404 -> toolError("not_found_or_denied", "The resource does not exist or you have no access.");
                default -> toolError("upstream_unavailable", "Jira did not answer.");
            };
        } catch (IOException e) {
            return toolError("upstream_unavailable", "Jira did not answer.");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return toolError("upstream_unavailable", "Jira did not answer.");
        }
    }

    private static ArrayNode toolDefinitions(Map<String, String> overrides) {
        ArrayNode tools = JSON.createArrayNode();
        tools.add(tool("get_issue", "Get issue", overrides.getOrDefault("get_issue", "Returns the key and summary of one Jira issue."),
                "issueKey", "Issue key, e.g. ABC-123.", true));
        tools.add(tool("search_issues", "Search issues", overrides.getOrDefault("search_issues", "Lists issues of one Jira project."),
                "project", "Project key, e.g. ABC.", true));
        tools.add(tool("delete_issue", "Delete issue", overrides.getOrDefault("delete_issue", "Deletes one Jira issue."),
                "issueKey", "Issue key, e.g. ABC-123.", false));
        return tools;
    }

    private static ObjectNode tool(String name, String title, String description, String argument, String argumentDescription,
                                   boolean readOnly) {
        ObjectNode tool = JSON.createObjectNode();
        tool.put("name", name);
        tool.put("title", title);
        tool.put("description", description);
        ObjectNode schema = tool.putObject("inputSchema");
        schema.put("type", "object");
        schema.putObject("properties").putObject(argument).put("type", "string").put("maxLength", 64)
                .put("description", argumentDescription);
        schema.putArray("required").add(argument);
        schema.put("additionalProperties", false);
        tool.putObject("annotations").put("readOnlyHint", readOnly).put("destructiveHint", !readOnly);
        return tool;
    }

    private static ObjectNode toolResult(ObjectNode payload, boolean isError) {
        ObjectNode result = JSON.createObjectNode();
        result.putArray("content").addObject().put("type", "text").put("text", JSON.writeValueAsString(payload));
        result.put("isError", isError);
        return result;
    }

    private static ObjectNode toolError(String code, String message) {
        ObjectNode payload = JSON.createObjectNode();
        payload.put("error", code);
        payload.put("message", message);
        return toolResult(payload, true);
    }

    private static String errorCodeOf(ObjectNode result) {
        try {
            return JSON.readTree(result.path("content").path(0).path("text").asString("{}")).path("error").asString(null);
        } catch (RuntimeException e) {
            return "internal_error";
        }
    }

    private void audit(String rid, Map<String, Object> claims, String tool, String outcome, String errorCode, long startedNanos) {
        if (rid == null || !UUID_V7.matcher(rid).matches()) {
            return;
        }
        ObjectNode event = JSON.createObjectNode();
        event.put("ts", Instant.now().toString());
        event.put("requestId", rid);
        event.put("component", "server");
        event.put("componentId", config.serverId());
        event.put("event", "tool_call");
        putIfPresent(event, "sub", claims.get("sub"));
        putIfPresent(event, "username", claims.get("usr"));
        putIfPresent(event, "client", claims.get("azp"));
        event.put("server", config.serverId());
        if (tool != null && tool.matches("^[a-z][a-z0-9]*(_[a-z0-9]+)*$") && tool.length() <= 64) {
            event.put("tool", tool);
        }
        event.put("outcome", outcome);
        if (errorCode != null) {
            event.put("errorCode", errorCode);
        }
        event.put("latencyMs", (System.nanoTime() - startedNanos) / 1_000_000);
        System.out.println(JSON.writeValueAsString(event));
    }

    private static void putIfPresent(ObjectNode node, String field, Object value) {
        if (value instanceof String s && !s.isEmpty()) {
            node.put(field, s);
        }
    }

    private static String response(JsonNode id, JsonNode result) {
        ObjectNode response = JSON.createObjectNode();
        response.put("jsonrpc", "2.0");
        response.set("id", id);
        response.set("result", result);
        return JSON.writeValueAsString(response);
    }

    private static void sendEventStream(HttpExchange exchange, JsonNode id, ObjectNode result) throws IOException {
        ObjectNode log = JSON.createObjectNode();
        log.put("jsonrpc", "2.0");
        log.put("method", "notifications/message");
        log.putObject("params").put("level", "info").put("data", "working");
        String body = "event: message\ndata: " + JSON.writeValueAsString(log) + "\n\n"
                + "event: message\ndata: " + response(id, result) + "\n\n";
        send(exchange, 200, "text/event-stream", body);
    }

    private static void send(HttpExchange exchange, int status, String contentType, String body) throws IOException {
        byte[] bytes = body == null ? new byte[0] : body.getBytes(StandardCharsets.UTF_8);
        if (contentType != null) {
            exchange.getResponseHeaders().set("Content-Type", contentType);
        }
        exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
        if (bytes.length > 0) {
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        }
    }

    private void record(HttpExchange exchange, Map<String, List<String>> headers, String body, String rpcMethod,
                        String toolName, int status, String reason, String sub, String sessionId) {
        recorded.add(new RecordedRequest(exchange.getRequestMethod(), headers, body, rpcMethod, toolName, status, reason,
                sub, sessionId));
    }

    private static String clientCommonName(HttpExchange exchange) {
        if (!(exchange instanceof HttpsExchange https)) {
            return null;
        }
        try {
            LdapName name = new LdapName(https.getSSLSession().getPeerPrincipal().getName());
            for (Rdn rdn : name.getRdns()) {
                if ("CN".equalsIgnoreCase(rdn.getType())) {
                    return rdn.getValue().toString();
                }
            }
        } catch (SSLPeerUnverifiedException | InvalidNameException e) {
            return null;
        }
        return null;
    }

    private static Map<String, List<String>> lowerCase(Headers headers) {
        Map<String, List<String>> out = new HashMap<>();
        headers.forEach((k, v) -> out.computeIfAbsent(k.toLowerCase(Locale.ROOT), x -> new ArrayList<>()).addAll(v));
        return out;
    }

    private static String first(Map<String, List<String>> headers, String name) {
        List<String> values = headers.get(name);
        return values == null || values.isEmpty() ? null : values.getFirst();
    }

    private static String randomId() {
        byte[] bytes = new byte[24];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
