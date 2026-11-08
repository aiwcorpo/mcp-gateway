package pl.aiwcorpo.mcp.gateway.upstream;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.broker.Credential;
import pl.aiwcorpo.mcp.gateway.jwt.InternalTokenIssuer;
import pl.aiwcorpo.mcp.gateway.jwt.UuidV7;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * MCP sessions of the gateway towards the servers. A session belongs to one conversation key, and every key
 * contains the user's {@code sub}, so a session is never shared between users (C2); the stored sub is checked
 * again on each use. Every HTTP request carries a new user-variant JWT (no {@code tool} except tools/call).
 */
public class UpstreamSessions {

    public static final List<String> SUPPORTED_VERSIONS = List.of("2025-11-25", "2025-06-18", "2025-03-26");
    private static final Logger log = LoggerFactory.getLogger(UpstreamSessions.class);

    private record Session(String sub, String sessionId, String protocolVersion, Instant lastUsed) {
    }

    /** The client of a server and what it was made for: a change of its address or of the approved trust makes another client. */
    private record Connection(java.net.URI url, String tlsMode, String fingerprint, StreamableHttpClient client) {
        boolean matches(McpServer server) {
            // A ca server renews its certificate without a new approval: only a pinned certificate is part of what the client was made for.
            return url.equals(server.internalUrl()) && java.util.Objects.equals(tlsMode, server.connection().tlsMode())
                    && (!"pinned".equals(tlsMode) || java.util.Objects.equals(fingerprint, server.connection().fingerprint()));
        }
    }

    private final Map<String, Connection> clients = new ConcurrentHashMap<>();
    private final java.util.function.Function<McpServer, StreamableHttpClient> clientFactory;
    private final java.util.function.Predicate<McpServer> policyDataPush;
    private final InternalTokenIssuer tokens;
    private final JsonMapper json;
    private final Duration idleTimeout;
    private final Clock clock;
    private final String clientName;
    private final String clientVersion;
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();
    private final Map<String, Object> initLocks = new ConcurrentHashMap<>();
    private final Map<String, String> serverVersions = new ConcurrentHashMap<>();
    private volatile Instant lastSweep = Instant.EPOCH;

    /**
     * @param clientFactory  makes the HTTP client for a server from its address and approved trust; called again when either changes, because
     *                       the servers are data of the registry and not fixed at start
     * @param policyDataPush pushes the current policy data to a server and says whether it was delivered: asked when a server answers
     *                       {@code 409 policy_data_stale} to a tool call
     */
    public UpstreamSessions(java.util.function.Function<McpServer, StreamableHttpClient> clientFactory,
                            java.util.function.Predicate<McpServer> policyDataPush, InternalTokenIssuer tokens,
                            JsonMapper json, Duration idleTimeout, Clock clock, String clientName, String clientVersion) {
        this.clientFactory = clientFactory;
        this.policyDataPush = policyDataPush;
        this.tokens = tokens;
        this.json = json;
        this.idleTimeout = idleTimeout;
        this.clock = clock;
        this.clientName = clientName;
        this.clientVersion = clientVersion;
    }

    /**
     * Sends one JSON-RPC request (with id) and returns the server's response message. {@code tool} is set only
     * for tools/call; {@code credential} only when the tool needs one. A request that is answered 404 because the server lost the session is
     * sent again on a new session only when {@code repeatable}: a call that may change something is never repeated by the gateway
     * (CC-204); the client decides, and the next request starts a new session.
     */
    public JsonNode call(McpServer server, String conversationKey, GatewayUser user, String requestId, ObjectNode message,
                         String tool, Credential credential, boolean repeatable) throws UpstreamException {
        return call(server, conversationKey, user, requestId, message, tool, credential, repeatable, null, null);
    }

    /** {@code risk} and {@code action}: the classification of a tool of an adapter, put into the token of the call only for a server in adapter mode (CC-226). */
    public JsonNode call(McpServer server, String conversationKey, GatewayUser user, String requestId, ObjectNode message,
                         String tool, Credential credential, boolean repeatable, String risk, String action) throws UpstreamException {
        sweep();
        if (!server.connectionApproved()) {
            throw new UpstreamException(UpstreamException.Kind.UNAVAILABLE, server.serverId() + " has no approved connection");
        }
        StreamableHttpClient client = client(server);
        String key = key(server, conversationKey);
        for (int attempt = 0; attempt < 2; attempt++) {
            Session session = ensure(server, client, key, user, requestId);
            // A new token for every send: the first one is spent when the server answers, whatever it answers (one-time jti).
            java.util.function.Supplier<UpstreamRequest> next = () -> new UpstreamRequest(
                    tokens.forUser(server.serverId(), user, tool, requestId, server.adapter() ? risk : null,
                            server.adapter() ? action : null), requestId, session.sessionId(),
                    session.protocolVersion(), credential, json.writeValueAsString(message));
            UpstreamResponse response = client.post(next.get(), message.get("id"));
            if (tool != null && policyDataStale(response)) {
                // The server holds no policy data or older than this instance's revision (C14): push the data and repeat the call once,
                // whether or not the push was delivered (the vectors count two calls for a push that failed). It refused before it did
                // anything, so repeating is safe whatever the tool does.
                boolean delivered = policyDataPush.test(server);
                response = client.post(next.get(), message.get("id"));
                if (policyDataStale(response)) {
                    throw new UpstreamException(UpstreamException.Kind.UNAVAILABLE, server.serverId() + " is still stale after the push"
                            + (delivered ? "" : " (the push did not reach it)"));
                }
            }
            if (response.status() == 404 && session.sessionId() != null) {
                sessions.remove(key, session);
                if (attempt == 0 && repeatable) {
                    continue;
                }
                if (!repeatable) {
                    throw new UpstreamException(UpstreamException.Kind.UNAVAILABLE, server.serverId() + " lost the session; the call is not repeated");
                }
            }
            check(response, server);
            if (response.message() == null) {
                throw new UpstreamException(UpstreamException.Kind.PROTOCOL, "no response message");
            }
            sessions.computeIfPresent(key, (k, s) -> s == session
                    ? new Session(s.sub(), s.sessionId(), s.protocolVersion(), Instant.now(clock)) : s);
            return response.message();
        }
        throw new UpstreamException(UpstreamException.Kind.PROTOCOL, "session lost twice");
    }

    private static boolean policyDataStale(UpstreamResponse response) {
        return response.status() == 409 && response.message() != null && "policy_data_stale".equals(response.message().path("error").asString(null));
    }

    /** Drops the client and the sessions towards a server that was removed (or is added again later under other settings). */
    public void forgetServer(String serverId) {
        clients.remove(serverId);
        sessions.keySet().removeIf(key -> key.startsWith(serverId + "|"));
        serverVersions.remove(serverId);
    }

    /** Ends the server sessions whose conversation key starts with the prefix (client DELETE of a legacy session). */
    public void close(String conversationPrefix, GatewayUser user, String requestId) {
        sessions.entrySet().removeIf(entry -> {
            if (!entry.getKey().substring(entry.getKey().indexOf('|') + 1).startsWith(conversationPrefix) || !entry.getValue().sub().equals(user.sub())) {
                return false;
            }
            String serverId = entry.getKey().substring(0, entry.getKey().indexOf('|'));
            Connection connection = clients.get(serverId);
            StreamableHttpClient client = connection == null ? null : connection.client();
            Session session = entry.getValue();
            if (client != null && session.sessionId() != null) {
                client.delete(new UpstreamRequest(tokens.forUser(serverId, user, null, requestId), requestId,
                        session.sessionId(), session.protocolVersion(), null, null));
            }
            return true;
        });
    }

    /** Forgets the sessions this instance holds towards the servers for the user (offboarding); the servers drop them when idle. */
    public void forgetUser(String sub) {
        sessions.values().removeIf(session -> session.sub().equals(sub));
    }

    /** The version a server reported in its last initialize (serverInfo.version), or null; a value the server controls. */
    public String serverVersion(String serverId) {
        return serverVersions.get(serverId);
    }

    int size() {
        return sessions.size();
    }

    private Session ensure(McpServer server, StreamableHttpClient client, String key, GatewayUser user, String requestId) throws UpstreamException {
        Session existing = sessions.get(key);
        if (existing != null) {
            verifyOwner(existing, user);
            return existing;
        }
        Object lock = initLocks.computeIfAbsent(key, k -> new Object());
        try {
            synchronized (lock) {
                existing = sessions.get(key);
                if (existing != null) {
                    verifyOwner(existing, user);
                    return existing;
                }
                Session created = initialize(server, client, user, requestId);
                sessions.put(key, created);
                return created;
            }
        } finally {
            initLocks.remove(key, lock);
        }
    }

    private Session initialize(McpServer server, StreamableHttpClient client, GatewayUser user, String requestId) throws UpstreamException {
        ObjectNode init = json.createObjectNode();
        init.put("jsonrpc", "2.0");
        init.put("id", "gw-init-" + UuidV7.next());
        ObjectNode params = init.putObject("params");
        params.put("protocolVersion", SUPPORTED_VERSIONS.getFirst());
        params.putObject("capabilities");
        params.putObject("clientInfo").put("name", clientName).put("version", clientVersion);
        init.put("method", "initialize");
        UpstreamResponse response = client.post(new UpstreamRequest(tokens.forUser(server.serverId(), user, null, requestId),
                requestId, null, null, null, json.writeValueAsString(init)), init.get("id"));
        check(response, server);
        JsonNode result = response.message() == null ? null : response.message().get("result");
        String version = result == null ? null : result.path("protocolVersion").asString(null);
        String reported = result == null ? null : result.path("serverInfo").path("version").asString(null);
        if (reported != null) {
            serverVersions.put(server.serverId(), reported);
        }
        if (version == null || !SUPPORTED_VERSIONS.contains(version)) {
            throw new UpstreamException(UpstreamException.Kind.PROTOCOL, "unsupported protocol version from " + server.serverId());
        }
        ObjectNode initialized = json.createObjectNode();
        initialized.put("jsonrpc", "2.0");
        initialized.put("method", "notifications/initialized");
        UpstreamResponse ack = client.post(new UpstreamRequest(tokens.forUser(server.serverId(), user, null, requestId),
                requestId, response.sessionId(), version, null, json.writeValueAsString(initialized)), null);
        if (ack.status() != 202 && ack.status() != 200) {
            throw new UpstreamException(UpstreamException.Kind.PROTOCOL, "notifications/initialized answered " + ack.status());
        }
        return new Session(user.sub(), response.sessionId(), version, Instant.now(clock));
    }

    private static void verifyOwner(Session session, GatewayUser user) {
        if (!session.sub().equals(user.sub())) {
            throw new IllegalStateException("upstream session bound to another user");
        }
    }

    private static void check(UpstreamResponse response, McpServer server) throws UpstreamException {
        int status = response.status();
        if (status == 200 || status == 202) {
            return;
        }
        if (status == 401 || status == 403) {
            log.error("{} rejected the gateway's request with {}", server.serverId(), status);
            throw new UpstreamException(UpstreamException.Kind.REJECTED, server.serverId() + " answered " + status);
        }
        if (status >= 500) {
            throw new UpstreamException(UpstreamException.Kind.UNAVAILABLE, server.serverId() + " answered " + status);
        }
        throw new UpstreamException(UpstreamException.Kind.PROTOCOL, server.serverId() + " answered " + status);
    }

    private StreamableHttpClient client(McpServer server) {
        Connection connection = clients.get(server.serverId());
        if (connection != null && connection.matches(server)) {
            return connection.client();
        }
        synchronized (clients) {
            connection = clients.get(server.serverId());
            if (connection == null || !connection.matches(server)) {
                if (connection != null) {
                    // Sessions of the old address or trust mean nothing to the new one.
                    sessions.keySet().removeIf(key -> key.startsWith(server.serverId() + "|"));
                }
                connection = new Connection(server.internalUrl(), server.connection().tlsMode(), server.connection().fingerprint(),
                        clientFactory.apply(server));
                clients.put(server.serverId(), connection);
            }
            return connection.client();
        }
    }

    private static String key(McpServer server, String conversationKey) {
        return server.serverId() + "|" + conversationKey;
    }

    private void sweep() {
        Instant now = Instant.now(clock);
        if (now.isBefore(lastSweep.plusSeconds(60))) {
            return;
        }
        lastSweep = now;
        sessions.values().removeIf(s -> s.lastUsed().plus(idleTimeout).isBefore(now));
    }
}
