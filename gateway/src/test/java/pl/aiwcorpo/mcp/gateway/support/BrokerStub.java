package pl.aiwcorpo.mcp.gateway.support;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsExchange;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

import pl.aiwcorpo.mcp.testserver.InternalJwtVerifier;
import pl.aiwcorpo.mcp.testserver.AuthenticatorEndpoints;

/**
 * Credential broker stand-in (C4 resolve and systems): mTLS with client CN mcp-gateway, strict C2
 * verification with the receiver of the test server, programmable answer.
 */
public final class BrokerStub implements AutoCloseable {

    public record Received(String method, String path, String body, String requestId, String rejectReason, String tool) {
    }

    public enum Mode { GRANT, REQUIRED, UNAVAILABLE, DROP, REJECT, BAD_BODY, EXCHANGE_DENIED, SYSTEM_NOT_CONFIGURED, EXCHANGED_WITHOUT_EXPIRY, OTHER_TYPE, UNKNOWN_TYPE }

    private final HttpsServer server;
    private final InternalJwtVerifier verifier;
    private final List<Received> received = new CopyOnWriteArrayList<>();
    private final List<Received> systemsCalls = new CopyOnWriteArrayList<>();
    private volatile Mode mode = Mode.GRANT;
    private volatile String secret = "alice-pat";
    private volatile int cacheTtlSeconds = 60;
    private final AuthenticatorEndpoints authenticators = new AuthenticatorEndpoints(Clock.systemUTC());

    /** Registers the authenticator of a user; the test makes its codes with {@code Totp.currentCode}. */
    public void enroll(String sub, String secretBase32) {
        authenticators.enroll(sub, secretBase32);
    }

    public void removeAuthenticator(String sub) {
        authenticators.remove(sub);
    }

    /** The authenticator endpoints answer 503 (the credential endpoints are not affected). */
    public void authenticatorDown(boolean down) {
        authenticators.down(down);
    }

    /** Only {@code invalidate-codes} answers 503. */
    public void invalidateFails(boolean fails) {
        authenticators.invalidateFails(fails);
    }

    public long count(String path) {
        return received.stream().filter(r -> r.path().equals(path)).count();
    }

    public BrokerStub(SSLContext tls, InternalJwtVerifier.KeySource gatewayKeys) throws IOException {
        this.verifier = new InternalJwtVerifier("https://mcp-gateway.internal", "mcp-credential-broker", false, gatewayKeys,
                Clock.systemUTC());
        this.server = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(tls) {
            @Override
            public void configure(HttpsParameters params) {
                SSLParameters ssl = tls.getDefaultSSLParameters();
                ssl.setNeedClientAuth(true);
                params.setSSLParameters(ssl);
            }
        });
        server.createContext("/v1/", this::handle);
        server.setExecutor(java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor());
        server.start();
    }

    /** True when requests are served on threads of their own; the default executor of the server runs them one by one. */
    public boolean servesInParallel() {
        return server.getExecutor() != null;
    }

    public int port() {
        return server.getAddress().getPort();
    }

    public void grant(String value, int ttlSeconds) {
        this.secret = value;
        this.cacheTtlSeconds = ttlSeconds;
        this.mode = Mode.GRANT;
    }

    public void mode(Mode mode) {
        this.mode = mode;
    }

    public List<Received> received() {
        return List.copyOf(received);
    }

    /** GET /v1/systems calls since start; not cleared by {@link #clear()}. */
    public List<Received> systemsCalls() {
        return List.copyOf(systemsCalls);
    }

    public void clear() {
        received.clear();
    }

    @Override
    public void close() {
        server.stop(0);
    }

    private void handle(HttpExchange exchange) throws IOException {
        try (exchange) {
            String path = exchange.getRequestURI().getPath();
            String method = exchange.getRequestMethod();
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String rid = exchange.getRequestHeaders().getFirst("X-Request-Id");
            if (!"mcp-gateway".equals(commonName(exchange))) {
                received.add(new Received(method, path, body, rid, "client_cn", null));
                send(exchange, 403, "{\"error\":\"forbidden\"}");
                return;
            }
            InternalJwtVerifier.Result auth = verifier.verify(exchange.getRequestHeaders().getFirst("Authorization"), rid,
                    InternalJwtVerifier.RequestRule.forHttp(method, path));
            Received entry = new Received(method, path, body, rid, auth.reason(),
                    auth.valid() ? (String) auth.claims().get("tool") : null);
            received.add(entry);
            if ("/v1/systems".equals(path)) {
                systemsCalls.add(entry);
            }
            if (!auth.valid()) {
                send(exchange, 401, "{\"error\":\"unauthenticated\"}");
                return;
            }
            if (path.startsWith("/v1/authenticator")) {
                authenticator(exchange, method, path, body, (String) auth.claims().get("sub"));
                return;
            }
            if ("GET".equals(method) && "/v1/systems".equals(path)) {
                send(exchange, 200, "[{\"system\":\"jira\",\"supportedTypes\":[\"user-oauth\",\"user-secret\"],"
                        + "\"defaultType\":\"user-secret\",\"oauthScopes\":[]}]");
                return;
            }
            switch (mode) {
                case GRANT -> send(exchange, 200, "{\"scheme\":\"Bearer\",\"value\":\"" + secret + "\",\"type\":\"user-secret\","
                        + "\"expiresAt\":null,\"cacheTtlSeconds\":" + cacheTtlSeconds + "}");
                case REQUIRED -> send(exchange, 409, "{\"error\":\"credential_required\",\"system\":\"jira\","
                        + "\"connectUrl\":\"http://localhost:18090/connections?system=jira\"}");
                case UNAVAILABLE -> send(exchange, 503, "{\"error\":\"upstream_unavailable\"}");
                case DROP -> throw new IOException("connection dropped on purpose");
                case REJECT -> send(exchange, 401, "{\"error\":\"unauthenticated\"}");
                case EXCHANGE_DENIED -> send(exchange, 403, "{\"error\":\"exchange_denied\"}");
                case SYSTEM_NOT_CONFIGURED -> send(exchange, 422, "{\"error\":\"system_not_configured\"}");
                case EXCHANGED_WITHOUT_EXPIRY -> send(exchange, 200, "{\"scheme\":\"Bearer\",\"value\":\"" + secret
                        + "\",\"type\":\"token-exchange\",\"expiresAt\":null,\"cacheTtlSeconds\":30}");
                case OTHER_TYPE -> send(exchange, 200, "{\"scheme\":\"Bearer\",\"value\":\"" + secret
                        + "\",\"type\":\"user-oauth\",\"expiresAt\":null,\"cacheTtlSeconds\":30}");
                case UNKNOWN_TYPE -> send(exchange, 200, "{\"scheme\":\"Bearer\",\"value\":\"" + secret
                        + "\",\"type\":\"service-token\",\"expiresAt\":null,\"cacheTtlSeconds\":30}");
                case BAD_BODY -> send(exchange, 200, "{\"scheme\":\"Bearer\",\"type\":\"user-secret\",\"cacheTtlSeconds\":60}");
            }
        }
    }

    private void authenticator(HttpExchange exchange, String method, String path, String body, String sub) throws IOException {
        AuthenticatorEndpoints.Response response = authenticators.handle(method, path, body, sub);
        if (response.status() == 204) {
            exchange.sendResponseHeaders(204, -1);
        } else {
            send(exchange, response.status(), response.body());
        }
    }

    private static void send(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    private static String commonName(HttpExchange exchange) {
        try {
            LdapName name = new LdapName(((HttpsExchange) exchange).getSSLSession().getPeerPrincipal().getName());
            for (Rdn rdn : name.getRdns()) {
                if ("CN".equals(rdn.getType().toUpperCase(Locale.ROOT))) {
                    return rdn.getValue().toString();
                }
            }
        } catch (Exception e) {
            return null;
        }
        return null;
    }
}
