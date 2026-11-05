package pl.aiwcorpo.mcp.testserver;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Locale;
import java.util.Map;

import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsExchange;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * Stand-in for the credential broker (C4 resolve and systems) for demos of the gateway on the host: mTLS with
 * client CN mcp-gateway, strict C2 verification, a fixed PAT per user name and 409 credential_required for
 * everyone else. It stores nothing and is not the broker.
 */
public final class TestBroker implements AutoCloseable {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    private final HttpsServer server;
    private final InternalJwtVerifier verifier;
    private final Map<String, String> patsByUser;
    private final String connectUrl;
    private final AuthenticatorEndpoints authenticators = new AuthenticatorEndpoints(Clock.systemUTC());

    public TestBroker(SSLContext tls, InternalJwtVerifier.KeySource gatewayKeys, String issuer, Map<String, String> patsByUser,
                      String connectUrl, InetSocketAddress address) throws IOException {
        this.verifier = new InternalJwtVerifier(issuer, "mcp-credential-broker", false, gatewayKeys, Clock.systemUTC());
        this.patsByUser = Map.copyOf(patsByUser);
        this.connectUrl = connectUrl;
        this.server = HttpsServer.create(address, 0);
        server.setHttpsConfigurator(new HttpsConfigurator(tls) {
            @Override
            public void configure(HttpsParameters params) {
                SSLParameters ssl = tls.getDefaultSSLParameters();
                ssl.setNeedClientAuth(true);
                params.setSSLParameters(ssl);
            }
        });
        server.createContext("/v1/", this::handle);
    }

    /** Gives a user (by {@code sub}) an authenticator with this Base32 seed; the demo makes its codes from the same seed. */
    public TestBroker enroll(String sub, String secretBase32) {
        authenticators.enroll(sub, secretBase32);
        return this;
    }

    public TestBroker start() {
        server.start();
        return this;
    }

    public int port() {
        return server.getAddress().getPort();
    }

    @Override
    public void close() {
        server.stop(0);
    }

    private void handle(HttpExchange exchange) throws IOException {
        try (exchange) {
            String method = exchange.getRequestMethod();
            String path = exchange.getRequestURI().getPath();
            String requestBody = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            if (!"mcp-gateway".equals(commonName(exchange))) {
                send(exchange, 403, "{\"error\":\"forbidden\"}");
                return;
            }
            InternalJwtVerifier.Result auth = verifier.verify(exchange.getRequestHeaders().getFirst("Authorization"),
                    exchange.getRequestHeaders().getFirst("X-Request-Id"), InternalJwtVerifier.RequestRule.forHttp(method, path));
            if (!auth.valid()) {
                System.err.println("test broker: rejected " + method + " " + path + ": " + auth.reason());
                send(exchange, 401, "{\"error\":\"unauthenticated\"}");
                return;
            }
            if (AuthenticatorEndpoints.handles(path)) {
                AuthenticatorEndpoints.Response response = authenticators.handle(method, path, requestBody,
                        String.valueOf(auth.claims().get("sub")));
                if (response.status() == 204) {
                    exchange.sendResponseHeaders(204, -1);
                } else {
                    send(exchange, response.status(), response.body());
                }
                return;
            }
            if ("GET".equals(method) && "/v1/systems".equals(path)) {
                send(exchange, 200, "[{\"system\":\"jira\",\"supportedTypes\":[\"user-oauth\",\"user-secret\"],"
                        + "\"defaultType\":\"user-secret\",\"oauthScopes\":[]}]");
                return;
            }
            if (!"POST".equals(method) || !"/v1/credentials/resolve".equals(path)) {
                send(exchange, 404, "{\"error\":\"not_found\"}");
                return;
            }
            String user = String.valueOf(auth.claims().get("usr"));
            String pat = patsByUser.get(user);
            if (pat == null) {
                ObjectNode body = JSON.createObjectNode();
                body.put("error", "credential_required");
                body.put("system", "jira");
                body.put("connectUrl", connectUrl);
                send(exchange, 409, JSON.writeValueAsString(body));
                return;
            }
            send(exchange, 200, "{\"scheme\":\"Bearer\",\"value\":\"" + pat + "\",\"type\":\"user-secret\","
                    + "\"expiresAt\":null,\"cacheTtlSeconds\":30}");
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
