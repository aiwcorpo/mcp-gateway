package pl.aiwcorpo.mcp.gateway.support;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;

/**
 * Stand-in for Keycloak (C1): JWKS over HTTP and tokens signed with the test-idp-corp key of mcp-contracts.
 * Also answers the token exchange endpoint for the broker audience.
 */
public final class TestIdp implements AutoCloseable {

    public static final String ISSUER = "http://localhost:18080/realms/corp";

    private final ECKey key;
    private final HttpServer server;
    private volatile int exchangeCalls;

    public TestIdp() throws Exception {
        this.key = ECKey.parse(resource("mcp-contracts/test-vectors/keys/test-idp-corp.NOT-FOR-PRODUCTION.private.jwk.json"));
        this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        String jwks = new JWKSet(key.toPublicJWK()).toString();
        server.createContext("/certs", exchange -> {
            byte[] body = jwks.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        server.createContext("/token", exchange -> {
            exchangeCalls++;
            String form = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            boolean ok = form.contains("audience=mcp-credential-broker")
                    && form.contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange");
            byte[] body = (ok ? "{\"access_token\":\"exchanged-" + UUID.randomUUID() + "\",\"token_type\":\"Bearer\"}"
                    : "{\"error\":\"invalid_request\"}").getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(ok ? 200 : 400, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        server.start();
    }

    public String jwksUri() {
        return "http://127.0.0.1:" + server.getAddress().getPort() + "/certs";
    }

    public String tokenUri() {
        return "http://127.0.0.1:" + server.getAddress().getPort() + "/token";
    }

    public int exchangeCalls() {
        return exchangeCalls;
    }

    public String token(String sub, String username, List<String> groups) {
        return token(sub, username, groups, "mcp-gateway", "claude-code");
    }

    public String token(String sub, String username, List<String> groups, String audience, String azp) {
        return token(sub, username, groups, audience, azp, 900);
    }

    public String token(String sub, String username, List<String> groups, String audience, String azp, long lifetimeSeconds) {
        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER).subject(sub).audience(audience)
                .issueTime(Date.from(now)).expirationTime(Date.from(now.plusSeconds(lifetimeSeconds)))
                .claim("azp", azp).claim("preferred_username", username).claim("groups", groups)
                .jwtID(UUID.randomUUID().toString()).build();
        try {
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(key.getKeyID())
                    .type(JOSEObjectType.JWT).build(), claims);
            jwt.sign(new ECDSASigner(key));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void close() {
        server.stop(0);
    }

    static String resource(String path) throws IOException {
        try (InputStream in = TestIdp.class.getClassLoader().getResourceAsStream(path)) {
            if (in == null) {
                throw new IOException("missing " + path);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
