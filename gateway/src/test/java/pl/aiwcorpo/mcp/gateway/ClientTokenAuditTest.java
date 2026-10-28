package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.system.CapturedOutput;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

import pl.aiwcorpo.mcp.gateway.support.Contracts;
import tools.jackson.databind.JsonNode;

/** CC-120: every rejected C1 token is an authentication event of the gateway, with the reason and nothing from the token. */
class ClientTokenAuditTest extends GatewayTestBase {

    private static final String CANARY_SUB = "5a1b2c3d-0000-4000-8000-00000000c0de";
    private static final String CANARY_USER = "canary-user-zq91";
    private static final Set<String> ALLOWED_FIELDS = Set.of("ts", "requestId", "clientRequestId", "component", "componentId",
            "event", "server", "decision", "reason", "outcome", "errorCode", "latencyMs");

    @Test
    void missingTokenIsAnEvent(CapturedOutput output) throws Exception {
        assertRejected(output, null, "missing_token");
    }

    @Test
    void garbageIsMalformed(CapturedOutput output) throws Exception {
        assertRejected(output, "not-a-jwt", "malformed");
        assertRejected(output, "a.b.c", "malformed");
    }

    @Test
    void algorithmOutsideTheListIsRejectedByName(CapturedOutput output) throws Exception {
        JWTClaimsSet claims = claims().build();
        PlainJWT unsigned = new PlainJWT(claims);
        assertRejected(output, unsigned.serialize(), "alg_not_allowed");
        SignedJWT hmac = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
        hmac.sign(new MACSigner(new byte[32]));
        assertRejected(output, hmac.serialize(), "alg_not_allowed");
    }

    @Test
    void signatureAndKeyFailures(CapturedOutput output) throws Exception {
        String good = env.idp.sign(claims().build());
        String[] parts = good.split("\\.");
        byte[] signature = Base64.getUrlDecoder().decode(parts[2]);
        signature[0] ^= 0x55;
        String tampered = parts[0] + "." + parts[1] + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
        assertRejected(output, tampered, "bad_signature");

        ECKey stranger = new ECKeyGenerator(Curve.P_256).keyID("a-key-the-idp-does-not-publish").generate();
        assertRejected(output, env.idp.sign(claims().build(), stranger), "unknown_kid");
    }

    @Test
    void claimFailures(CapturedOutput output) throws Exception {
        assertRejected(output, env.idp.sign(claims().issuer("http://localhost:1/realms/other").build()), "wrong_issuer");
        assertRejected(output, env.idp.sign(claims().audience(List.of("mcp-credential-broker")).build()), "wrong_audience");
        Instant now = Instant.now();
        assertRejected(output, env.idp.sign(claims().issueTime(Date.from(now.minusSeconds(900)))
                .expirationTime(Date.from(now.minusSeconds(300))).build()), "expired");
        assertRejected(output, env.idp.sign(claims().notBeforeTime(Date.from(now.plusSeconds(600))).build()), "not_yet_valid");
        assertRejected(output, env.idp.sign(claims().subject("system:svc").build()), "invalid_claims");
        assertRejected(output, env.idp.sign(claims().expirationTime(Date.from(now.plusSeconds(86400))).build()), "invalid_claims");
    }

    @Test
    void theClientRequestIdIsKeptWhenSafeAndNothingElseIsCopied(CapturedOutput output) throws Exception {
        String token = env.idp.sign(claims().audience(List.of("nobody")).build());
        HttpResponse<String> response = send(token, "/s/mcp-jira/mcp", initializeBody(), Map.of("X-Request-Id", "client-req-7"));
        String rid = response.headers().firstValue("X-Request-Id").orElseThrow();
        JsonNode event = onlyAuthenticationEvent(output, rid);
        assertThat(event.path("clientRequestId").asString()).isEqualTo("client-req-7");
        assertThat(rid).isNotEqualTo("client-req-7");
        assertThat(event.propertyNames()).allMatch(ALLOWED_FIELDS::contains);
    }

    @Test
    void jwksOutageIsA401WithAnUpstreamUnavailableEvent(CapturedOutput output) throws Exception {
        ECKey stranger = new ECKeyGenerator(Curve.P_256).keyID("kid-that-forces-a-key-fetch").generate();
        String token = env.idp.sign(claims().build(), stranger);
        env.idp.jwksUp(false);
        try {
            HttpResponse<String> response = send(token, "/s/mcp-jira/mcp", initializeBody(), Map.of());
            assertThat(response.statusCode()).isEqualTo(401);
            assertThat(response.headers().firstValue("WWW-Authenticate").orElse("")).doesNotContain("invalid_token")
                    .startsWith("Bearer resource_metadata=");
            assertThat(response.body()).doesNotContain("jwks");
            String rid = response.headers().firstValue("X-Request-Id").orElseThrow();
            JsonNode event = onlyAuthenticationEvent(output, rid);
            assertThat(event.path("reason").asString()).isEqualTo("jwks_unavailable");
            assertThat(event.path("errorCode").asString()).isEqualTo("upstream_unavailable");
            assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", event)).isEmpty();
            assertThat(output.getAll()).doesNotContain("AuthenticationServiceException");
        } finally {
            env.idp.jwksUp(true);
        }
    }

    @Test
    void otherTokenTypesAreRejected(CapturedOutput output) throws Exception {
        String logout = env.idp.sign(claims().build(), new com.nimbusds.jose.JOSEObjectType("logout+jwt"));
        assertRejected(output, logout, "invalid_claims");
    }

    @Test
    void knownNoiseIsNotAuditedAndEveryOtherPathIs(CapturedOutput output) throws Exception {
        for (String path : List.of("/", "/favicon.ico", "/robots.txt")) {
            HttpResponse<String> response = send(null, path, "{}", Map.of());
            assertThat(response.statusCode()).as(path).isEqualTo(401);
            assertThat(auditEvents(output, response.headers().firstValue("X-Request-Id").orElseThrow())).as(path).isEmpty();
        }
    }

    @Test
    void pathVariantsOfAnMcpEndpointDoNotSkipTheAudit(CapturedOutput output) throws Exception {
        String bad = env.idp.sign(claims().audience(List.of("nobody")).build());
        int rejected = 0;
        for (String path : List.of("/s/mcp-jira/mcp/", "//s/mcp-jira/mcp", "/s/mcp-jira/mcp;x=1", "/%73/mcp-jira/mcp",
                "/S/mcp-jira/mcp", "/s/mcp-jira%2Fmcp", "/s/mcp-jira/mcp/extra", "/v//x/mcp", "/wp-admin")) {
            HttpResponse<String> response;
            try {
                response = send(bad, path, initializeBody(), Map.of());
            } catch (java.io.IOException e) {
                continue;
            }
            if (response.statusCode() == 401) {
                rejected++;
                List<JsonNode> events = auditEvents(output, response.headers().firstValue("X-Request-Id").orElseThrow());
                assertThat(events).as(path).hasSize(1);
                assertThat(events.get(0).path("reason").asString()).as(path).isEqualTo("wrong_audience");
            }
        }
        assertThat(rejected).as("variants answered 401 by the gateway").isGreaterThan(2);
    }

    @Test
    void preflightIsNotAudited(CapturedOutput output) throws Exception {
        HttpResponse<String> preflight = http.send(java.net.http.HttpRequest.newBuilder(
                java.net.URI.create("http://localhost:" + port + "/s/mcp-jira/mcp"))
                .method("OPTIONS", java.net.http.HttpRequest.BodyPublishers.noBody()).build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(auditEvents(output, preflight.headers().firstValue("X-Request-Id").orElse("none"))).isEmpty();
    }

    private void assertRejected(CapturedOutput output, String token, String reason) throws Exception {
        HttpResponse<String> response = send(token, "/s/mcp-jira/mcp", initializeBody(), Map.of());
        assertThat(response.statusCode()).as(reason).isEqualTo(401);
        String rid = response.headers().firstValue("X-Request-Id").orElseThrow();
        JsonNode event = onlyAuthenticationEvent(output, rid);
        assertThat(event.path("reason").asString()).isEqualTo(reason);
        assertThat(event.path("decision").asString()).isEqualTo("deny");
        assertThat(event.path("outcome").asString()).isEqualTo("denied");
        assertThat(event.path("errorCode").asString()).isEqualTo("unauthenticated");
        assertThat(event.path("component").asString()).isEqualTo("gateway");
        assertThat(event.propertyNames()).allMatch(ALLOWED_FIELDS::contains);
        assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", event)).isEmpty();
        assertThat(env.jira.requests()).isEmpty();
        if (token != null) {
            for (String part : token.split("\\.")) {
                if (part.length() > 8) {
                    assertThat(output.getAll()).as("a part of the token in the output").doesNotContain(part);
                }
            }
        }
        assertThat(output.getAll()).doesNotContain(CANARY_SUB).doesNotContain(CANARY_USER);
    }

    private static JsonNode onlyAuthenticationEvent(CapturedOutput output, String rid) {
        List<JsonNode> events = auditEvents(output, rid);
        assertThat(events).hasSize(1);
        assertThat(events.get(0).path("event").asString()).isEqualTo("authentication");
        return events.get(0);
    }

    private JWTClaimsSet.Builder claims() {
        return env.idp.validClaims(CANARY_SUB, CANARY_USER);
    }
}
