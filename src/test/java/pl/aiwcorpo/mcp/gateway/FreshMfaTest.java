package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.http.HttpResponse;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.security.oauth2.jwt.Jwt;

import pl.aiwcorpo.mcp.gateway.admin.FreshMfa;
import pl.aiwcorpo.mcp.gateway.audit.AuditLog;
import pl.aiwcorpo.mcp.gateway.jwt.UuidV7;
import pl.aiwcorpo.mcp.testserver.TestMcpServer;

/**
 * Fresh MFA for the operations that widen access (CC-239, CC-240): {@code auth_time} within 300 s and proof of a second factor ({@code amr}
 * or a configured {@code acr}); a password-only login that is fresh is not enough. Every other case is {@code 401 step_up_required}.
 */
class FreshMfaTest extends GatewayTestBase {

    private static final List<String> ADMIN = List.of("mcp-platform-admin");
    private static final String SERVER = "/admin/v1/servers/mcp-mfa";

    private TestMcpServer mfa;
    private String body;

    @BeforeEach
    void startTheServer() throws Exception {
        mfa = env.startServer("mcp-mfa");
        body = "{\"internalUrl\":\"https://127.0.0.1:" + mfa.port() + "/mcp\"}";
    }

    @AfterEach
    void remove() throws Exception {
        adminCall("DELETE", SERVER, null);
        jdbc.sql("DELETE FROM policy_overrides").update();
        mfa.close();
    }

    private String token(Long authAge, List<String> amr, String acr) {
        return env.idp.adminToken(ADMIN_SUB, "a.admin", ADMIN, authAge, amr, acr);
    }

    private HttpResponse<String> call(String token, String method, String path, String body, Map<String, String> headers) throws Exception {
        return admin(env.bffTls, method, path, token, body, headers);
    }

    private static List<String> notFresh() {
        return List.of("stale", "missing", "password", "acr");
    }

    private String notFreshToken(String kind) {
        return switch (kind) {
            case "stale" -> token(400L, List.of("pwd", "otp"), null);
            case "missing" -> token(null, List.of("pwd", "otp"), null);
            case "password" -> token(10L, List.of("pwd"), null);
            default -> token(10L, null, "urn:not-listed");
        };
    }

    @Test
    void everyOperationThatWidensAccessNeedsAFreshMfa(CapturedOutput output) throws Exception {
        String fresh = token(10L, List.of("pwd", "otp"), null);
        assertThat(call(fresh, "POST", "/admin/v1/servers", body, Map.of()).statusCode()).isEqualTo(201);
        String etag = etag(call(fresh, "GET", SERVER, null, Map.of()));
        HttpResponse<String> mapping = call(fresh, "GET", "/admin/v1/policy/scope-mapping", null, Map.of());
        String override = "{\"target\":\"gateway\",\"text\":\"forbid (principal, action == Action::\\\"call\\\", resource is Tool);\"}";
        HttpResponse<String> created = call(fresh, "PUT", "/admin/v1/policy/overrides/override-mfa", override, Map.of("If-None-Match", "*"));
        assertThat(created.statusCode()).as(created.body()).isEqualTo(200);

        for (String kind : notFresh()) {
            String stale = notFreshToken(kind);
            String requestId = UuidV7.next();
            Map<String, String> rid = Map.of("X-Request-Id", requestId);
            Map<String, String> match = Map.of("If-Match", etag, "X-Request-Id", requestId);
            Map<String, HttpResponse<String>> refused = new java.util.LinkedHashMap<>();
            refused.put("createServer", call(stale, "POST", "/admin/v1/servers", body, rid));
            refused.put("updateServer", call(stale, "PATCH", SERVER, "{\"enabled\":true}", match));
            refused.put("updateServerUrl", call(stale, "PATCH", SERVER, "{\"internalUrl\":\"https://127.0.0.1:9/mcp\"}", match));
            refused.put("deleteServer", call(stale, "DELETE", SERVER, null, rid));
            refused.put("putScopeMapping", call(stale, "PUT", "/admin/v1/policy/scope-mapping", "{\"scopeMapping\":[]}",
                    Map.of("If-Match", etag(mapping), "X-Request-Id", requestId)));
            refused.put("deleteOverride", call(stale, "DELETE", "/admin/v1/policy/overrides/override-mfa", null,
                    Map.of("If-Match", etag(created), "X-Request-Id", requestId)));
            refused.put("approveServerPolicies", call(stale, "POST", "/admin/v1/registry/servers/mcp-mfa/policies/approve",
                    "{\"policiesHash\":\"sha256:" + "0".repeat(64) + "\"}", rid));
            refused.forEach((operation, response) -> {
                assertThat(response.statusCode()).as(kind + " " + operation + " " + response.body()).isEqualTo(401);
                assertThat(JSON.readTree(response.body()).path("error").asString()).isEqualTo("step_up_required");
            });
            assertThat(auditEvents(output, requestId).stream().filter(e -> "step_up_required".equals(e.path("reason").asString())).count())
                    .as(kind + ": every refusal is audited").isEqualTo(refused.size());
        }
        assertThat(call(fresh, "GET", SERVER, null, Map.of()).statusCode()).as("nothing was changed or removed").isEqualTo(200);
        assertThat(etag(call(fresh, "GET", SERVER, null, Map.of()))).isEqualTo(etag);
        assertThat(call(fresh, "GET", "/admin/v1/policy/overrides/override-mfa", null, Map.of()).statusCode()).isEqualTo(200);
    }

    @Test
    void switchingAServerOffNeedsNoFreshMfaAndNothingElseDoesAnyMore() throws Exception {
        String fresh = token(10L, List.of("pwd", "otp"), null);
        assertThat(call(fresh, "POST", "/admin/v1/servers", body, Map.of()).statusCode()).isEqualTo(201);
        String stale = token(4000L, List.of("pwd"), null);
        String etag = etag(call(fresh, "GET", SERVER, null, Map.of()));

        HttpResponse<String> off = call(stale, "PATCH", SERVER, "{\"enabled\":false}", Map.of("If-Match", etag));
        assertThat(off.statusCode()).as(off.body()).isEqualTo(200);

        HttpResponse<String> on = call(stale, "PATCH", SERVER, "{\"enabled\":true}", Map.of("If-Match", etag(off)));
        assertThat(on.statusCode()).as("switching on widens access").isEqualTo(401);
        assertThat(call(stale, "PATCH", SERVER, "{\"enabled\":false,\"internalUrl\":\"https://127.0.0.1:9/mcp\"}",
                Map.of("If-Match", etag(off))).statusCode()).as("not only a switch off").isEqualTo(401);
        assertThat(call(fresh, "PATCH", SERVER, "{\"enabled\":true}", Map.of("If-Match", etag(off))).statusCode()).isEqualTo(200);
    }

    @Test
    void readingNeedsNoFreshMfa() throws Exception {
        String stale = token(4000L, null, null);
        assertThat(call(stale, "GET", "/admin/v1/servers", null, Map.of()).statusCode()).isEqualTo(200);
        assertThat(call(stale, "GET", "/admin/v1/policy/scope-mapping", null, Map.of()).statusCode()).isEqualTo(200);
    }

    @Test
    void theAcrAndAmrValuesAreConfigurable(CapturedOutput output) {
        Instant now = Instant.parse("2026-11-06T12:00:00Z");
        FreshMfa strict = new FreshMfa(List.of("urn:mfa"), List.of("hwk"), Clock.fixed(now, java.time.ZoneOffset.UTC), new AuditLog(), "mcp-gateway");
        java.util.function.BiFunction<Long, java.util.Map<String, Object>, Jwt> token = (age, extra) -> {
            Jwt.Builder builder = Jwt.withTokenValue("t").header("alg", "none").subject("s").claim("auth_time", now.getEpochSecond() - age);
            extra.forEach(builder::claim);
            return builder.build();
        };
        assertThat(strict.fresh(token.apply(10L, Map.of("acr", "urn:mfa")))).isTrue();
        assertThat(strict.fresh(token.apply(10L, Map.of("amr", List.of("pwd", "hwk"))))).isTrue();
        assertThat(strict.fresh(token.apply(10L, Map.of("amr", "hwk")))).as("a single value").isTrue();
        assertThat(strict.fresh(token.apply(10L, Map.of("amr", List.of("otp"))))).as("otp is not in this configuration").isFalse();
        assertThat(strict.fresh(token.apply(10L, Map.of("acr", "urn:other")))).isFalse();
        assertThat(strict.fresh(token.apply(10L, Map.of()))).as("no proof of a second factor").isFalse();
        assertThat(strict.fresh(token.apply(301L, Map.of("acr", "urn:mfa")))).as("older than 300 s").isFalse();
        assertThat(strict.fresh(token.apply(300L, Map.of("acr", "urn:mfa")))).as("exactly 300 s").isTrue();
        assertThat(strict.fresh(token.apply(-3600L, Map.of("acr", "urn:mfa")))).as("an auth_time in the future").isFalse();
        assertThat(strict.fresh(Jwt.withTokenValue("t").header("alg", "none").subject("s").claim("amr", List.of("hwk")).build()))
                .as("no auth_time").isFalse();
        assertThat(strict.fresh(null)).isFalse();
    }
}
