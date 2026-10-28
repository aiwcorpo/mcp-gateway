package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.system.CapturedOutput;

import io.micrometer.core.instrument.MeterRegistry;
import pl.aiwcorpo.mcp.gateway.auth.AuthenticationEventLimiter;
import pl.aiwcorpo.mcp.gateway.support.Contracts;
import tools.jackson.databind.JsonNode;

/** CC-125: rejections on the admin port (C5 and /actuator/prometheus) are authentication events, sampled per source. */
class AdminAuthenticationAuditTest extends GatewayTestBase {

    private static final Set<String> ALLOWED_FIELDS = Set.of("ts", "requestId", "clientRequestId", "component", "componentId",
            "event", "server", "decision", "reason", "outcome", "errorCode", "latencyMs");

    @Autowired
    MeterRegistry meters;

    @BeforeEach
    void clearSamplingWindow() throws Exception {
        // One certificate rejection per source per interval (1 s in tests): start every test with an empty window.
        Thread.sleep(1100);
    }

    private double suppressed(String reason) {
        var counter = meters.find(AuthenticationEventLimiter.METRIC).tag("component", "gateway").tag("reason", reason).counter();
        return counter == null ? 0 : counter.count();
    }

    private JsonNode onlyEvent(CapturedOutput output, HttpResponse<String> response) {
        String rid = response.headers().firstValue("X-Request-Id").orElseThrow();
        List<JsonNode> events = auditEvents(output, rid);
        assertThat(events).hasSize(1);
        JsonNode event = events.getFirst();
        assertThat(event.path("event").asString()).isEqualTo("authentication");
        assertThat(event.propertyNames()).allMatch(ALLOWED_FIELDS::contains);
        assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", event)).isEmpty();
        return event;
    }

    @Test
    void noClientCertificateIsAnEventWithoutAnythingFromTheRequest(CapturedOutput output) throws Exception {
        HttpResponse<String> response = admin(env.noClientCertificateTls, "GET", "/admin/v1/catalog", null, null);
        assertThat(response.statusCode()).isEqualTo(401);
        JsonNode event = onlyEvent(output, response);
        assertThat(event.path("reason").asString()).isEqualTo("client_certificate_rejected");
        assertThat(event.path("decision").asString()).isEqualTo("deny");
        assertThat(event.path("outcome").asString()).isEqualTo("denied");
        assertThat(event.path("errorCode").asString()).isEqualTo("unauthenticated");
        assertThat(event.path("component").asString()).isEqualTo("gateway");
    }

    @Test
    void certificateOfAForeignCaAndOfAnotherComponentAreEvents(CapturedOutput output) throws Exception {
        HttpResponse<String> foreign = admin(env.foreignCaTls, "GET", "/admin/v1/catalog", null, null);
        assertThat(foreign.statusCode()).isEqualTo(401);
        assertThat(onlyEvent(output, foreign).path("reason").asString()).isEqualTo("client_certificate_rejected");

        Thread.sleep(1100);
        HttpResponse<String> other = admin(env.otherComponentTls, "GET", "/admin/v1/catalog", null, null);
        assertThat(other.statusCode()).isEqualTo(403);
        JsonNode event = onlyEvent(output, other);
        assertThat(event.path("reason").asString()).isEqualTo("client_certificate_rejected");
        assertThat(event.path("errorCode").asString()).isEqualTo("access_denied");
    }

    @Test
    void aScannerFromOneAddressWritesOneEventPerIntervalAndTheRestIsCounted(CapturedOutput output) throws Exception {
        double before = suppressed("client_certificate_rejected");
        int events = 0;
        for (int i = 0; i < 12; i++) {
            HttpResponse<String> response = admin(env.noClientCertificateTls, "GET", "/admin/v1/virtual-servers", null, null);
            assertThat(response.statusCode()).isEqualTo(401);
            events += auditEvents(output, response.headers().firstValue("X-Request-Id").orElseThrow()).size();
        }
        assertThat(events).isBetween(1, 2);
        assertThat(suppressed("client_certificate_rejected") - before).isEqualTo(12 - events);
    }

    @Test
    void prometheusWithoutTheScrapersCertificateIsAnEvent(CapturedOutput output) throws Exception {
        HttpResponse<String> response = admin(env.noClientCertificateTls, "GET", "/actuator/prometheus", null, null);
        assertThat(response.statusCode()).isEqualTo(401);
        assertThat(onlyEvent(output, response).path("reason").asString()).isEqualTo("client_certificate_rejected");
    }

    @Test
    void aBffTokenThatFailsValidationIsAnEventWithItsReason(CapturedOutput output) throws Exception {
        String wrongAudience = env.idp.token(ALICE_SUB, "alice", ALICE_GROUPS, "mcp-gateway", "mcp-portal-bff");
        HttpResponse<String> response = admin(env.bffTls, "GET", "/admin/v1/catalog", wrongAudience, null);
        assertThat(response.statusCode()).isEqualTo(401);
        JsonNode event = onlyEvent(output, response);
        assertThat(event.path("reason").asString()).isEqualTo("wrong_audience");
        assertThat(event.path("errorCode").asString()).isEqualTo("unauthenticated");

        HttpResponse<String> missing = admin(env.bffTls, "GET", "/admin/v1/catalog", null, null);
        assertThat(missing.statusCode()).isEqualTo(401);
        assertThat(onlyEvent(output, missing).path("reason").asString()).isEqualTo("missing_token");
    }

    @Test
    void anIdpOutageOnTheAdminPortIs503WithRetryAfter(CapturedOutput output) throws Exception {
        com.nimbusds.jose.jwk.ECKey stranger = new com.nimbusds.jose.jwk.gen.ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256)
                .keyID("admin-kid-that-forces-a-key-fetch").generate();
        String token = env.idp.sign(env.idp.validClaims(ALICE_SUB, "alice").audience(List.of("mcp-gateway-admin"))
                .claim("azp", "mcp-portal-bff").build(), stranger);
        env.idp.jwksUp(false);
        try {
            HttpResponse<String> response = await().atMost(Duration.ofSeconds(5)).pollInterval(Duration.ofMillis(250))
                    .until(() -> admin(env.bffTls, "GET", "/admin/v1/catalog", token, null), r -> r.statusCode() == 503);
            assertThat(response.headers().firstValue("Retry-After")).contains("1");
            assertThat(response.headers().firstValue("WWW-Authenticate")).isEmpty();
            assertThat(JSON.readTree(response.body()).path("error").asString()).isEqualTo("upstream_unavailable");
            JsonNode event = onlyEvent(output, response);
            assertThat(event.path("reason").asString()).isEqualTo("jwks_unavailable");
            assertThat(event.path("errorCode").asString()).isEqualTo("upstream_unavailable");
        } finally {
            env.idp.jwksUp(true);
            Thread.sleep(1100);
        }
    }
}
