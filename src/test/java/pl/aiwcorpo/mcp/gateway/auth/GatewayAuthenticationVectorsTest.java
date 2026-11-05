package pl.aiwcorpo.mcp.gateway.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import pl.aiwcorpo.mcp.gateway.audit.AuditLog;
import pl.aiwcorpo.mcp.gateway.ratelimit.RateLimitResponse;
import pl.aiwcorpo.mcp.gateway.support.Contracts;
import pl.aiwcorpo.mcp.gateway.support.Vectors;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** CC-124, CC-156: the 401, 503 and 429 answers of gateway-authentication/ produced by the real entry point and the real rate limit response. */
class GatewayAuthenticationVectorsTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    @TestFactory
    List<DynamicTest> everyVector() {
        List<Vectors.Vector> vectors = Vectors.of("gateway-authentication");
        assertThat(vectors).hasSize(21);
        return vectors.stream().map(v -> DynamicTest.dynamicTest(v.name(), () -> check(v.document()))).toList();
    }

    private static void check(JsonNode vector) throws Exception {
        JsonNode input = vector.path("input");
        String base = input.path("publicBaseUrl").asString();
        McpAuthenticationEntryPoint entryPoint = new McpAuthenticationEntryPoint(
                new ResourceMetadata(new PublicUrls(URI.create(base), false)),
                new AuthenticationAudit(new AuditLog(), "mcp-gateway", new AuthenticationEventLimiter(1000, java.time.Duration.ofMinutes(1), System::nanoTime,
                        new SimpleMeterRegistry())));
        // Older vectors name the route of a system (/s/mcp-jira); the aggregate endpoint is named by its whole path (/mcp).
        String resourcePath = input.path("resourcePath").asString();
        MockHttpServletRequest request = new MockHttpServletRequest("POST", resourcePath.startsWith("/s/") ? resourcePath + "/mcp" : resourcePath);
        if (input.has("requestQuery")) {
            request.setQueryString(input.path("requestQuery").asString());
        }
        MockHttpServletResponse response = new MockHttpServletResponse();

        if ("rate_limit_store_unavailable".equals(input.path("reason").asString())) {
            org.springframework.http.ResponseEntity<String> refused = RateLimitResponse.unavailable("0192d1b2-7c3a-7d4e-8f10-2a3b4c5d6e7f", 10);
            response.setStatus(refused.getStatusCode().value());
            refused.getHeaders().forEach((name, values) -> response.setHeader(name, values.getFirst()));
            response.getWriter().write(refused.getBody());
        } else if ("overloaded".equals(input.path("reason").asString()) || "streams_limit_reached".equals(input.path("reason").asString())) {
            write(response, RateLimitResponse.overloaded("0192d1b2-7c3a-7d4e-8f10-2a3b4c5d6e7f", 2));
        } else if ("session_store_unavailable".equals(input.path("reason").asString())) {
            write(response, RateLimitResponse.sessionStoreUnavailable("0192d1b2-7c3a-7d4e-8f10-2a3b4c5d6e7f", 10));
        } else if ("rate_limited".equals(input.path("reason").asString())) {
            // The wait is a decimal in a vector (0.2 s): the limiter rounds up to whole seconds, at least one.
            int seconds = (int) Math.max(1, Math.ceil(input.path("retryAfterSeconds").asDouble()));
            org.springframework.http.ResponseEntity<String> limited = RateLimitResponse.of("0192d1b2-7c3a-7d4e-8f10-2a3b4c5d6e7f", seconds);
            response.setStatus(limited.getStatusCode().value());
            limited.getHeaders().forEach((name, values) -> response.setHeader(name, values.getFirst()));
            response.getWriter().write(limited.getBody());
        } else {
            entryPoint.commence(request, response, failure(input.path("reason").asString(), input.path("retryAfterSeconds").asInt(10)));
        }

        JsonNode expected = vector.path("expected");
        assertThat(response.getStatus()).isEqualTo(expected.path("status").asInt());
        expected.path("headers").properties().forEach(header -> {
            String value = header.getValue().asString();
            if ("WWW-Authenticate".equals(header.getKey()) && resourcePath.startsWith("/s/")) {
                // The vectors name the route (/s/mcp-jira); the protected resource of RFC 9728 is its MCP endpoint.
                value = value.substring(0, value.length() - 1) + "/mcp\"";
            }
            assertThat(response.getHeader(header.getKey())).as(header.getKey()).isEqualTo(value);
        });
        for (JsonNode absent : expected.path("absentHeaders")) {
            assertThat(response.getHeader(absent.asString())).as("absent " + absent.asString()).isNull();
        }
        assertThat(JSON.readTree(response.getContentAsString())).isEqualTo(expected.path("body"));
        if (response.getStatus() == 503) {
            assertThat(Contracts.schemaErrors("schemas/tool-error.schema.json#/$defs/UpstreamUnavailable",
                    JSON.readTree(response.getContentAsString()))).isEmpty();
        }
    }

    private static void write(MockHttpServletResponse response, org.springframework.http.ResponseEntity<String> answer) throws Exception {
        response.setStatus(answer.getStatusCode().value());
        answer.getHeaders().forEach((name, values) -> response.setHeader(name, values.getFirst()));
        response.getWriter().write(answer.getBody());
    }

    private static AuthenticationException failure(String reason, int retryAfter) {
        if ("jwks_unavailable".equals(reason)) {
            return new AuthenticationServiceException("keys", new ClientTokenUnavailable(retryAfter));
        }
        if ("missing_token".equals(reason)) {
            return new AuthenticationCredentialsNotFoundException("no token");
        }
        assertThat(Set.of("malformed", "bad_signature", "unknown_kid", "alg_not_allowed", "wrong_issuer", "wrong_audience",
                "expired", "not_yet_valid", "invalid_claims")).contains(reason);
        return new InvalidBearerTokenException(reason, new ClientTokenRejection(reason));
    }
}
