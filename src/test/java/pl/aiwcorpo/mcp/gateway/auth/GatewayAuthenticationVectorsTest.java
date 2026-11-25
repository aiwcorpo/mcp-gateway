package pl.aiwcorpo.mcp.gateway.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
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
import pl.aiwcorpo.mcp.gateway.agent.AgentClient;
import pl.aiwcorpo.mcp.gateway.agent.AgentRegistry;
import pl.aiwcorpo.mcp.gateway.agent.PrincipalClassifier;
import pl.aiwcorpo.mcp.gateway.audit.AuditLog;
import pl.aiwcorpo.mcp.gateway.authz.AgentCeilingAuthorizer;
import pl.aiwcorpo.mcp.gateway.authz.ToolAuthorizer;
import pl.aiwcorpo.mcp.gateway.authz.ToolDecision;
import pl.aiwcorpo.mcp.gateway.killswitch.KillSwitches;
import pl.aiwcorpo.mcp.gateway.mcp.CallOrder;
import pl.aiwcorpo.mcp.gateway.server.CredentialPolicy;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.server.Risk;
import pl.aiwcorpo.mcp.gateway.server.ToolDefinition;
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
        List<Vectors.Vector> all = Vectors.of("gateway-authentication");
        assertThat(all).hasSize(37);
        assertThat(all.stream().filter(v -> v.name().startsWith("agent-"))).hasSize(15);
        return all.stream().map(v -> DynamicTest.dynamicTest(v.name(), () -> {
            if (!v.name().startsWith("agent-")) {
                check(v.document());
            } else if (v.document().path("input").has("token")) {
                checkClassification(v.document());
            } else {
                checkCeiling(v.document());
            }
        })).toList();
    }

    private static final AgentClient.Suspension SUSPENDED = new AgentClient.Suspension("owner-1", Instant.EPOCH, "test");

    private static McpAuthenticationEntryPoint entryPoint() {
        return new McpAuthenticationEntryPoint(new ResourceMetadata(new PublicUrls(URI.create("https://mcp.aiwcorpo.pl"), false)),
                new AuthenticationAudit(new AuditLog(), "mcp-gateway", new AuthenticationEventLimiter(1000, java.time.Duration.ofMinutes(1),
                        System::nanoTime, new SimpleMeterRegistry())));
    }

    /** The classification of a token by the registry, and the 401 and 503 answers it leads to through the real entry point. */
    private static void checkClassification(JsonNode vector) throws Exception {
        JsonNode input = vector.path("input");
        JsonNode expected = vector.path("expected");
        boolean readable = input.path("registryReadable").asBoolean(true);
        List<AgentClient> entries = new ArrayList<>();
        input.path("registry").forEach(entry -> entries.add(new AgentClient(entry.path("clientId").asString(), entry.path("serviceAccountSub").asString(),
                "owner-1", Risk.READ_ONLY, List.of(), false, "admin-1", Instant.EPOCH, null,
                "suspended".equals(entry.path("status").asString()) ? SUSPENDED : null)));
        AgentRegistry registry = new AgentRegistry(() -> {
            if (!readable) {
                throw new IllegalStateException("database down");
            }
            return entries;
        }, java.time.Duration.ofSeconds(5), System::nanoTime, new SimpleMeterRegistry());
        JsonNode token = input.path("token");
        PrincipalClassifier.Classification result = new PrincipalClassifier(registry).classify(token.path("azp").asString(), token.path("sub").asString(),
                "agent".equals(token.path("principalType").asString()), Instant.ofEpochSecond(token.path("iat").asLong()),
                Instant.ofEpochSecond(token.path("exp").asLong()));

        String principal = switch (result) {
            case PrincipalClassifier.Classification.Human human -> "human";
            default -> "agent";
        };
        assertThat(principal).as(vector.path("description").asString()).isEqualTo(expected.path("principal").asString());
        switch (result) {
            case PrincipalClassifier.Classification.Human human -> assertThat(expected.path("decision").asString()).isEqualTo("continue");
            case PrincipalClassifier.Classification.Agent agent -> {
                assertThat(agent.entry().clientId()).isEqualTo(expected.path("clientId").asString(agent.entry().clientId()));
                // A suspended agent is let in as one and refused for what it asks (access_denied, agent_suspended): see AgentCallsTest.
                assertThat(agent.entry().suspended() ? "deny" : "continue").isEqualTo(expected.path("decision").asString());
                if (agent.entry().suspended()) {
                    assertThat(expected.path("status").asInt()).isEqualTo(200);
                    assertThat(expected.path("errorCode").asString()).isEqualTo("access_denied");
                    assertThat(expected.path("reason").asString()).isEqualTo("agent_suspended");
                }
            }
            case PrincipalClassifier.Classification.Refused refused -> {
                assertThat(expected.path("decision").asString()).isEqualTo("deny");
                assertThat(refused.reason()).isEqualTo(expected.path("reason").asString());
                MockHttpServletResponse response = new MockHttpServletResponse();
                entryPoint().commence(new MockHttpServletRequest("POST", "/mcp"), response,
                        new InvalidBearerTokenException(refused.reason(), new ClientTokenRejection(refused.reason())));
                assertThat(response.getStatus()).isEqualTo(expected.path("status").asInt());
                assertThat(AuthenticationAudit.reasonOf(new InvalidBearerTokenException("x", new ClientTokenRejection(refused.reason()))))
                        .isEqualTo(expected.path("reason").asString());
            }
            case PrincipalClassifier.Classification.Unavailable unavailable -> {
                assertThat(expected.path("decision").asString()).isEqualTo("deny");
                AuthenticationServiceException failure = new AuthenticationServiceException("registry", new AgentRegistryUnavailable());
                MockHttpServletResponse response = new MockHttpServletResponse();
                entryPoint().commence(new MockHttpServletRequest("POST", "/mcp"), response, failure);
                assertThat(response.getStatus()).isEqualTo(expected.path("status").asInt());
                assertThat(response.getHeader("Retry-After")).isNotNull();
                assertThat(AuthenticationAudit.reasonOf(failure)).isEqualTo(expected.path("reason").asString());
                assertThat(AuthenticationAudit.errorCodeOf(AuthenticationAudit.reasonOf(failure))).isEqualTo(expected.path("errorCode").asString());
            }
        }
    }

    @org.junit.jupiter.api.Test
    void anAgentTokenThatEndsLaterThanItsLifetimeFromNowIsRefusedWhateverItsIat() {
        Instant now = Instant.parse("2026-11-24T12:00:00Z");
        AgentClient entry = new AgentClient("agent-reports", "sa-1", "owner-1", Risk.READ_ONLY, List.of(), false, "admin-1", Instant.EPOCH, null, null);
        AgentRegistry registry = new AgentRegistry(() -> List.of(entry), java.time.Duration.ofSeconds(5), System::nanoTime, new SimpleMeterRegistry());
        PrincipalClassifier classifier = new PrincipalClassifier(registry, java.time.Clock.fixed(now, java.time.ZoneOffset.UTC), java.time.Duration.ofSeconds(60));

        assertThat(classifier.classify("agent-reports", "sa-1", true, now.plusSeconds(1000), now.plusSeconds(1300)))
                .as("an iat in the future makes exp - iat 300 s, but the token would live 1300 s").isInstanceOf(PrincipalClassifier.Classification.Refused.class);
        assertThat(classifier.classify("agent-reports", "sa-1", true, now.plusSeconds(60), now.plusSeconds(360))).isInstanceOf(PrincipalClassifier.Classification.Agent.class);
        assertThat(classifier.classify("agent-reports", "sa-1", true, now.minusSeconds(100), now.plusSeconds(200))).isInstanceOf(PrincipalClassifier.Classification.Agent.class);
    }

    @org.junit.jupiter.api.Test
    void theCeilingNeverLetsAForbiddenGroupThroughEvenIfItWasStored() {
        AgentClient entry = new AgentClient("agent-reports", "sa-1", "owner-1", Risk.READ_ONLY,
                List.of("mcp-jira-read", "mcp-jira-destructive", "mcp-platform-admin"), false, "admin-1", Instant.EPOCH, null, null);

        assertThat(entry.narrow(List.of("mcp-platform-admin", "mcp-jira-destructive", "mcp-jira-read", "mcp-other"))).containsExactly("mcp-jira-read");
    }

    private static final McpServer SERVER = new McpServer("mcp-jira", "jira", URI.create("https://mcp-jira.internal:8443/mcp"), "1.0.0", true,
            new CredentialPolicy(true, Set.of("user-secret"), List.of(), false, "user-secret"), Map.of());

    /** The ceiling of risk of an agent in the list and in the order of the call, with a Cedar that allows everything. */
    private static void checkCeiling(JsonNode vector) {
        JsonNode input = vector.path("input");
        JsonNode expected = vector.path("expected");
        Risk maxRisk = Risk.valueOf(input.path("maxRisk").asString());
        Risk toolRisk = Risk.valueOf(input.path("toolRisk").asString());
        AgentClient entry = new AgentClient("agent-reports", "sa-1", "owner-1", maxRisk, List.of(), false, "admin-1", Instant.EPOCH, null, null);
        AgentRegistry registry = new AgentRegistry(() -> List.of(entry), java.time.Duration.ofSeconds(5), System::nanoTime, new SimpleMeterRegistry());
        ToolAuthorizer cedarAllowsAll = new ToolAuthorizer() {
            @Override
            public ToolDecision decide(GatewayUser user, McpServer server, ToolDefinition tool, JsonNode arguments) {
                return ToolDecision.allow();
            }

            @Override
            public ToolDecision toolLevel(GatewayUser user, McpServer server, ToolDefinition tool) {
                return ToolDecision.allow();
            }

            @Override
            public List<String> requiredEntitlements(McpServer server, ToolDefinition tool) {
                return List.of();
            }

            @Override
            public long policyRevision() {
                return 1;
            }
        };
        GatewayUser agent = new GatewayUser("sa-1", "service-account-agent-reports", "agent-reports", List.of(), "t",
                new GatewayUser.Agent("agent-reports", "owner-1"));
        ToolDefinition tool = new ToolDefinition("some_tool", toolRisk, "read", null, "x", false, List.of());
        AgentCeilingAuthorizer authorizer = new AgentCeilingAuthorizer(cedarAllowsAll, registry);

        if ("list".equals(input.path("event").asString())) {
            assertThat(authorizer.mayCall(agent, SERVER, tool)).as(vector.path("description").asString()).isEqualTo(expected.path("listed").asBoolean());
            return;
        }
        ToolDecision level = authorizer.toolLevel(agent, SERVER, tool);
        CallOrder.Verdict verdict = CallOrder.decide(level.allowed(), true, () -> KillSwitches.Status.OFF, () -> true, () -> true, () -> true,
                () -> !tool.requiresConfirmation(), () -> true);
        assertThat(verdict.passes()).as(vector.path("description").asString()).isEqualTo(expected.path("allowed").asBoolean());
        if (!verdict.passes()) {
            assertThat(verdict.errorCode()).isEqualTo(expected.path("errorCode").asString());
            // A refusal at the level of the tool says not_granted in the order of the checks and names its reason in the decision.
            assertThat(level.allowed() ? verdict.auditReason() : level.reason()).isEqualTo(expected.path("auditReason").asString());
            assertThat(expected.path("confirmationCreated").asBoolean(false)).isFalse();
        }
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
        } else if ("user_streams_limit_reached".equals(input.path("reason").asString())) {
            write(response, RateLimitResponse.of("0192d1b2-7c3a-7d4e-8f10-2a3b4c5d6e7f", 2));
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
