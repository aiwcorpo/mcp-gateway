package pl.aiwcorpo.mcp.gateway.mcp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.Test;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import pl.aiwcorpo.mcp.gateway.audit.AuditLog;
import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.auth.PublicUrls;
import pl.aiwcorpo.mcp.gateway.authz.ToolAuthorizer;
import pl.aiwcorpo.mcp.gateway.authz.ToolDecision;
import pl.aiwcorpo.mcp.gateway.broker.CredentialService;
import pl.aiwcorpo.mcp.gateway.confirm.ConfirmationService;
import pl.aiwcorpo.mcp.gateway.ratelimit.RateLimitAuditThrottle;
import pl.aiwcorpo.mcp.gateway.ratelimit.RateLimiter;
import pl.aiwcorpo.mcp.gateway.registry.DefinitionGuard;
import pl.aiwcorpo.mcp.gateway.registry.RegistryService;
import pl.aiwcorpo.mcp.gateway.server.CredentialPolicy;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.server.Risk;
import pl.aiwcorpo.mcp.gateway.server.ServerRegistry;
import pl.aiwcorpo.mcp.gateway.server.ToolDefinition;
import pl.aiwcorpo.mcp.gateway.upstream.UpstreamSessions;
import pl.aiwcorpo.mcp.manifest.EndpointFilter;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * A policy that could not decide is not a policy that said no (CC-178 asks for mayCall, but a failure of the policy service is not a
 * missing right): the client is told the service failed, with the real reason in the audit, and not that the tool does not exist.
 */
class UndecidedPolicyTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    private String answer(ToolDecision toolLevel, String auditReason) throws Exception {
        ToolDefinition tool = new ToolDefinition("get_issue", Risk.READ_ONLY, "read", null, "x", false, List.of());
        McpServer server = new McpServer("mcp-jira", "jira", URI.create("https://mcp-jira.internal:8443/mcp"), "1.0.0", true,
                new CredentialPolicy(false, Set.of(), List.of(), false, null), Map.of("get_issue", tool));
        ServerRegistry registry = mock(ServerRegistry.class);
        when(registry.resolveForCall("jira__get_issue")).thenReturn(Optional.of(new ServerRegistry.Resolved(server, tool)));
        ToolAuthorizer authorizer = mock(ToolAuthorizer.class);
        when(authorizer.toolLevel(any(), any(), any())).thenReturn(toolLevel);
        RateLimiter limiter = mock(RateLimiter.class);
        when(limiter.check(any(), any(), any(), any())).thenReturn(Optional.empty());
        SimpleMeterRegistry meters = new SimpleMeterRegistry();
        AuditLog audit = new AuditLog();
        List<String> reasons = new java.util.ArrayList<>();
        audit.listen(event -> reasons.add(String.valueOf(event.view().get("reason"))));
        McpGatewayService service = new McpGatewayService(registry, new PublicUrls(URI.create("https://mcp.aiwcorpo.pl"), false),
                mock(UpstreamSessions.class), mock(CredentialService.class), authorizer, audit, new ToolErrors(JSON), JSON, meters,
                "mcp-gateway", mock(ConfirmationService.class), mock(RegistryService.class), mock(DefinitionGuard.class), limiter,
                new RateLimitAuditThrottle(Duration.ofSeconds(10), System::nanoTime, meters),
                new ToolsListCursor("0123456789abcdef".getBytes(), JSON), Duration.ofSeconds(3), Clock.systemUTC());
        GatewayUser user = new GatewayUser("sub-1", "alice", "claude-code", List.of("mcp-jira-read"), "token");
        CallContext ctx = new CallContext("01a19307-c3cb-77bb-8622-b2c6b6d53779", null, user, Target.aggregate(), EndpointFilter.none(),
                "2026-07-28", "m|sub-1|claude-code|mcp");
        ObjectNode params = JSON.createObjectNode();
        params.put("name", "jira__get_issue");
        params.putObject("arguments");
        JsonNode result = service.callTool(ctx, params);
        JsonNode error = JSON.readTree(result.path("content").get(0).path("text").asString());
        assertThat(reasons).contains(auditReason);
        return error.path("error").asString();
    }

    @Test
    void aPolicyServiceThatIsNotThereIsUpstreamUnavailable() throws Exception {
        assertThat(answer(ToolDecision.deny("policy_unavailable", List.of()), "policy_unavailable")).isEqualTo("upstream_unavailable");
    }

    @Test
    void aPolicyThatFailedToEvaluateIsAnInternalError() throws Exception {
        assertThat(answer(ToolDecision.deny("policy_error", List.of()), "policy_error")).isEqualTo("internal_error");
    }

    @Test
    void aDenialThatIsTheUsersIsNotFoundOrDenied() throws Exception {
        assertThat(answer(ToolDecision.deny("not_granted", List.of("mcp-jira-read")), "not_granted")).isEqualTo("not_found_or_denied");
        assertThat(answer(ToolDecision.deny("policy_forbid", List.of()), "not_granted")).isEqualTo("not_found_or_denied");
    }
}
