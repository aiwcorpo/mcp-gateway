package pl.aiwcorpo.mcp.gateway.mcp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import pl.aiwcorpo.mcp.gateway.audit.AuditLog;
import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.auth.PublicUrls;
import pl.aiwcorpo.mcp.gateway.authz.ToolAccess;
import pl.aiwcorpo.mcp.gateway.authz.ToolAuthorizer;
import pl.aiwcorpo.mcp.gateway.authz.ToolDecision;
import pl.aiwcorpo.mcp.gateway.broker.CredentialService;
import pl.aiwcorpo.mcp.gateway.confirm.ConfirmationService;
import pl.aiwcorpo.mcp.gateway.killswitch.KillSwitches;
import pl.aiwcorpo.mcp.gateway.ratelimit.EndpointAuditThrottle;
import pl.aiwcorpo.mcp.gateway.ratelimit.RateLimitAuditThrottle;
import pl.aiwcorpo.mcp.gateway.ratelimit.RateLimiter;
import pl.aiwcorpo.mcp.gateway.registry.DefinitionGuard;
import pl.aiwcorpo.mcp.gateway.registry.DefinitionGuard.Verdict;
import pl.aiwcorpo.mcp.gateway.registry.RegistryService;
import pl.aiwcorpo.mcp.gateway.server.CredentialPolicy;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.server.Risk;
import pl.aiwcorpo.mcp.gateway.server.ServerRegistry;
import pl.aiwcorpo.mcp.gateway.server.ToolDefinition;
import pl.aiwcorpo.mcp.gateway.upstream.UpstreamException;
import pl.aiwcorpo.mcp.gateway.upstream.UpstreamSessions;
import pl.aiwcorpo.mcp.manifest.EndpointFilter;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * The definitions of a server are read once per TTL however many admitted calls find the reading expired: the others wait for that
 * read, and a read that fails fails them all closed and is not kept. The tool is reported as changed so that a call ends at the
 * check of the definition and never reaches the server.
 */
class DefinitionReadSingleFlightTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final int CALLERS = 24;

    private final AtomicInteger toolsListCalls = new AtomicInteger();
    private final AtomicBoolean serverFails = new AtomicBoolean();
    private Duration toolsListTimeout = Duration.ofSeconds(5);
    private McpGatewayService service;

    private void setUp() throws Exception {
        ToolDefinition tool = new ToolDefinition("get_issue", Risk.READ_ONLY, "read", null, "x", false, List.of());
        McpServer server = new McpServer("mcp-jira", "jira", URI.create("https://mcp-jira.internal:8443/mcp"), "1.0.0", true,
                new CredentialPolicy(false, Set.of(), List.of(), false, null), Map.of("get_issue", tool), true);
        ServerRegistry registry = mock(ServerRegistry.class);
        when(registry.resolveForCall("jira__get_issue")).thenReturn(Optional.of(new ServerRegistry.Resolved(server, tool)));
        when(registry.find("mcp-jira")).thenReturn(Optional.of(server));
        ToolAuthorizer authorizer = mock(ToolAuthorizer.class);
        when(authorizer.toolLevel(any(), any(), any())).thenReturn(ToolDecision.allow());
        RateLimiter limiter = mock(RateLimiter.class);
        when(limiter.check(any(), any(), any(), any())).thenReturn(Optional.empty());
        KillSwitches killSwitches = mock(KillSwitches.class);
        when(killSwitches.status(anyString(), anyString())).thenReturn(KillSwitches.Status.OFF);
        UpstreamSessions upstream = mock(UpstreamSessions.class);
        when(upstream.call(any(), any(), any(), any(), any(), any(), any(), anyBoolean())).thenAnswer(invocation -> {
            toolsListCalls.incrementAndGet();
            Thread.sleep(300);
            if (serverFails.get()) {
                throw new UpstreamException(UpstreamException.Kind.UNAVAILABLE, "response not complete in time");
            }
            return JSON.readTree("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"get_issue\"}]}}");
        });
        RegistryService registryService = mock(RegistryService.class);
        when(registryService.observe(any(), any(), any())).thenReturn(Map.of("get_issue", Verdict.CHANGED));
        SimpleMeterRegistry meters = new SimpleMeterRegistry();
        AuditLog audit = new AuditLog();
        service = new McpGatewayService(registry, new PublicUrls(URI.create("https://mcp.aiwcorpo.pl"), false), upstream,
                mock(CredentialService.class), authorizer, audit, new ToolErrors(JSON), JSON, meters, "mcp-gateway",
                mock(ConfirmationService.class), registryService, new DefinitionGuard(Clock.systemUTC(), Duration.ofSeconds(60)), limiter,
                new RateLimitAuditThrottle(Duration.ofSeconds(10), System::nanoTime, meters),
                new EndpointAuditThrottle(Duration.ofSeconds(10), 50, System::currentTimeMillis, meters, audit, "mcp-gateway", () -> null),
                new ToolsListCursor("0123456789abcdef".getBytes(), JSON), killSwitches, new ToolAccess(authorizer),
                toolsListTimeout, Clock.systemUTC());
    }

    private String callOnce() throws Exception {
        GatewayUser user = new GatewayUser("sub-1", "alice", "claude-code", List.of("mcp-jira-read"), "token");
        CallContext ctx = new CallContext("01a19307-c3cb-77bb-8622-b2c6b6d53779", null, user, Target.aggregate(), EndpointFilter.none(),
                "2026-07-28", "m|sub-1|claude-code|mcp");
        ObjectNode params = JSON.createObjectNode();
        params.put("name", "jira__get_issue");
        params.putObject("arguments");
        JsonNode result = service.callTool(ctx, params);
        return JSON.readTree(result.path("content").get(0).path("text").asString()).path("error").asString();
    }

    private List<String> concurrentCalls() throws Exception {
        List<String> errors = new ArrayList<>();
        try (ExecutorService callers = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<String>> answers = new ArrayList<>();
            for (int i = 0; i < CALLERS; i++) {
                answers.add(callers.submit(this::callOnce));
            }
            for (Future<String> answer : answers) {
                errors.add(answer.get());
            }
        }
        return errors;
    }

    @Test
    void callersThatFindTheReadingExpiredShareOneRead() throws Exception {
        setUp();
        assertThat(concurrentCalls()).hasSize(CALLERS).allMatch("tool_disabled"::equals);
        assertThat(toolsListCalls.get()).as("tools/list requests to the server").isEqualTo(1);
    }

    @Test
    void aWaiterDoesNotGiveUpBeforeTheReadItWaitsForIsOver() throws Exception {
        toolsListTimeout = Duration.ofMillis(50);
        setUp();
        assertThat(concurrentCalls()).hasSize(CALLERS).allMatch("tool_disabled"::equals);
        assertThat(toolsListCalls.get()).isEqualTo(1);
    }

    @Test
    void aFailedReadFailsEveryWaiterClosedAndTheNextCallReadsAgain() throws Exception {
        setUp();
        serverFails.set(true);
        assertThat(concurrentCalls()).hasSize(CALLERS).allMatch("upstream_unavailable"::equals);
        assertThat(toolsListCalls.get()).isEqualTo(1);

        serverFails.set(false);
        assertThat(callOnce()).as("the failure was not kept").isEqualTo("tool_disabled");
        assertThat(toolsListCalls.get()).isEqualTo(2);
    }
}
