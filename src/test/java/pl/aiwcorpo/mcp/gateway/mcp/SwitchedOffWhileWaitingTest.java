package pl.aiwcorpo.mcp.gateway.mcp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

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
import pl.aiwcorpo.mcp.gateway.jwt.InternalTokenIssuer;
import pl.aiwcorpo.mcp.gateway.killswitch.KillSwitchStore;
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
import pl.aiwcorpo.mcp.gateway.upstream.StreamableHttpClient;
import pl.aiwcorpo.mcp.gateway.upstream.UpstreamRequest;
import pl.aiwcorpo.mcp.gateway.upstream.UpstreamResponse;
import pl.aiwcorpo.mcp.gateway.upstream.UpstreamSessions;
import pl.aiwcorpo.mcp.manifest.EndpointFilter;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * Calls admitted while the emergency switch was off and still waiting on their server (here for the definitions read in flight) are
 * checked again right before they are sent: a switch set meanwhile stops them, and no tools/call reaches the server (CC-194).
 */
class SwitchedOffWhileWaitingTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final int CALLERS = 3;

    private final AtomicInteger toolsListCalls = new AtomicInteger();
    private final AtomicInteger toolsCallCalls = new AtomicInteger();
    private final CountDownLatch releaseRead = new CountDownLatch(1);
    private final AtomicReference<List<KillSwitchStore.Entry>> switches = new AtomicReference<>(List.of());
    private KillSwitches killSwitches;
    private McpGatewayService service;

    private void setUp() throws Exception {
        ToolDefinition tool = new ToolDefinition("get_issue", Risk.READ_ONLY, "read", null, "x", false, List.of());
        McpServer server = new McpServer("mcp-jira", "jira", URI.create("https://mcp-jira.internal:8443/mcp"), "1.0.0", true,
                new CredentialPolicy(false, Set.of(), List.of(), false, null), Map.of("get_issue", tool));
        ServerRegistry registry = mock(ServerRegistry.class);
        when(registry.resolveForCall("jira__get_issue")).thenReturn(Optional.of(new ServerRegistry.Resolved(server, tool)));
        when(registry.find("mcp-jira")).thenReturn(Optional.of(server));
        ToolAuthorizer authorizer = mock(ToolAuthorizer.class);
        when(authorizer.toolLevel(any(), any(), any())).thenReturn(ToolDecision.allow());
        when(authorizer.decide(any(), any(), any(), any())).thenReturn(ToolDecision.allow());
        RateLimiter limiter = mock(RateLimiter.class);
        when(limiter.check(any(), any(), any(), any())).thenReturn(Optional.empty());
        SimpleMeterRegistry meters = new SimpleMeterRegistry();
        killSwitches = new KillSwitches(switches::get, Duration.ofMillis(5), System::nanoTime, meters);
        // The server: a session at once, its tools/list held until the test releases it.
        StreamableHttpClient http = mock(StreamableHttpClient.class);
        when(http.post(any(), any(), anyLong())).thenAnswer(invocation -> {
            UpstreamRequest sent = invocation.getArgument(0);
            return switch (JSON.readTree(sent.body()).path("method").asString()) {
                case "initialize" -> new UpstreamResponse(200, "session-1",
                        JSON.readTree("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-11-25\"}}"));
                case "tools/list" -> {
                    toolsListCalls.incrementAndGet();
                    releaseRead.await(20, TimeUnit.SECONDS);
                    yield new UpstreamResponse(200, null, JSON.readTree("{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"get_issue\"}]}}"));
                }
                case "tools/call" -> {
                    toolsCallCalls.incrementAndGet();
                    yield new UpstreamResponse(200, null, JSON.readTree("{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"content\":[]}}"));
                }
                default -> new UpstreamResponse(202, null, null);
            };
        });
        UpstreamSessions upstream = new UpstreamSessions(s -> http, s -> true, mock(InternalTokenIssuer.class), JSON, Duration.ofMinutes(5),
                Clock.systemUTC(), "mcp-gateway", "test");
        RegistryService registryService = mock(RegistryService.class);
        when(registryService.observe(any(), any(), any())).thenReturn(Map.of("get_issue", Verdict.INTACT));
        AuditLog audit = new AuditLog();
        service = new McpGatewayService(registry, new PublicUrls(URI.create("https://mcp.aiwcorpo.pl"), false), upstream,
                mock(CredentialService.class), authorizer, audit, new ToolErrors(JSON), JSON, meters, "mcp-gateway",
                mock(ConfirmationService.class), registryService, new DefinitionGuard(Clock.systemUTC(), Duration.ofSeconds(60)), limiter,
                new RateLimitAuditThrottle(Duration.ofSeconds(10), System::nanoTime, meters),
                new EndpointAuditThrottle(Duration.ofSeconds(10), 50, System::currentTimeMillis, meters, audit, "mcp-gateway", () -> 0L),
                new ToolsListCursor("0123456789abcdef".getBytes(), JSON), killSwitches, new ToolAccess(authorizer),
                Duration.ofSeconds(5), Clock.systemUTC(), Duration.ofSeconds(60));
    }

    private String callOnce() throws Exception {
        GatewayUser user = new GatewayUser("sub-1", "alice", "claude-code", List.of("mcp-jira-read"), "token");
        CallContext ctx = new CallContext("01a19307-c3cb-77bb-8622-b2c6b6d53779", null, user, Target.aggregate(), EndpointFilter.none(),
                "2026-07-28", "m|sub-1|claude-code|mcp");
        ObjectNode params = JSON.createObjectNode();
        params.put("name", "jira__get_issue");
        params.putObject("arguments");
        return new ToolErrors(JSON).codeOf(service.callTool(ctx, params));
    }

    @Test
    void aSwitchSetWhileCallsWaitOnTheServerStopsThemBeforeTheyAreSent() throws Exception {
        setUp();
        List<String> errors = new ArrayList<>();
        try (ExecutorService callers = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<String>> answers = new ArrayList<>();
            for (int i = 0; i < CALLERS; i++) {
                answers.add(callers.submit(this::callOnce));
            }
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (toolsListCalls.get() == 0 && System.nanoTime() < deadline) {
                Thread.sleep(10);
            }
            Thread.sleep(300); // the other callers join the read in flight
            assertThat(toolsListCalls.get()).as("the read is held by the server").isEqualTo(1);

            switches.set(List.of(new KillSwitchStore.Entry("mcp-jira", null, "admin", Instant.now(), "t")));
            killSwitches.refresh();
            assertThat(killSwitches.status("mcp-jira", "get_issue")).isEqualTo(KillSwitches.Status.ON);

            releaseRead.countDown();
            for (Future<String> answer : answers) {
                errors.add(answer.get(10, TimeUnit.SECONDS));
            }
        }
        assertThat(errors).hasSize(CALLERS).allMatch("tool_disabled"::equals);
        assertThat(toolsCallCalls.get()).as("tools/call requests to the server").isZero();
    }
}
