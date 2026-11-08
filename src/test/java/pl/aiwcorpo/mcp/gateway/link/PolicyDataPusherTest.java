package pl.aiwcorpo.mcp.gateway.link;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import pl.aiwcorpo.mcp.cedar.entities.ResourceTypes;
import pl.aiwcorpo.mcp.cedar.entities.ScopeMapping;
import pl.aiwcorpo.mcp.gateway.policy.PolicyService;
import pl.aiwcorpo.mcp.gateway.registry.ServerConfig;
import pl.aiwcorpo.mcp.gateway.server.ServerRegistry;
import pl.aiwcorpo.mcp.gateway.support.Configs;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * When the gateway pushes policy data (C14, CC-249): to a server whose connection is approved, after every change of the revision and at least every
 * minute, a push that failed again after a pause, and nothing to a server whose connection waits or that is switched off.
 */
class PolicyDataPusherTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    private final AtomicLong revision = new AtomicLong(1);
    private final AtomicLong now = new AtomicLong();
    private final AtomicBoolean delivered = new AtomicBoolean(true);
    private final List<Long> pushed = new CopyOnWriteArrayList<>();
    private final List<JsonNode> bodies = new CopyOnWriteArrayList<>();
    private final ServerRegistry servers = new ServerRegistry();
    private PolicyDataPusher pusher;

    @BeforeEach
    void start() {
        PolicyService policies = mock(PolicyService.class);
        when(policies.snapshot()).thenAnswer(call -> new PolicyService.Snapshot(revision.get(), ResourceTypes.empty(), ScopeMapping.empty(), null,
                List.of(), Map.of(), Map.of(), List.of(), null));
        when(policies.dataFor("mcp-jira")).thenAnswer(call -> Optional.of(new PolicyService.ServerData(revision.get(), "sha256:" + "a".repeat(64),
                ScopeMapping.empty(), List.of("claude-code"), List.of())));
        ServerLinks links = mock(ServerLinks.class);
        when(links.pushPolicyData(any(), eq("mcp-jira"), any(), any(), anyLong(), any())).thenAnswer(call -> {
            pushed.add(call.getArgument(4));
            bodies.add(call.getArgument(5));
            return new ServerLinks.Push(delivered.get(), delivered.get() ? 200 : 0, null, delivered.get() ? null : ServerLinks.Failure.UNREACHABLE);
        });
        servers.replaceConfigs(List.of(Configs.connected("mcp-jira", "jira", URI.create("https://mcp-jira.test:8443/mcp"),
                new ServerConfig.Credential(true, List.of("user-secret"), "user-secret"), true, false)));
        pusher = new PolicyDataPusher(policies, servers, links, JSON, Duration.ofHours(1), Duration.ofSeconds(60),
                Duration.ofSeconds(10), now::get);
    }

    @AfterEach
    void stop() {
        pusher.destroy();
    }

    private void tickAndWait(int expectedPushes) {
        pusher.tick();
        await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> assertThat(pushed).hasSize(expectedPushes));
        // A push in flight holds the server: the next tick would skip it.
        await().atMost(Duration.ofSeconds(5)).pollDelay(Duration.ofMillis(20)).until(() -> true);
    }

    private void after(Duration time) {
        now.addAndGet(time.toNanos());
    }

    @Test
    void theFirstTickPushesAndAnUnchangedRevisionIsNotPushedAgainBeforeTheMinuteIsOut() {
        tickAndWait(1);
        assertThat(bodies.getFirst().path("revision").asLong()).isEqualTo(1);
        assertThat(bodies.getFirst().path("allowedClients").toString()).isEqualTo("[\"claude-code\"]");

        after(Duration.ofSeconds(30));
        pusher.tick();
        assertThat(pushed).as("same revision, half a minute").hasSize(1);

        after(Duration.ofSeconds(31));
        tickAndWait(2);
        assertThat(pushed).as("a server loses its data with a restart, so the data is pushed every minute").containsExactly(1L, 1L);
    }

    @Test
    void everyChangeOfTheRevisionIsPushedAtOnce() {
        tickAndWait(1);

        revision.set(2);
        after(Duration.ofSeconds(1));
        tickAndWait(2);
        revision.set(3);
        after(Duration.ofSeconds(1));
        tickAndWait(3);

        assertThat(pushed).containsExactly(1L, 2L, 3L);
    }

    @Test
    void aPushThatFailedIsTriedAgainAfterAPauseAndNotAtEveryTick() {
        delivered.set(false);
        tickAndWait(1);

        after(Duration.ofSeconds(5));
        pusher.tick();
        assertThat(pushed).as("too soon after a failure").hasSize(1);

        delivered.set(true);
        after(Duration.ofSeconds(6));
        tickAndWait(2);
        after(Duration.ofSeconds(1));
        pusher.tick();
        assertThat(pushed).as("delivered: back to the rhythm of the revision and the minute").hasSize(2);
    }

    @Test
    void aServerWhoseConnectionWaitsOrIsSwitchedOffGetsNothing() {
        servers.replaceConfigs(List.of(Configs.waiting("mcp-jira", "jira", URI.create("https://mcp-jira.test:8443/mcp"),
                new ServerConfig.Credential(true, List.of("user-secret"), "user-secret"))));
        pusher.tick();
        assertThat(pushed).as("nothing is sent to an address nobody approved").isEmpty();

        servers.replaceConfigs(List.of(Configs.connected("mcp-jira", "jira", URI.create("https://mcp-jira.test:8443/mcp"),
                new ServerConfig.Credential(true, List.of("user-secret"), "user-secret"), false, false)));
        pusher.tick();
        assertThat(pushed).as("a server that is switched off").isEmpty();
    }

    @Test
    void theToolCallPathPushesAtOnceWhateverTheTimer() {
        revision.set(7);

        boolean ok = pusher.push(servers.find("mcp-jira").orElseThrow());

        assertThat(ok).isTrue();
        assertThat(pushed).containsExactly(7L);
        delivered.set(false);
        assertThat(pusher.push(servers.find("mcp-jira").orElseThrow())).isFalse();
    }
}
