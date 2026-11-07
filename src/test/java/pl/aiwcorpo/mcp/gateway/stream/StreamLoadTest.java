package pl.aiwcorpo.mcp.gateway.stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.OutputStream;
import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import pl.aiwcorpo.mcp.gateway.GatewayTestBase;
import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.authz.ToolAccess;
import pl.aiwcorpo.mcp.gateway.authz.ToolAuthorizer;
import pl.aiwcorpo.mcp.gateway.killswitch.KillSwitchStore;
import pl.aiwcorpo.mcp.gateway.killswitch.KillSwitches;
import pl.aiwcorpo.mcp.gateway.registry.DefinitionGuard;
import pl.aiwcorpo.mcp.gateway.server.CredentialPolicy;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.server.Risk;
import pl.aiwcorpo.mcp.gateway.server.ServerRegistry;
import pl.aiwcorpo.mcp.gateway.server.ToolDefinition;
import pl.aiwcorpo.mcp.manifest.EndpointFilter;
import tools.jackson.databind.json.JsonMapper;

/**
 * Many streams and one change (CC-192: the notification at the latest 5 s after the event). The streams of this instance are real, the
 * policies are the real Cedar of the shared context, the server has 253 tools. The size is set by the properties
 * {@code streams.load.identities} (default 60) and {@code streams.load.perIdentity} (default 4); the reference measurement was made with
 * 500 and 4 (2000 streams). The numbers go to the output; the assertion is the 5 s and that a client list is not starved meanwhile.
 */
class StreamLoadTest extends GatewayTestBase {

    private static final int TOOLS = 253;

    @Autowired
    ToolAuthorizer authorizer;

    private static McpServer server(Map<String, Risk> risks) {
        Map<String, ToolDefinition> tools = new LinkedHashMap<>();
        for (int i = 0; i < TOOLS; i++) {
            String name = String.format("tool_%03d", i);
            Risk risk = risks.getOrDefault(name, i % 5 == 0 ? Risk.UPDATE : Risk.READ_ONLY);
            tools.put(name, new ToolDefinition(name, risk, risk == Risk.READ_ONLY ? "read" : "update", name, "Tool " + i, false, List.of()));
        }
        return new McpServer("mcp-jira", "jira", URI.create("https://mcp-jira.internal:8443/mcp"), "1.0.0", true,
                new CredentialPolicy(true, Set.of("user-secret"), List.of(), false, "user-secret"), tools);
    }

    @Test
    void oneChangeReachesEveryStreamWithinFiveSecondsAndLeavesTheListsOfClientsAlone() throws Exception {
        int identities = Integer.getInteger("streams.load.identities", 60);
        int perIdentity = Integer.getInteger("streams.load.perIdentity", 4);
        int total = identities * perIdentity;
        AtomicReference<McpServer> current = new AtomicReference<>(server(Map.of()));
        ServerRegistry registry = mock(ServerRegistry.class);
        when(registry.all()).thenAnswer(call -> List.of(current.get()));
        List<KillSwitchStore.Entry> switched = new java.util.concurrent.CopyOnWriteArrayList<>();
        KillSwitches switches = new KillSwitches(() -> switched, Duration.ofSeconds(5), System::nanoTime, new SimpleMeterRegistry());
        ToolAccess access = new ToolAccess(authorizer);
        UserToolLists lists = new UserToolLists(registry, access, switches, mock(DefinitionGuard.class));
        when(registry.find("mcp-jira")).thenAnswer(call -> java.util.Optional.of(current.get()));
        DefinitionGuard guard = mock(DefinitionGuard.class);
        when(guard.lastKnownIntact(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any())).thenReturn(true);
        UserToolLists listsOfStreams = new UserToolLists(registry, access, switches, guard);
        ToolStreams streams = new ToolStreams(listsOfStreams, Duration.ofSeconds(15), Duration.ofSeconds(1), System::currentTimeMillis,
                new SimpleMeterRegistry(), id -> true, JsonMapper.builder().build(), total + 10, 4, Duration.ofMillis(100));
        switches.onChange(streams::changed);

        AtomicInteger notified = new AtomicInteger();
        List<ToolStreams.Stream> open = new ArrayList<>();
        List<Thread> serving = new ArrayList<>();
        List<GatewayUser> users = new ArrayList<>();
        long openStarted = System.nanoTime();
        for (int i = 0; i < identities; i++) {
            users.add(new GatewayUser("load-" + i, "user" + i, "claude-code", List.of("mcp-jira-read", "mcp-jira-write"), "unused"));
        }
        // The opening computes one list per identity, the other streams of it find the decisions.
        List<Thread> openers = new ArrayList<>();
        Object lock = new Object();
        for (GatewayUser user : users) {
            openers.add(Thread.ofVirtual().start(() -> {
                for (int k = 0; k < perIdentity; k++) {
                    ToolStreams.Stream stream = streams.open(ToolStreams.Kind.SESSION, user, "s", EndpointFilter.none(), null, null, null, true).orElseThrow();
                    synchronized (lock) {
                        open.add(stream);
                    }
                    serving.add(Thread.ofVirtual().start(() -> stream.serve(new OutputStream() {
                        private final StringBuilder seen = new StringBuilder();

                        @Override
                        public void write(int b) {
                            seen.append((char) b);
                        }

                        @Override
                        public void write(byte[] bytes, int from, int length) {
                            String text = new String(bytes, from, length, java.nio.charset.StandardCharsets.UTF_8);
                            if (text.contains("list_changed")) {
                                notified.incrementAndGet();
                            }
                        }
                    })));
                }
            }));
        }
        for (Thread opener : openers) {
            opener.join();
        }
        long openMillis = (System.nanoTime() - openStarted) / 1_000_000;
        assertThat(streams.openCount()).isEqualTo(total);

        // Baseline of a client's list of 253 tools, then the same while the streams are woken by a change.
        GatewayUser client = new GatewayUser("a-client", "client", "claude-code", List.of("mcp-jira-read", "mcp-jira-write"), "unused");
        List<ToolDefinition> all = new ArrayList<>(current.get().tools().values());
        long baseline = timeMillis(() -> access.mayCall(client, current.get(), all));

        long started = System.nanoTime();
        switched.add(new KillSwitchStore.Entry("mcp-jira", "tool_001", "admin", java.time.Instant.now(), "load"));
        switches.refresh();
        long duringStorm = timeMillis(() -> access.mayCall(client, current.get(), all));
        while (notified.get() < total && System.nanoTime() - started < Duration.ofSeconds(60).toNanos()) {
            Thread.sleep(20);
        }
        long switchMillis = (System.nanoTime() - started) / 1_000_000;
        int afterSwitch = notified.get();

        // A change of the registry in one tool (its risk): the decision of Cedar is made again for that tool only, once per identity.
        Thread.sleep(1200);
        notified.set(0);
        started = System.nanoTime();
        current.set(server(Map.of("tool_002", Risk.DESTRUCTIVE)));
        streams.changed();
        while (notified.get() < total && System.nanoTime() - started < Duration.ofSeconds(60).toNanos()) {
            Thread.sleep(20);
        }
        long registryMillis = (System.nanoTime() - started) / 1_000_000;
        int afterRegistry = notified.get();

        // A new bundle of policies: every identity needs all its decisions again; this is the cost of a policy change, with no promise of 5 s.
        started = System.nanoTime();
        listsOfStreams.policiesChanged();
        List<Thread> recomputing = new ArrayList<>();
        for (GatewayUser user : users) {
            recomputing.add(Thread.ofVirtual().start(() -> listsOfStreams.of(user)));
        }
        for (Thread thread : recomputing) {
            thread.join();
        }
        long policyMillis = (System.nanoTime() - started) / 1_000_000;

        System.out.printf("STREAM-LOAD: %d streams of %d identities, %d tools, %d cores. Opening %d ms. Client list of 253 tools: %d ms alone, %d ms during the storm."
                        + " One switch: %d of %d notified in %d ms. One tool changed in the registry: %d of %d in %d ms. New policies, every identity again: %d ms.%n",
                total, identities, TOOLS, Runtime.getRuntime().availableProcessors(), openMillis, baseline, duringStorm, afterSwitch, total, switchMillis,
                afterRegistry, total, registryMillis, policyMillis);
        open.forEach(stream -> stream.close("test"));
        for (Thread thread : serving) {
            thread.join(5000);
        }
        assertThat(afterSwitch).as("every stream heard of the switch").isEqualTo(total);
        assertThat(switchMillis).isLessThan(5000);
        assertThat(afterRegistry).as("every stream heard of the tool").isEqualTo(total);
        assertThat(registryMillis).isLessThan(5000);
        assertThat(duringStorm).as("a client's list is not starved by the storm").isLessThan(3000);
    }

    private static long timeMillis(Runnable work) {
        long started = System.nanoTime();
        work.run();
        return (System.nanoTime() - started) / 1_000_000;
    }
}
