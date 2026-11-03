package pl.aiwcorpo.mcp.gateway.stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.ByteArrayOutputStream;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.manifest.EndpointFilter;
import tools.jackson.databind.json.JsonMapper;

/** The books of the open streams (CC-192): a stream that is never served does not stay in them, the limit of open streams, and the bounded and coalesced recomputation. */
class ToolStreamsTest {

    private static final GatewayUser USER = new GatewayUser("sub-1", "u", "claude-code", List.of("mcp-jira-read"), "t");

    private final SimpleMeterRegistry meters = new SimpleMeterRegistry();
    private final UserToolLists lists = mock(UserToolLists.class);

    private ToolStreams streams(int maxOpen, int parallelism, Duration debounce) {
        when(lists.of(any())).thenReturn(List.of());
        return new ToolStreams(lists, Duration.ofSeconds(15), Duration.ofSeconds(1), System::currentTimeMillis, meters, id -> true,
                JsonMapper.builder().build(), maxOpen, parallelism, debounce);
    }

    private Optional<ToolStreams.Stream> open(ToolStreams streams) {
        return streams.open(ToolStreams.Kind.SESSION, USER, "session", EndpointFilter.none(), null, null, true);
    }

    @Test
    void aStreamThatIsOpenedAndNeverServedIsOutOfTheBooksAfterItIsReleased() {
        ToolStreams streams = streams(10, 4, Duration.ZERO);
        ToolStreams.Stream stream = open(streams).orElseThrow();
        assertThat(streams.openCount()).isEqualTo(1);

        stream.release();
        stream.release();

        assertThat(streams.openCount()).as("once, however often it is released").isZero();
        assertThat(meters.get("mcp_gateway_open_streams").gauge().value()).isZero();
    }

    @Test
    void aStreamWhoseListCannotBeComputedIsNotLeftInTheBooks() {
        ToolStreams streams = streams(10, 4, Duration.ZERO);
        when(lists.of(any())).thenThrow(new IllegalStateException("policy"));

        org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class, () -> open(streams));

        assertThat(streams.openCount()).isZero();
    }

    @Test
    void overTheLimitTheStreamIsRefusedAndCounted() {
        ToolStreams streams = streams(2, 4, Duration.ZERO);
        ToolStreams.Stream first = open(streams).orElseThrow();
        open(streams).orElseThrow();

        assertThat(open(streams)).isEmpty();
        assertThat(meters.get("mcp_gateway_streams_refused_total").counter().count()).isEqualTo(1.0);
        assertThat(streams.openCount()).isEqualTo(2);

        first.release();
        assertThat(open(streams)).as("a place is free again").isPresent();
    }

    @Test
    void aBurstOfChangesIsOneComputationPerStreamAndFewListsAreComputedAtOnce() throws Exception {
        ToolStreams streams = streams(20, 2, Duration.ofMillis(150));
        AtomicInteger running = new AtomicInteger();
        AtomicInteger mostAtOnce = new AtomicInteger();
        AtomicInteger computations = new AtomicInteger();
        List<ToolStreams.Stream> open = new ArrayList<>();
        for (int i = 0; i < 6; i++) {
            open.add(open(streams).orElseThrow());
        }
        when(lists.of(any())).thenAnswer(call -> {
            int now = running.incrementAndGet();
            mostAtOnce.accumulateAndGet(now, Math::max);
            computations.incrementAndGet();
            Thread.sleep(100);
            running.decrementAndGet();
            return List.of();
        });
        List<Thread> servers = new ArrayList<>();
        for (ToolStreams.Stream stream : open) {
            servers.add(Thread.ofVirtual().start(() -> stream.serve(new ByteArrayOutputStream())));
        }
        Thread.sleep(200);

        for (int i = 0; i < 5; i++) {
            streams.changed();
        }

        await().atMost(Duration.ofSeconds(5)).until(() -> computations.get() >= 6);
        Thread.sleep(500);
        assertThat(computations.get()).as("one list per stream for the five changes").isEqualTo(6);
        assertThat(mostAtOnce.get()).as("two at a time").isLessThanOrEqualTo(2);
        open.forEach(stream -> stream.close("test"));
        for (Thread server : servers) {
            server.join(2000);
        }
        assertThat(streams.openCount()).isZero();
    }
}
