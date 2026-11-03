package pl.aiwcorpo.mcp.gateway.stream;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import pl.aiwcorpo.mcp.gateway.support.Vectors;
import pl.aiwcorpo.mcp.manifest.EndpointFilter;
import tools.jackson.databind.JsonNode;

/**
 * The vectors {@code list-changed}, {@code list-changed-sequence} and {@code list-changed-stateless} of {@code endpoint-aggregate/} on the
 * tracker that streams use (CC-176, CC-192, CC-207): when the list of a user, seen through the filter of the address, calls for a
 * notification, and the window of one second.
 */
class ListChangeVectorsTest {

    private static List<ListChangeTracker.Tool> tools(JsonNode array) {
        List<ListChangeTracker.Tool> out = new ArrayList<>();
        array.forEach(t -> out.add(new ListChangeTracker.Tool(t.path("name").asString(), t.path("risk").asString(),
                t.has("definitionHash") ? t.path("definitionHash").asString() : null)));
        return out;
    }

    private static long millis(JsonNode seconds) {
        return Math.round(seconds.asDouble() * 1000);
    }

    /** The times at which the tracker sends, for snapshots given with their times (the first one is the list at the opening). */
    private static List<Double> replay(EndpointFilter filter, JsonNode snapshots, long windowMillis) {
        ListChangeTracker tracker = new ListChangeTracker(filter, tools(snapshots.get(0).path("tools")), windowMillis);
        List<Double> sent = new ArrayList<>();
        for (int i = 1; i < snapshots.size(); i++) {
            tracker.observe(millis(snapshots.get(i).path("t")), tools(snapshots.get(i).path("tools"))).forEach(at -> sent.add(at / 1000.0));
        }
        tracker.advance(Long.MAX_VALUE - windowMillis).forEach(at -> sent.add(at / 1000.0));
        return sent;
    }

    @TestFactory
    List<DynamicTest> sequencesAndStatelessStreams() {
        List<DynamicTest> tests = new ArrayList<>();
        for (Vectors.Vector vector : Vectors.of("endpoint-aggregate")) {
            String kind = vector.document().path("kind").asString();
            JsonNode input = vector.document().path("input");
            JsonNode expected = vector.document().path("expected");
            if ("list-changed-sequence".equals(kind)) {
                tests.add(DynamicTest.dynamicTest(vector.name(), () -> {
                    long window = input.has("windowSeconds") ? millis(input.path("windowSeconds")) : 1000;
                    assertThat(replay(EndpointFilter.parse(input.path("query").asString()), input.path("snapshots"), window))
                            .as(vector.document().path("description").asString()).isEqualTo(seconds(expected.path("notifyAt")));
                }));
            } else if ("list-changed-stateless".equals(kind)) {
                tests.add(DynamicTest.dynamicTest(vector.name(), () -> {
                    // The list a tools/list read elsewhere returned (lastToolsListRead) is not a reference; the tracker never sees it.
                    ListChangeTracker tracker = new ListChangeTracker(EndpointFilter.parse(input.path("query").asString()),
                            tools(input.path("openedWith")), 1000);
                    List<Double> sent = new ArrayList<>();
                    for (JsonNode change : input.path("changes")) {
                        tracker.observe(millis(change.path("t")), tools(change.path("tools"))).forEach(at -> sent.add(at / 1000.0));
                    }
                    tracker.advance(Long.MAX_VALUE - 1000).forEach(at -> sent.add(at / 1000.0));
                    assertThat(sent).as(vector.document().path("description").asString()).isEqualTo(seconds(expected.path("notifyAt")));
                }));
            } else if ("list-changed".equals(kind)) {
                tests.add(DynamicTest.dynamicTest(vector.name(), () -> {
                    ListChangeTracker tracker = new ListChangeTracker(EndpointFilter.parse(input.path("query").asString()),
                            tools(input.path("before")), 1000);
                    boolean notified = !tracker.observe(5000, tools(input.path("after"))).isEmpty();
                    assertThat(notified).as(vector.document().path("description").asString()).isEqualTo(expected.path("notify").asBoolean());
                }));
            }
        }
        assertThat(tests).hasSize(11 + 7 + 4);
        return tests;
    }

    private static List<Double> seconds(JsonNode array) {
        List<Double> out = new ArrayList<>();
        array.forEach(n -> out.add(n.asDouble()));
        return out;
    }

    @Test
    void aChangeThatComesBackInsideTheWindowIsStillAnnouncedOnceAtTheEnd() {
        ListChangeTracker tracker = new ListChangeTracker(EndpointFilter.none(), List.of(new ListChangeTracker.Tool("jira__a", "READ_ONLY", null)), 1000);
        assertThat(tracker.observe(0, List.of())).containsExactly(0L);
        assertThat(tracker.observe(200, List.of(new ListChangeTracker.Tool("jira__a", "READ_ONLY", null)))).isEmpty();
        assertThat(tracker.nextDueAt()).isEqualTo(1000);
        assertThat(tracker.advance(999)).isEmpty();
        assertThat(tracker.advance(1000)).containsExactly(1000L);
        assertThat(tracker.nextDueAt()).isEqualTo(Long.MAX_VALUE);
    }
}
