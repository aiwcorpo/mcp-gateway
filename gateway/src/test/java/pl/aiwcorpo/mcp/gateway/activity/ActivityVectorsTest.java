package pl.aiwcorpo.mcp.gateway.activity;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import pl.aiwcorpo.mcp.gateway.support.Contracts;
import pl.aiwcorpo.mcp.gateway.support.Vectors;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/** CC-095: the vectors of activity-calls/ (aggregation and the shape of a row) and activity-cursor/ (mcp-contracts 3.0.2). */
class ActivityVectorsTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    @TestFactory
    List<DynamicTest> aggregationAndRowShape() {
        List<DynamicTest> tests = new ArrayList<>();
        ActivityAggregator aggregator = new ActivityAggregator(JSON);
        List<Vectors.Vector> vectors = Vectors.of("activity-calls");
        assertThat(vectors).hasSizeGreaterThanOrEqualTo(38);
        for (Vectors.Vector vector : vectors) {
            JsonNode document = vector.document();
            if (document.has("events")) {
                tests.add(DynamicTest.dynamicTest(vector.name(), () -> {
                    List<JsonNode> events = new ArrayList<>();
                    document.path("events").forEach(events::add);
                    ObjectNode row = aggregator.aggregate(events, Instant.parse(document.path("now").asString()).toEpochMilli());
                    assertThat(row).as(document.path("description").asString()).isEqualTo(document.path("expected"));
                    assertThat(Contracts.gatewayAdminErrors("ActivityCall", row)).isEmpty();
                }));
            } else {
                tests.add(DynamicTest.dynamicTest(vector.name(), () -> {
                    boolean valid = document.path("expected").path("valid").asBoolean();
                    assertThat(Contracts.gatewayAdminErrors("ActivityCall", document.path("value")).isEmpty())
                            .as(document.path("description").asString()).isEqualTo(valid);
                }));
            }
        }
        return tests;
    }

    @TestFactory
    List<DynamicTest> cursor() {
        List<DynamicTest> tests = new ArrayList<>();
        List<Vectors.Vector> vectors = Vectors.of("activity-cursor");
        assertThat(vectors).hasSizeGreaterThanOrEqualTo(9);
        for (Vectors.Vector vector : vectors) {
            tests.add(DynamicTest.dynamicTest(vector.name(), () -> {
                JsonNode document = vector.document();
                ActivityCursor cursor = new ActivityCursor(document.path("key").asString().getBytes(StandardCharsets.UTF_8), JSON);
                JsonNode input = document.path("input");
                var position = cursor.open(input.path("sub").asString(), input.path("cursor").asString(),
                        Instant.parse(input.path("now").asString()).getEpochSecond());
                assertThat(position.isPresent()).as(document.path("description").asString())
                        .isEqualTo(document.path("expected").path("valid").asBoolean());
                position.ifPresent(p -> {
                    assertThat(p.ts()).isEqualTo(document.path("expected").path("position").path("ts").asString());
                    assertThat(p.requestId()).isEqualTo(document.path("expected").path("position").path("requestId").asString());
                });
            }));
        }
        return tests;
    }

    @org.junit.jupiter.api.Test
    void aCursorIssuedHereIsOpenedHereAndOnlyForTheSameUser() {
        ActivityCursor cursor = new ActivityCursor("a-key-of-sixteen-bytes-or-more".getBytes(StandardCharsets.UTF_8), JSON);
        String issued = cursor.issue("sub-1", new ActivityCursor.Position("2026-10-26T19:50:00.000Z", "req-1"), 1_000);
        assertThat(cursor.open("sub-1", issued, 1_100)).contains(new ActivityCursor.Position("2026-10-26T19:50:00.000Z", "req-1"));
        assertThat(cursor.open("sub-2", issued, 1_100)).isEmpty();
        assertThat(cursor.open("sub-1", issued, 1_000 + ActivityCursor.LIFETIME_SECONDS + 1)).isEmpty();
        assertThat(cursor.open("sub-1", issued, 999)).isEmpty();
    }
}
