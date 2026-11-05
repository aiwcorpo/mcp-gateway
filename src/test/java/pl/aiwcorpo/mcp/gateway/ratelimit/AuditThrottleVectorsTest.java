package pl.aiwcorpo.mcp.gateway.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import pl.aiwcorpo.mcp.gateway.support.Vectors;
import tools.jackson.databind.JsonNode;

/** The vectors {@code endpoint-aggregate/audit-throttle-*} (CC-190, CC-191) on the rule the gateway applies. */
class AuditThrottleVectorsTest {

    @TestFactory
    List<DynamicTest> everyVector() {
        List<Vectors.Vector> vectors = Vectors.of("endpoint-aggregate").stream()
                .filter(v -> "audit-throttle".equals(v.document().path("kind").asString())).toList();
        assertThat(vectors).hasSize(12);
        return vectors.stream().map(v -> DynamicTest.dynamicTest(v.name(), () -> check(v.document()))).toList();
    }

    private static void check(JsonNode vector) {
        JsonNode input = vector.path("input");
        long interval = input.has("intervalSeconds") ? input.path("intervalSeconds").asLong() * 1000 : 10_000;
        int max = input.has("maxTargetsPerSub") ? input.path("maxTargetsPerSub").asInt() : 50;
        AuditThrottleCore<String> core = new AuditThrottleCore<>(interval, max);
        List<Boolean> audited = new ArrayList<>();
        Map<String, Integer> suppressed = new TreeMap<>();
        List<AuditThrottleCore.Summary<String>> summaries = new ArrayList<>();
        long last = 0;
        for (JsonNode event : input.path("events")) {
            long now = event.path("t").asLong() * 1000;
            last = now;
            summaries.addAll(core.closeDue(now));
            boolean due = core.admit(now, event.path("sub").asString(), event.path("reason").asString(), event.path("target").asString(), "user");
            audited.add(due);
            if (!due) {
                suppressed.merge(event.path("reason").asString(), 1, Integer::sum);
            }
        }
        long flushAt = input.has("flushAt") ? input.path("flushAt").asLong() * 1000 : last + interval;
        summaries.addAll(core.closeDue(flushAt));

        JsonNode expected = vector.path("expected");
        List<Boolean> wantAudited = new ArrayList<>();
        expected.path("decisions").forEach(d -> {
            assertThat(d.path("rejected").asBoolean()).as("a refusal is never affected").isTrue();
            wantAudited.add(d.path("audited").asBoolean());
        });
        assertThat(audited).isEqualTo(wantAudited);
        Map<String, Integer> wantSuppressed = new TreeMap<>();
        expected.path("suppressed").properties().forEach(e -> wantSuppressed.put(e.getKey(), e.getValue().asInt()));
        assertThat(suppressed).isEqualTo(wantSuppressed);
        List<String> want = new ArrayList<>();
        expected.path("summaries").forEach(s -> want.add(s.path("t").asLong() + " " + s.path("sub").asString() + " " + s.path("reason").asString()
                + " " + s.path("suppressedCount").asInt() + " " + s.path("suppressedTargets").asInt()));
        List<String> got = new ArrayList<>();
        summaries.forEach(s -> got.add(s.closedAtMillis() / 1000 + " " + s.sub() + " " + s.reason() + " " + s.suppressedCount() + " " + s.suppressedTargets()));
        assertThat(got).isEqualTo(want);
    }
}
