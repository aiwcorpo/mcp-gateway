package pl.aiwcorpo.mcp.gateway.killswitch;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import pl.aiwcorpo.mcp.gateway.mcp.CallOrder;
import pl.aiwcorpo.mcp.gateway.support.Vectors;
import tools.jackson.databind.JsonNode;

/**
 * The vectors of {@code kill-switch/} (CC-194, CC-206) for what the gateway decides on a call, a confirmation and a list. The vectors that
 * lift a switch or approve and register around one run against the database in {@code KillSwitchApiTest}.
 */
class KillSwitchVectorsTest {

    private static final Set<String> HANDLED_HERE = Set.of("call", "confirm", "list", "catalog");

    private static KillSwitches switchesOf(JsonNode input, boolean readable) {
        List<KillSwitchStore.Entry> entries = new ArrayList<>();
        input.path("switches").forEach(s -> entries.add(new KillSwitchStore.Entry(s.path("serverId").asString(),
                "tool".equals(s.path("scope").asString()) ? s.path("tool").asString() : null, "admin", Instant.EPOCH, "test")));
        return new KillSwitches(() -> {
            if (!readable) {
                throw new IllegalStateException("database down");
            }
            return entries;
        }, Duration.ofSeconds(5), System::nanoTime, new SimpleMeterRegistry());
    }

    @TestFactory
    List<DynamicTest> callsConfirmationsAndLists() {
        List<Vectors.Vector> vectors = Vectors.of("kill-switch");
        assertThat(vectors).hasSize(18);
        List<DynamicTest> tests = new ArrayList<>();
        for (Vectors.Vector vector : vectors) {
            String event = vector.document().path("input").path("event").asString();
            if (!HANDLED_HERE.contains(event)) {
                continue;
            }
            tests.add(DynamicTest.dynamicTest(vector.name(), () -> check(vector.document())));
        }
        assertThat(tests).hasSizeGreaterThanOrEqualTo(11);
        return tests;
    }

    private static void check(JsonNode vector) {
        JsonNode input = vector.path("input");
        JsonNode expected = vector.path("expected");
        boolean readable = input.path("storeReadable").asBoolean(true);
        KillSwitches switches = switchesOf(input, readable);
        String qualified = input.path("tool").asString();
        int separator = qualified.indexOf("__");
        String serverId = "mcp-" + qualified.substring(0, separator);
        String tool = qualified.substring(separator + 2);
        if ("catalog".equals(input.path("event").asString())) {
            // The catalog answers 503 with Retry-After exactly when the switches cannot be read (CC-224), see AdminApiTest.
            assertThat(!switches.readable()).isEqualTo(expected.path("status").asInt() == 503);
            return;
        }
        if ("list".equals(input.path("event").asString())) {
            boolean listed = readable && switches.status(serverId, tool) == KillSwitches.Status.OFF;
            assertThat(listed).as(vector.path("description").asString()).isEqualTo(expected.path("listed").asBoolean());
            return;
        }
        CallOrder.Verdict verdict = CallOrder.decide(input.path("mayCall").asBoolean(true), input.path("inFilter").asBoolean(true),
                () -> switches.status(serverId, tool), () -> true, () -> true, () -> true, () -> true);
        assertThat(verdict.passes()).as(vector.path("description").asString()).isEqualTo(expected.path("allowed").asBoolean());
        if (!verdict.passes()) {
            assertThat(verdict.errorCode()).isEqualTo(expected.path("errorCode").asString());
            assertThat(verdict.auditReason()).isEqualTo(expected.path("auditReason").asString());
        }
    }

    @TestFactory
    List<DynamicTest> everyVectorIsAccountedFor() {
        Set<String> events = new TreeSet<>();
        Vectors.of("kill-switch").forEach(v -> events.add(v.document().path("input").path("event").asString()));
        return List.of(DynamicTest.dynamicTest("events of the vectors", () ->
                assertThat(events).containsExactlyInAnyOrder("call", "confirm", "list", "approve", "register", "lift-tool", "lift-server", "catalog")));
    }
}
