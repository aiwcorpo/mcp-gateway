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
                "tool".equals(s.path("scope").asString()) ? s.path("tool").asString() : null, "admin", Instant.EPOCH, "test",
                "resource".equals(s.path("scope").asString()) ? s.path("resource").asString() : null,
                "prompt".equals(s.path("scope").asString()) ? s.path("prompt").asString() : null)));
        return new KillSwitches(() -> {
            if (!readable) {
                throw new IllegalStateException("database down");
            }
            return entries;
        }, Duration.ofSeconds(5), System::nanoTime, new SimpleMeterRegistry());
    }

    /**
     * The vectors of 8.0.0 by kind: the switches of a tool and a server have no kind (18); {@code agent-switch} (5) is the suspension of an
     * agent (CC-266), for the slice with the agent registry; {@code primitive-switch} (21) is the switch of a resource or a prompt (CC-265).
     * Of those, {@code list} runs here (what a switch hides) and {@code lift} in KillSwitchApiTest (the database); {@code read} is the
     * refusal of resources/read and prompts/get on /mcp (-32602, order of the checks), which comes with the dispatch of those methods.
     */
    private static boolean isTool(Vectors.Vector vector) {
        return !vector.document().has("kind");
    }

    private static boolean isListOfPrimitive(Vectors.Vector vector) {
        return "primitive-switch".equals(vector.document().path("kind").asString()) && "list".equals(vector.document().path("input").path("event").asString());
    }

    @TestFactory
    List<DynamicTest> callsConfirmationsAndLists() {
        List<Vectors.Vector> vectors = Vectors.of("kill-switch");
        assertThat(vectors).hasSize(44);
        assertThat(vectors.stream().filter(v -> "agent-switch".equals(v.document().path("kind").asString()))).hasSize(5);
        assertThat(vectors.stream().filter(v -> "primitive-switch".equals(v.document().path("kind").asString())
                && "read".equals(v.document().path("input").path("event").asString()))).as("left for the dispatch of resources/read and prompts/get").hasSize(14);
        List<DynamicTest> tests = new ArrayList<>();
        for (Vectors.Vector vector : vectors) {
            if (isListOfPrimitive(vector)) {
                tests.add(DynamicTest.dynamicTest(vector.name(), () -> checkListOfPrimitive(vector.document())));
                continue;
            }
            String event = vector.document().path("input").path("event").asString();
            if (!isTool(vector) || !HANDLED_HERE.contains(event)) {
                continue;
            }
            tests.add(DynamicTest.dynamicTest(vector.name(), () -> check(vector.document())));
        }
        assertThat(tests).hasSizeGreaterThanOrEqualTo(11 + 7);
        return tests;
    }

    private static void checkListOfPrimitive(JsonNode vector) {
        JsonNode input = vector.path("input");
        JsonNode target = input.path("target");
        boolean readable = input.path("storeReadable").asBoolean(true);
        KillSwitches switches = switchesOf(input, readable);
        String serverId = target.path("serverId").asString();
        KillSwitches.Status status = "prompt".equals(target.path("kind").asString()) ? switches.statusOfPrompt(serverId, target.path("name").asString())
                : switches.statusOfResource(serverId, target.path("name").asString());
        assertThat(readable && status == KillSwitches.Status.OFF).as(vector.path("description").asString())
                .isEqualTo(vector.path("expected").path("listed").asBoolean());
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
        Set<String> kinds = new TreeSet<>();
        Vectors.of("kill-switch").forEach(v -> {
            kinds.add(v.document().path("kind").asString("tool"));
            if (isTool(v)) {
                events.add(v.document().path("input").path("event").asString());
            }
        });
        return List.of(DynamicTest.dynamicTest("events of the vectors", () -> {
            assertThat(events).containsExactlyInAnyOrder("call", "confirm", "list", "approve", "register", "lift-tool", "lift-server", "catalog");
            assertThat(kinds).containsExactlyInAnyOrder("tool", "agent-switch", "primitive-switch");
        }));
    }
}
