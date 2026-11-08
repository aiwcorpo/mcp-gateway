package pl.aiwcorpo.mcp.gateway.registry;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import pl.aiwcorpo.mcp.gateway.support.Manifests;
import pl.aiwcorpo.mcp.gateway.support.Manifests.Tool;
import pl.aiwcorpo.mcp.gateway.support.Vectors;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * The vectors of {@code server-connection/} (CC-249): the approval of a connection, what a certificate does to an approved connection, the
 * first connection (everything pending), and when a tool is listed and callable.
 */
class ServerConnectionVectorsTest {

    private static String text(JsonNode node) {
        return node == null || node.isNull() ? null : node.asString();
    }

    @TestFactory
    List<DynamicTest> theVectors() {
        List<DynamicTest> tests = new ArrayList<>();
        for (Vectors.Vector vector : Vectors.of("server-connection")) {
            tests.add(DynamicTest.dynamicTest(vector.name(), () -> {
                JsonNode document = vector.document();
                switch (document.path("kind").asString()) {
                    case "approve" -> approve(document);
                    case "check" -> check(document);
                    case "availability" -> availability(document);
                    case "firstConnection" -> firstConnection(document);
                    default -> throw new AssertionError("unknown kind in " + vector.name());
                }
            }));
        }
        assertThat(tests).hasSize(24);
        return tests;
    }

    private void approve(JsonNode vector) {
        JsonNode input = vector.path("input").path("approve");
        JsonNode expected = vector.path("expected");
        JsonNode pending = input.path("pending");
        ServerConfig.PendingConnection waiting = pending.isNull() ? null : new ServerConfig.PendingConnection(pending.path("tlsMode").asString(),
                text(pending.get("fingerprint")), null, null, List.of(), null, pending.path("validatesAsCa").asBoolean(), "first_connection", Instant.now());
        boolean https = !"http".equals(input.path("scheme").asString("https"));

        ConnectionRules.Approval answer = ConnectionRules.approve(waiting, input.path("body").path("tlsMode").asString(),
                text(input.path("body").get("fingerprint")), https, input.path("addedWithAllowPlainHttp").asBoolean(false));

        String why = vector.path("description").asString();
        if (expected.path("status").asInt() == 200) {
            assertThat(answer).as(why).isInstanceOf(ConnectionRules.Approval.Accepted.class);
            ConnectionRules.Approval.Accepted accepted = (ConnectionRules.Approval.Accepted) answer;
            assertThat(accepted.tlsMode()).isEqualTo(expected.path("connection").path("tlsMode").asString());
            assertThat(accepted.fingerprint()).isEqualTo(text(expected.path("connection").get("fingerprint")));
        } else {
            assertThat(answer).as(why).isInstanceOf(ConnectionRules.Approval.Refused.class);
            ConnectionRules.Approval.Refused refused = (ConnectionRules.Approval.Refused) answer;
            assertThat(refused.status()).isEqualTo(expected.path("status").asInt());
            assertThat(refused.error()).isEqualTo(expected.path("error").asString());
            assertThat(refused.reason()).isEqualTo(text(expected.get("reason")));
        }
    }

    private void check(JsonNode vector) {
        JsonNode input = vector.path("input").path("check");
        JsonNode expected = vector.path("expected");

        ConnectionRules.Check verdict = ConnectionRules.check(input.path("approved").path("tlsMode").asString(),
                text(input.path("approved").get("fingerprint")), new ConnectionRules.Seen(text(input.path("presented").get("fingerprint")),
                        input.path("presented").path("validatesAsCa").asBoolean()));

        String why = vector.path("description").asString();
        assertThat(verdict.status()).as(why).isEqualTo(expected.path("status").asString());
        if (expected.has("pendingConnection")) {
            assertThat(verdict.pendingMode()).isEqualTo(expected.path("pendingConnection").path("tlsMode").asString());
            assertThat(verdict.pendingReason()).isEqualTo(expected.path("pendingConnection").path("reason").asString());
        } else {
            assertThat(verdict.pendingMode()).as(why).isNull();
        }
        if (expected.has("connectionRefreshed")) {
            assertThat(verdict.refreshed()).as(why).isEqualTo(expected.path("connectionRefreshed").asBoolean());
        }
    }

    private void availability(JsonNode vector) {
        JsonNode input = vector.path("input").path("availability");
        JsonNode expected = vector.path("expected");

        ConnectionRules.Availability answer = ConnectionRules.availability(input.path("connectionApproved").asBoolean(),
                input.path("policiesApproved").asBoolean(), input.path("toolStatus").asString(), text(input.get("serverStatus")));

        String why = vector.path("description").asString();
        assertThat(answer.listed()).as(why).isEqualTo(expected.path("listed").asBoolean());
        assertThat(answer.errorCode()).as(why).isEqualTo(text(expected.get("errorCode")));
        assertThat(answer.disabledBy()).as(why).isEqualTo(text(expected.get("disabledBy")));
    }

    /** A pulled manifest of a server that was just added: every tool is pending, the policies are pending, the connection is proposed. */
    private void firstConnection(JsonNode vector) {
        JsonNode input = vector.path("input").path("firstConnection");
        JsonNode expected = vector.path("expected");
        List<Tool> tools = new ArrayList<>();
        for (JsonNode tool : input.path("tools")) {
            tools.add(new Tool(tool.path("name").asString(), tool.path("risk").asString(), "Does " + tool.path("name").asString() + "."));
        }
        ObjectNode manifest = Manifests.jira("1.0.0", tools.toArray(new Tool[0]));

        RegistryPlanner.Plan plan = RegistryPlanner.plan(manifest, "{}", Map.of(), Map.of(), false);

        String mode = input.path("tlsMode").asString();
        assertThat(ConnectionRules.proposal(!"plain".equals(mode), "ca".equals(mode))).isEqualTo(expected.path("pendingConnection").path("tlsMode").asString());
        assertThat(expected.path("status").asString()).isEqualTo(ServerConfig.PENDING_APPROVAL);
        assertThat(expected.path("connection").isNull()).isTrue();
        Map<String, String> states = new LinkedHashMap<>();
        List<String> listed = new ArrayList<>();
        plan.tools().forEach((name, tool) -> {
            String state = tool.approved() != null ? "approved" : "pending_approval";
            states.put(name, state);
            if (ConnectionRules.availability(false, false, state, null).listed()) {
                listed.add(name);
            }
        });
        expected.path("tools").propertyNames().forEach(name -> assertThat(states).containsEntry(name, expected.path("tools").path(name).asString()));
        List<String> wanted = new ArrayList<>();
        expected.path("listed").forEach(name -> wanted.add(name.asString()));
        assertThat(listed).isEqualTo(wanted);
    }
}
