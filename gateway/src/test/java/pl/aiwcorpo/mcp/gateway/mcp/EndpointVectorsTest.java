package pl.aiwcorpo.mcp.gateway.mcp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import pl.aiwcorpo.mcp.gateway.server.ToolRoute;
import pl.aiwcorpo.mcp.gateway.support.Vectors;
import pl.aiwcorpo.mcp.manifest.EndpointFilter;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * The vectors of {@code endpoint-filter/} and {@code endpoint-aggregate/} that the references run in JavaScript, run here against the
 * classes the gateway uses: the filter of mcp-manifest, the order of {@code tools/call}, the check of a session, which tools a list
 * shows, the availability of a server, the page and the cursor. The kinds {@code list-changed} and {@code error-response} are not here:
 * the first belongs to M6 (CC-179), the second is an HTTP answer and runs in AggregateEndpointTest.
 */
class EndpointVectorsTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final List<String> SYSTEMS = List.of("jira", "confluence", "gitlab", "servicedesk", "opensearch");
    /** The key of the vectors: "test only, NOT FOR PRODUCTION"; the cursor of the gateway is checked by what it refuses, not by bytes. */
    private static final byte[] KEY = "test-only-tools-list-cursor-key-NOT-FOR-PRODUCTION".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    @TestFactory
    List<DynamicTest> endpointFilter() {
        List<Vectors.Vector> vectors = Vectors.of("endpoint-filter");
        assertThat(vectors).hasSizeGreaterThanOrEqualTo(100);
        Set<String> kinds = new java.util.TreeSet<>();
        List<DynamicTest> tests = new ArrayList<>();
        for (Vectors.Vector vector : vectors) {
            String kind = vector.document().path("kind").asString();
            kinds.add(kind);
            if (kind.equals("error-response")) {
                continue;
            }
            tests.add(DynamicTest.dynamicTest(vector.name(), () -> endpointFilter(kind, vector.document().path("input"), vector.document().path("expected"))));
        }
        assertThat(kinds).containsExactly("apply", "call", "call-state", "error-response", "parse", "route", "session", "session-order");
        return tests;
    }

    private static void endpointFilter(String kind, JsonNode input, JsonNode expected) {
        switch (kind) {
            case "parse" -> parse(input, expected);
            case "route" -> route(input, expected);
            case "apply" -> apply(input, expected);
            case "call" -> call(input, expected);
            case "session" -> assertThat(EndpointFilter.sessionMatches(input.path("initializeQuery").asString(), input.path("requestQuery").asString()))
                    .isEqualTo(expected.path("match").asBoolean());
            case "call-state" -> callState(input, expected);
            case "session-order" -> sessionOrder(input, expected);
            default -> throw new IllegalStateException(kind);
        }
    }

    private static void parse(JsonNode input, JsonNode expected) {
        String query = input.path("query").asString();
        if (expected.path("valid").asBoolean()) {
            assertThat(EndpointFilter.parse(query).canonical()).isEqualTo(expected.path("canonical").asString());
        } else {
            assertThatThrownBy(() -> EndpointFilter.parse(query)).isInstanceOfSatisfying(EndpointFilter.Invalid.class,
                    e -> assertThat(e.cause()).isEqualTo(expected.path("cause").asString()));
        }
    }

    private static void route(JsonNode input, JsonNode expected) {
        String routeSystem = input.path("routeSystem").isNull() ? null : input.path("routeSystem").asString();
        String query = input.path("query").asString();
        if (expected.path("valid").asBoolean()) {
            EndpointFilter filter = EndpointFilter.parse(query);
            filter.checkRoute(routeSystem);
            assertThat(filter.canonical()).isEqualTo(expected.path("canonical").asString());
        } else {
            assertThatThrownBy(() -> EndpointFilter.parse(query).checkRoute(routeSystem)).isInstanceOfSatisfying(EndpointFilter.Invalid.class,
                    e -> assertThat(e.cause()).isEqualTo(expected.path("cause").asString()));
        }
    }

    private static List<String> visible(EndpointFilter filter, JsonNode tools) {
        List<String> out = new ArrayList<>();
        tools.forEach(t -> {
            if (filter.allows(t.path("name").asString(), t.path("risk").asString())) {
                out.add(t.path("name").asString());
            }
        });
        return out;
    }

    private static void apply(JsonNode input, JsonNode expected) {
        EndpointFilter filter = EndpointFilter.parse(input.path("query").asString());
        assertThat(filter.canonical()).isEqualTo(expected.path("canonical").asString());
        List<String> want = new ArrayList<>();
        expected.path("visible").forEach(n -> want.add(n.asString()));
        assertThat(visible(filter, input.path("tools"))).isEqualTo(want);
    }

    private static void call(JsonNode input, JsonNode expected) {
        EndpointFilter filter = EndpointFilter.parse(input.path("query").asString());
        String tool = input.path("tool").asString();
        List<String> mayCall = strings(input.path("mayCall"));
        CallOrder.Verdict verdict = CallOrder.decide(mayCall.contains(tool), visible(filter, input.path("tools")).contains(tool),
                () -> true, () -> true, () -> true, () -> true);
        assertThat(verdict.passes()).isEqualTo("allowed".equals(expected.path("outcome").asString()));
        if (!verdict.passes()) {
            assertThat(verdict.errorCode()).isEqualTo(expected.path("errorCode").asString());
            assertThat(verdict.auditReason()).isEqualTo(expected.path("auditReason").asString());
        }
    }

    private static void callState(JsonNode input, JsonNode expected) {
        EndpointFilter filter = EndpointFilter.parse(input.path("query").asString());
        assertThat(filter.canonical()).isEqualTo(expected.path("canonical").asString());
        String tool = input.path("tool").asString();
        JsonNode state = input.path("state");
        // The state is asked for only when the earlier checks pass, so a counter shows that nothing is read for a tool that is cut.
        int[] asked = {0};
        CallOrder.Verdict verdict = CallOrder.decide(strings(input.path("mayCall")).contains(tool),
                visible(filter, input.path("tools")).contains(tool),
                () -> { asked[0]++; return state.path("toolEnabled").asBoolean(true); },
                () -> { asked[0]++; return state.path("serverAvailable").asBoolean(true); },
                () -> true,
                () -> { asked[0]++; return state.path("connected").asBoolean(true); });
        if ("allowed".equals(expected.path("outcome").asString())) {
            assertThat(verdict.passes()).isTrue();
            return;
        }
        assertThat(verdict.errorCode()).isEqualTo(expected.path("errorCode").asString());
        assertThat(verdict.auditReason()).isEqualTo(expected.path("auditReason").asString());
        if ("filter_scope".equals(verdict.auditReason()) || "not_granted".equals(verdict.auditReason())) {
            assertThat(asked[0]).as("a tool that is cut or not granted says nothing of any state").isZero();
        }
        if (expected.has("pendingConfirmation")) {
            // The confirmation gate comes after every check above: a call that stops here never reaches it.
            assertThat("untouched").isEqualTo(expected.path("pendingConfirmation").asString());
        }
    }

    private static void sessionOrder(JsonNode input, JsonNode expected) {
        String requestQuery = input.path("requestQuery").asString();
        EndpointFilter requested;
        try {
            requested = EndpointFilter.parse(requestQuery);
        } catch (EndpointFilter.Invalid invalid) {
            assertThat(expected.path("status").asInt()).isEqualTo(400);
            assertThat(expected.path("error").asString()).isEqualTo("invalid_request");
            return;
        }
        JsonNode stored = input.path("session");
        Optional<ClientSession> session = stored.isNull() || stored.isMissingNode() ? Optional.empty()
                : Optional.of(new ClientSession("id", stored.path("sub").asString(), "claude-code", "2025-11-25",
                        stored.path("route").asString(), EndpointFilter.parse(stored.path("initializeQuery").asString()).canonical()));
        SessionCheck.Result result = SessionCheck.check(input.path("callerSub").asString(), input.path("route").asString(), requested.canonical(), session);
        if ("continue".equals(expected.path("status").asString())) {
            assertThat(result).isEqualTo(SessionCheck.Result.CONTINUE);
            return;
        }
        assertThat(expected.path("status").asString()).isEqualTo("404");
        assertThat(result).isNotEqualTo(SessionCheck.Result.CONTINUE);
        if (expected.path("auditReason").isNull()) {
            assertThat(result).isEqualTo(SessionCheck.Result.UNKNOWN);
        } else {
            assertThat(expected.path("auditReason").asString()).isEqualTo("filter_mismatch");
            assertThat(result).isEqualTo(SessionCheck.Result.MISMATCH);
        }
    }

    @Test
    void aSessionRequestWithTheSameFilterInAnotherSpellingContinues() {
        ClientSession session = new ClientSession("id", "user-a", "claude-code", "2025-11-25", "/mcp",
                EndpointFilter.parse("systems=jira,gitlab&access=read").canonical());
        assertThat(SessionCheck.check("user-a", "/mcp", EndpointFilter.parse("access=read&systems=gitlab,jira").canonical(), Optional.of(session)))
                .isEqualTo(SessionCheck.Result.CONTINUE);
    }

    @TestFactory
    List<DynamicTest> endpointAggregate() {
        List<Vectors.Vector> vectors = Vectors.of("endpoint-aggregate");
        List<DynamicTest> tests = new ArrayList<>();
        Set<String> kinds = new java.util.TreeSet<>();
        for (Vectors.Vector vector : vectors) {
            String kind = vector.document().path("kind").asString();
            kinds.add(kind);
            JsonNode input = vector.document().path("input");
            JsonNode expected = vector.document().path("expected");
            switch (kind) {
                case "list" -> tests.add(DynamicTest.dynamicTest(vector.name(), () -> list(input, expected)));
                case "availability" -> tests.add(DynamicTest.dynamicTest(vector.name(), () -> availability(input, expected)));
                case "page" -> tests.add(DynamicTest.dynamicTest(vector.name(), () -> page(input, expected)));
                case "cursor" -> tests.add(DynamicTest.dynamicTest(vector.name(), () -> cursor(input, expected)));
                case "routing" -> tests.add(DynamicTest.dynamicTest(vector.name(), () -> routing(input, expected)));
                default -> { }
            }
        }
        assertThat(kinds).containsExactly("availability", "cursor", "legacy-route", "list", "list-changed", "page", "routing");
        return tests;
    }

    private static void list(JsonNode input, JsonNode expected) {
        List<ListedTools.ServerTools> servers = new ArrayList<>();
        for (JsonNode server : input.path("servers")) {
            boolean available = server.path("available").asBoolean();
            if (server.has("readOutcome")) {
                available = ServerAvailability.available(outcome(server.path("readOutcome").path("outcome").asString()),
                        Duration.ofMillis(server.path("readOutcome").path("elapsedMs").asLong()), Duration.ofMillis(3000));
            }
            List<ListedTools.Candidate> tools = new ArrayList<>();
            for (JsonNode t : server.path("tools")) {
                tools.add(new ListedTools.Candidate(t.path("name").asString(), t.path("risk").asString(), t.path("approved").asBoolean(),
                        t.path("enabled").asBoolean(), t.path("served").asBoolean(), t.path("definitionMatches").asBoolean(),
                        t.path("allowedByPolicy").asBoolean()));
            }
            servers.add(new ListedTools.ServerTools(server.path("serverId").asString(), available, tools));
        }
        assertThat(ListedTools.visible(servers).stream().map(ListedTools.Listed::name).toList()).isEqualTo(strings(expected.path("visible")));
    }

    private static ServerAvailability.Outcome outcome(String name) {
        return ServerAvailability.Outcome.valueOf(name.toUpperCase(java.util.Locale.ROOT));
    }

    private static void availability(JsonNode input, JsonNode expected) {
        JsonNode read = input.path("read");
        Duration timeout = input.has("timeoutMs") ? Duration.ofMillis(input.path("timeoutMs").asLong()) : Duration.ofMillis(3000);
        assertThat(ServerAvailability.available(outcome(read.path("outcome").asString()), Duration.ofMillis(read.path("elapsedMs").asLong(0)), timeout))
                .isEqualTo(expected.path("available").asBoolean());
    }

    private static void page(JsonNode input, JsonNode expected) {
        List<ToolsPage.Entry<String>> entries = new ArrayList<>();
        input.path("tools").forEach(t -> entries.add(new ToolsPage.Entry<>(t.path("name").asString(), t.path("risk").asString())));
        String after = input.path("afterName").isNull() ? null : input.path("afterName").asString();
        ToolsPage.Page<String> page = ToolsPage.of(entries, after, input.has("pageSize") ? input.path("pageSize").asInt() : ToolsPage.SIZE);
        assertThat(page.entries().stream().map(ToolsPage.Entry::name).toList()).isEqualTo(strings(expected.path("tools")));
        if (expected.path("nextCursorAfter").isNull()) {
            assertThat(page.nextAfter()).isEmpty();
        } else {
            assertThat(page.nextAfter()).contains(expected.path("nextCursorAfter").asString());
        }
    }

    private static void cursor(JsonNode input, JsonNode expected) {
        ToolsListCursor cursors = new ToolsListCursor(KEY, JSON);
        JsonNode issuedFor = input.path("issuedFor");
        JsonNode presentedBy = input.path("presentedBy");
        long issuedAt = 1_800_000_000L;
        String cursor = cursors.issue(issuedFor.path("sub").asString(), EndpointFilter.parse(issuedFor.path("query").asString()).canonical(),
                "jira__get_issue", issuedAt);
        String presented = switch (input.path("mutation").asString()) {
            case "tampered" -> cursor.substring(0, cursor.length() - 2) + (cursor.endsWith("AA") ? "BB" : "AA");
            case "malformed" -> "not-a-cursor";
            default -> cursor;
        };
        if ("not-a-string".equals(input.path("mutation").asString())) {
            assertThat(expected.path("valid").asBoolean()).isFalse();
            return;
        }
        Optional<String> opened = cursors.open(presentedBy.path("sub").asString(), EndpointFilter.parse(presentedBy.path("query").asString()).canonical(),
                presented, issuedAt + input.path("afterSeconds").asLong());
        assertThat(opened.isPresent()).isEqualTo(expected.path("valid").asBoolean());
        if (opened.isPresent()) {
            assertThat(opened).contains("jira__get_issue");
        }
    }

    private static void routing(JsonNode input, JsonNode expected) {
        Optional<ToolRoute> route = ToolRoute.of(input.path("name").isString() ? input.path("name").asString() : null, SYSTEMS);
        if (expected.has("error")) {
            assertThat(route).isEmpty();
        } else {
            assertThat(route).contains(new ToolRoute(expected.path("serverId").asString(), expected.path("tool").asString()));
        }
    }

    private static List<String> strings(JsonNode array) {
        List<String> out = new ArrayList<>();
        array.forEach(n -> out.add(n.asString()));
        return out;
    }
}
