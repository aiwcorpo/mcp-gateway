package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.system.CapturedOutput;

import pl.aiwcorpo.mcp.gateway.support.Contracts;
import pl.aiwcorpo.mcp.gateway.support.GatewayTestEnvironment;
import tools.jackson.databind.JsonNode;

/** {@code /mcp} and {@code /s/<serverId>/mcp} with the filter in the query (CC-169 ... CC-188), over HTTP. */
class AggregateEndpointTest extends GatewayTestBase {

    /** The query goes out exactly as written: the HTTP client of the JDK refuses a malformed escape, a real client may send one. */
    private int rawStatus(String method, String target, String token, String session) throws Exception {
        try (java.net.Socket socket = new java.net.Socket("localhost", port)) {
            String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}";
            socket.getOutputStream().write((method + " " + target + " HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + token
                    + "\r\nContent-Type: application/json\r\nAccept: application/json\r\n"
                    + (session == null ? "" : "Mcp-Session-Id: " + session + "\r\nMCP-Protocol-Version: 2025-11-25\r\n")
                    + "Content-Length: " + body.length() + "\r\nConnection: close\r\n\r\n" + body)
                    .getBytes(java.nio.charset.StandardCharsets.UTF_8));
            String status = new java.io.BufferedReader(new java.io.InputStreamReader(socket.getInputStream())).readLine();
            return Integer.parseInt(status.split(" ")[1]);
        }
    }

    private String token() {
        return env.idp.token(ALICE_SUB, "alice", List.of("mcp-jira-read", "mcp-jira-write", "mcp-jira-destructive", "mcp-gitlab-read"));
    }

    private static List<String> names(HttpResponse<String> response) {
        List<String> out = new ArrayList<>();
        JSON.readTree(response.body()).path("result").path("tools").forEach(t -> out.add(t.path("name").asString()));
        return out;
    }

    private HttpResponse<String> list(String token, String path) throws Exception {
        return sendModern(token, path, "tools/list", null, "{}");
    }

    private HttpResponse<String> get(String path, String token) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path)).GET();
        if (token != null) {
            builder.header("Authorization", "Bearer " + token);
        }
        return http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void oneAddressListsTheToolsOfSeveralSystemsInTheOrderOfTheContract() throws Exception {
        List<String> all = names(list(token(), "/mcp"));
        assertThat(all).as(all.toString()).contains("jira__get_issue", "jira__delete_issue", "gitlab__get_issue");
        List<String> sorted = new ArrayList<>(all);
        sorted.sort(null);
        assertThat(all.stream().map(n -> n.substring(0, n.indexOf("__"))).distinct().toList())
                .isEqualTo(all.stream().map(n -> n.substring(0, n.indexOf("__"))).distinct().sorted().toList());
        assertThat(names(list(token(), "/s/mcp-jira/mcp"))).doesNotContain("gitlab__get_issue");
        assertThat(JSON.readTree(list(token(), "/mcp").body()).path("result").has("nextCursor")).isFalse();
    }

    @Test
    void theFilterNarrowsAndNeverGrants() throws Exception {
        assertThat(names(list(token(), "/mcp?systems=gitlab"))).allMatch(n -> n.startsWith("gitlab__")).isNotEmpty();
        assertThat(names(list(token(), "/mcp?access=read"))).as(names(list(token(), "/mcp?access=read")).toString()).contains("jira__get_issue").doesNotContain("jira__delete_issue");
        assertThat(names(list(token(), "/mcp?access=write"))).contains("jira__delete_issue").doesNotContain("jira__get_issue");
        assertThat(names(list(token(), "/mcp?exclude=jira"))).noneMatch(n -> n.startsWith("jira__"));
        assertThat(names(list(token(), "/mcp?tools=jira__get_issue,jira__nope,confluence__nothing"))).containsExactly("jira__get_issue");
        assertThat(names(list(token(), "/mcp?systems=nosuchsystem"))).isEmpty();
        assertThat(names(list(bobToken(), "/mcp?tools=jira__delete_issue"))).as("a filter adds nothing the user may not call").isEmpty();
        assertThat(names(list(token(), "/s/mcp-jira/mcp?systems=jira&access=read"))).contains("jira__get_issue");
        assertThat(list(token(), "/s/mcp-jira/mcp?systems=gitlab").statusCode()).as("systems must be the system of the route").isEqualTo(400);
    }

    @Test
    void aCallOutsideTheFilterIsNotFoundWhateverTheStateOfTheTool(CapturedOutput output) throws Exception {
        HttpResponse<String> call = sendModern(token(), "/mcp?access=write", "tools/call", "jira__get_issue",
                "{\"name\":\"jira__get_issue\",\"arguments\":{\"issueKey\":\"ABC-1\"}}");
        assertThat(toolError(call).path("error").asString()).isEqualTo("not_found_or_denied");
        assertThat(env.jira.requests()).noneMatch(r -> "tools/call".equals(r.rpcMethod()));
        assertThat(resolveCount()).isZero();
        String rid = call.headers().firstValue("X-Request-Id").orElseThrow();
        assertThat(auditEvents(output, rid)).isNotEmpty().allSatisfy(e -> {
            assertThat(e.path("filter").asString()).isEqualTo("access=write");
            assertThat(e.path("reason").asString()).isEqualTo("filter_scope");
            assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", e)).isEmpty();
        });
        HttpResponse<String> through = sendModern(token(), "/mcp?access=read", "tools/call", "jira__get_issue",
                "{\"name\":\"jira__get_issue\",\"arguments\":{\"issueKey\":\"ABC-1\"}}");
        assertThat(toolError(through).has("error")).isFalse();
        assertThat(lastToolCall(env.jira)).isNotNull();
    }

    @Test
    void aQueryThatIsNotAFilterIsA400AfterTheTokenAndNeverASilentlyDroppedFilter(CapturedOutput output) throws Exception {
        assertThat(rawStatus("POST", "/mcp?systems=%zz", token(), null)).as("a malformed escape is no missing filter").isEqualTo(400);
        assertThat(rawStatus("POST", "/mcp?access=read&systems=%", token(), null)).isEqualTo(400);
        assertThat(rawStatus("POST", "/s/mcp-jira/mcp?%zz", token(), null)).isEqualTo(400);
        for (String query : List.of("system=jira", "systems=jira&systems=gitlab", "access=admin", "systems=",
                "systems=jira%2Cgitlab", "systems=%7Ejira", "systems=jira+gitlab", "x".repeat(600))) {
            HttpResponse<String> response = list(token(), "/mcp?" + query);
            assertThat(response.statusCode()).as(query).isEqualTo(400);
            JsonNode body = JSON.readTree(response.body());
            assertThat(body.path("error").asString()).as(query).isEqualTo("invalid_request");
            assertThat(body.path("reason").asString()).as(query).isEqualTo("invalid_filter");
            assertThat(response.headers().firstValue("WWW-Authenticate")).as(query).isEmpty();
            assertThat(Contracts.schemaErrors("schemas/common.schema.json#/$defs/EndpointFilterError", body)).as(query).isEmpty();
            String rid = response.headers().firstValue("X-Request-Id").orElseThrow();
            assertThat(auditEvents(output, rid)).as(query).singleElement().satisfies(e -> {
                assertThat(e.path("event").asString()).isEqualTo("policy_decision");
                assertThat(e.path("reason").asString()).isEqualTo("invalid_filter");
                assertThat(e.path("outcome").asString()).isEqualTo("error");
                assertThat(e.has("filter")).isFalse();
                assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", e)).isEmpty();
            });
        }
        HttpResponse<String> noToken = send(null, "/mcp?system=jira", initializeBody(), Map.of());
        assertThat(noToken.statusCode()).as("the token is checked first").isEqualTo(401);
        assertThat(noToken.headers().firstValue("WWW-Authenticate").orElse(""))
                .isEqualTo("Bearer resource_metadata=\"" + GatewayTestEnvironment.PUBLIC_URL + "/.well-known/oauth-protected-resource/mcp\"");
    }

    @Test
    void aLegacySessionIsBoundToItsRouteAndFilter(CapturedOutput output) throws Exception {
        String token = token();
        HttpResponse<String> init = send(token, "/mcp?systems=jira&access=read", initializeBody("2025-11-25"), Map.of());
        assertThat(init.statusCode()).isEqualTo(200);
        assertThat(JSON.readTree(init.body()).path("result").path("capabilities").path("tools").path("listChanged").asBoolean(true)).isFalse();
        String session = init.headers().firstValue("Mcp-Session-Id").orElseThrow();
        String listBody = "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}";
        Map<String, String> headers = Map.of("Mcp-Session-Id", session, "MCP-Protocol-Version", "2025-11-25");

        HttpResponse<String> same = send(token, "/mcp?access=read&systems=jira", listBody, headers);
        assertThat(same.statusCode()).as("the same filter in another spelling").isEqualTo(200);
        assertThat(names(same)).contains("jira__get_issue").noneMatch(n -> n.startsWith("gitlab__"));

        for (String path : List.of("/mcp", "/mcp?systems=jira", "/mcp?systems=gitlab&access=read", "/s/mcp-jira/mcp?access=read")) {
            HttpResponse<String> other = send(token, path, listBody, headers);
            assertThat(other.statusCode()).as(path).isEqualTo(404);
            String rid = other.headers().firstValue("X-Request-Id").orElseThrow();
            assertThat(auditEvents(output, rid)).as(path).singleElement().satisfies(e -> {
                assertThat(e.path("reason").asString()).isEqualTo("filter_mismatch");
                assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", e)).isEmpty();
            });
        }
        assertThat(rawStatus("POST", "/mcp?systems=bad%zz", token, session)).as("syntax before the session").isEqualTo(400);

        HttpResponse<String> foreign = send(bobToken(), "/mcp?systems=gitlab", listBody, headers);
        assertThat(foreign.statusCode()).isEqualTo(404);
        assertThat(auditEvents(output, foreign.headers().firstValue("X-Request-Id").orElseThrow()))
                .as("another user's session is an unknown one: no filter_mismatch").isEmpty();

        HttpResponse<String> withMeta = send(token, "/mcp?systems=gitlab", "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/list\",\"params\":{\"_meta\":"
                + "{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{}}}}",
                Map.of("Mcp-Session-Id", session, "MCP-Protocol-Version", "2026-07-28", "Mcp-Method", "tools/list"));
        assertThat(withMeta.statusCode()).as("a session id with _meta is still a session request").isEqualTo(404);

        HttpRequest delete = HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/mcp?systems=gitlab"))
                .header("Authorization", "Bearer " + token).header("Mcp-Session-Id", session).DELETE().build();
        assertThat(http.send(delete, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(404);
        HttpRequest ownDelete = HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/mcp?systems=jira&access=read"))
                .header("Authorization", "Bearer " + token).header("Mcp-Session-Id", session).DELETE().build();
        assertThat(http.send(ownDelete, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(204);
    }

    @Test
    void thereIsNoStreamAndNoSavedLinks() throws Exception {
        for (String path : List.of("/mcp", "/s/mcp-jira/mcp")) {
            HttpResponse<String> response = get(path, token());
            assertThat(response.statusCode()).isEqualTo(405);
            assertThat(response.headers().firstValue("Allow")).contains("POST, DELETE");
            assertThat(get(path, null).statusCode()).as("the token is checked first").isEqualTo(401);
        }
        String body = "{\"error\":\"not_found_or_denied\",\"message\":\"The resource does not exist or you do not have access to it.\"}";
        for (String t : new String[] {token(), "garbage", null}) {
            HttpResponse<String> gone = send(t, "/v/team-a-dev/mcp", initializeBody(), Map.of());
            assertThat(gone.statusCode()).isEqualTo(404);
            assertThat(JSON.readTree(gone.body())).isEqualTo(JSON.readTree(body));
        }
        assertThat(get("/v/team-a-dev/mcp", token()).statusCode()).isEqualTo(404);
        assertThat(send(token(), "/f/systems=jira/mcp", initializeBody(), Map.of()).statusCode()).isEqualTo(404);
    }

    @Test
    void theMetadataOfTheAggregateEndpointIgnoresTheQuery() throws Exception {
        for (String query : List.of("", "?systems=jira&access=read", "?system=jira")) {
            HttpResponse<String> response = get("/.well-known/oauth-protected-resource/mcp" + query, null);
            assertThat(response.statusCode()).as(query).isEqualTo(200);
            assertThat(JSON.readTree(response.body()).path("resource").asString()).isEqualTo(GatewayTestEnvironment.PUBLIC_URL + "/mcp");
        }
        assertThat(JSON.readTree(get("/.well-known/oauth-protected-resource/s/mcp-jira/mcp", null).body()).path("resource").asString())
                .isEqualTo(GatewayTestEnvironment.PUBLIC_URL + "/s/mcp-jira/mcp");
        for (String gone : List.of("/.well-known/oauth-protected-resource/v/team-a-dev/mcp", "/.well-known/oauth-protected-resource/f/systems=jira/mcp")) {
            HttpResponse<String> response = get(gone, null);
            assertThat(response.statusCode()).isEqualTo(404);
            assertThat(JSON.readTree(response.body()).path("error").asString()).isEqualTo("not_found_or_denied");
        }
    }

    @Test
    void aCursorOfAnotherUserOrFilterOrOfNoOneIsInvalidParams(CapturedOutput output) throws Exception {
        for (String cursor : List.of("\"not-a-cursor\"", "42", "\"a.b\"")) {
            HttpResponse<String> response = sendModern(token(), "/mcp", "tools/list", null, "{\"cursor\":" + cursor + "}");
            assertThat(response.statusCode()).as(cursor).isEqualTo(400);
            assertThat(JSON.readTree(response.body()).path("error").path("code").asInt()).isEqualTo(-32602);
            assertThat(auditEvents(output, response.headers().firstValue("X-Request-Id").orElseThrow())).as(cursor).anySatisfy(e -> {
                assertThat(e.path("reason").asString()).isEqualTo("invalid_cursor");
                assertThat(e.path("outcome").asString()).isEqualTo("error");
            });
        }
    }

    @Test
    void aSlowServerIsLeftOutOfTheListAndDoesNotHoldItBack() throws Exception {
        assertThat(names(list(token(), "/mcp"))).contains("gitlab__get_issue");
        env.gitlab.slowToolList(3000);
        try {
            Thread.sleep(1300);
            long started = System.nanoTime();
            List<String> during = names(list(token(), "/mcp"));
            long elapsedMillis = (System.nanoTime() - started) / 1_000_000;
            assertThat(during).contains("jira__get_issue").noneMatch(n -> n.startsWith("gitlab__"));
            assertThat(elapsedMillis).as("the list waits for the limit, not for the server").isLessThan(2500);
            assertThat(names(list(token(), "/s/mcp-gitlab/mcp"))).isEmpty();
        } finally {
            env.gitlab.slowToolList(0);
        }
        org.awaitility.Awaitility.await().atMost(java.time.Duration.ofSeconds(10)).untilAsserted(() ->
                assertThat(names(list(token(), "/mcp"))).contains("gitlab__get_issue"));
    }

    @Test
    void theVectorsOfTheMetadataAndTheRemovedRouteHoldOverHttp() throws Exception {
        for (pl.aiwcorpo.mcp.gateway.support.Vectors.Vector vector : pl.aiwcorpo.mcp.gateway.support.Vectors.of("oauth-metadata")) {
            JsonNode input = vector.document().path("input");
            String query = input.path("requestQuery").asString("");
            HttpResponse<String> response = get(input.path("requestPath").asString() + (query.isEmpty() ? "" : "?" + query), null);
            JsonNode expected = vector.document().path("expected");
            assertThat(response.statusCode()).as(vector.name()).isEqualTo(expected.path("status").asInt());
            if (expected.has("document")) {
                assertThat(JSON.readTree(response.body()).path("resource").asString()).as(vector.name())
                        .isEqualTo(expected.path("document").path("resource").asString());
            } else {
                assertThat(JSON.readTree(response.body())).as(vector.name()).isEqualTo(expected.path("body"));
            }
        }
        JsonNode gone = pl.aiwcorpo.mcp.gateway.support.Vectors.of("endpoint-aggregate").stream()
                .filter(v -> v.name().equals("legacy-link-route-gone.json")).findFirst().orElseThrow().document();
        HttpResponse<String> response = send(token(), gone.path("input").path("path").asString(), initializeBody(), Map.of());
        assertThat(response.statusCode()).isEqualTo(gone.path("expected").path("status").asInt());
        assertThat(JSON.readTree(response.body())).isEqualTo(gone.path("expected").path("body"));
    }
}
