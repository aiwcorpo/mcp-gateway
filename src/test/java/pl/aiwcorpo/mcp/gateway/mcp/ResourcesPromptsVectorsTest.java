package pl.aiwcorpo.mcp.gateway.mcp;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import pl.aiwcorpo.mcp.cedar.entities.ResourceTypes;
import pl.aiwcorpo.mcp.gateway.killswitch.KillSwitches;
import pl.aiwcorpo.mcp.gateway.primitive.ContractsVersion;
import pl.aiwcorpo.mcp.gateway.primitive.LinkBlocks;
import pl.aiwcorpo.mcp.gateway.primitive.PrimitiveLists;
import pl.aiwcorpo.mcp.gateway.primitive.PromptGetOrder;
import pl.aiwcorpo.mcp.gateway.primitive.PromptRenderer;
import pl.aiwcorpo.mcp.gateway.primitive.ResourceContents;
import pl.aiwcorpo.mcp.gateway.primitive.ResourceReadOrder;
import pl.aiwcorpo.mcp.gateway.primitive.ResourceUris;
import pl.aiwcorpo.mcp.gateway.support.Vectors;
import pl.aiwcorpo.mcp.manifest.EndpointFilter;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * The vectors of mcp-contracts 8.0.0 for resources and prompts (CC-258, CC-259, CC-260) against the classes the gateway serves them with:
 * {@code resource-uri/}, {@code prompt-render/}, the {@code resources-*} vectors of {@code mcp-endpoint/} that are decisions (the methods,
 * the declared capabilities, the fields of the results, the order of {@code resources/read} and {@code prompts/get}, the blocks that point at a
 * URI), the primitive lists, cursors and notifications of {@code endpoint-aggregate/}, and the version condition for the new claims of
 * {@code server-connection/}. The HTTP answers are checked over the wire in {@code ResourcesAndPromptsTest}.
 */
class ResourcesPromptsVectorsTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final byte[] KEY = "test-only-tools-list-cursor-key-NOT-FOR-PRODUCTION".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    private static List<ResourceUris.Variable> variables(JsonNode array) {
        List<ResourceUris.Variable> out = new ArrayList<>();
        array.forEach(v -> out.add(ResourceUris.Variable.of(v.path("name").asString(), v.path("idPattern").asString(), 4096)));
        return out;
    }

    private static ResourceUris.Resolved resolve(JsonNode entries, String uri) {
        List<ResourceUris.StaticEntry> statics = new ArrayList<>();
        entries.path("resources").forEach(r -> statics.add(new ResourceUris.StaticEntry(r.path("name").asString(), r.path("uri").asString())));
        List<ResourceUris.TemplateEntry> templates = new ArrayList<>();
        entries.path("templates").forEach(t -> templates.add(new ResourceUris.TemplateEntry(t.path("name").asString(),
                t.path("uriTemplate").asString(), variables(t.path("variables")))));
        return ResourceUris.resolve(statics, templates, uri);
    }

    @TestFactory
    List<DynamicTest> resourceUris() {
        List<Vectors.Vector> vectors = Vectors.of("resource-uri");
        assertThat(vectors).hasSize(21);
        List<DynamicTest> tests = new ArrayList<>();
        for (Vectors.Vector vector : vectors) {
            JsonNode input = vector.document().path("input");
            JsonNode expected = vector.document().path("expected");
            tests.add(DynamicTest.dynamicTest(vector.name(), () -> {
                if ("template".equals(vector.document().path("kind").asString())) {
                    ResourceUris.Match match = ResourceUris.match(input.path("template").asString(), variables(input.path("variables")),
                            input.path("uri").asString());
                    assertThat(match.matched()).as(vector.document().path("description").asString()).isEqualTo(expected.path("match").asBoolean());
                    if (match.matched() && expected.has("variables")) {
                        expected.path("variables").properties().forEach(e -> assertThat(match.variables()).containsEntry(e.getKey(), e.getValue().asString()));
                    }
                } else {
                    ResourceUris.Resolved resolved = resolve(input, input.path("uri").asString());
                    if (expected.path("kind").isNull()) {
                        assertThat(resolved.found()).isFalse();
                        assertThat(resolved.reason()).isEqualTo(expected.path("reason").asString());
                    } else {
                        assertThat(resolved.found()).isTrue();
                        assertThat(resolved.name()).isEqualTo(expected.path("name").asString());
                        assertThat("resource".equals(resolved.kind()) ? "resource" : "template").isEqualTo(expected.path("kind").asString());
                    }
                }
            }));
        }
        return tests;
    }

    @TestFactory
    List<DynamicTest> promptRender() {
        List<Vectors.Vector> vectors = Vectors.of("prompt-render");
        assertThat(vectors).hasSize(18);
        List<DynamicTest> tests = new ArrayList<>();
        for (Vectors.Vector vector : vectors) {
            JsonNode input = vector.document().path("input");
            JsonNode expected = vector.document().path("expected");
            tests.add(DynamicTest.dynamicTest(vector.name(), () -> {
                PromptRenderer.Outcome outcome = PromptRenderer.render(JSON, input.path("prompt"),
                        type -> input.path("typePatterns").has(type) ? Optional.of(input.path("typePatterns").path(type).asString()) : Optional.empty(),
                        input.get("arguments"));
                if (expected.has("error")) {
                    assertThat(outcome).as(vector.document().path("description").asString()).isInstanceOf(PromptRenderer.Refused.class);
                    assertThat(expected.path("reason").asString()).isEqualTo(PromptRenderer.ARGUMENT_INVALID);
                    return;
                }
                assertThat(outcome).isInstanceOf(PromptRenderer.Rendered.class);
                PromptRenderer.Rendered rendered = (PromptRenderer.Rendered) outcome;
                assertThat(rendered.description()).isEqualTo(expected.path("result").path("description").asString());
                assertThat(rendered.messages()).isEqualTo(expected.path("result").path("messages"));
            }));
        }
        return tests;
    }

    @TestFactory
    List<DynamicTest> endpointVectors() {
        List<DynamicTest> tests = new ArrayList<>();
        Set<String> kinds = new TreeSet<>();
        for (Vectors.Vector vector : Vectors.of("mcp-endpoint")) {
            String kind = vector.document().path("kind").asString(null);
            if (kind == null || !vector.name().startsWith("resources-")) {
                continue;
            }
            kinds.add(kind);
            JsonNode input = vector.document().path("input");
            JsonNode expected = vector.document().path("expected");
            tests.add(DynamicTest.dynamicTest(vector.name(), () -> {
                switch (kind) {
                    case "method" -> method(input, expected);
                    case "capabilities" -> capabilities(input, expected);
                    case "result-fields" -> resultFields(input, expected);
                    case "links" -> links(input, expected);
                    case "read" -> read(input, expected);
                    case "prompt-get" -> promptGet(input, expected);
                    case "rate-limited" -> rateLimited(input, expected);
                    default -> throw new IllegalStateException(kind);
                }
            }));
        }
        assertThat(kinds).containsExactly("capabilities", "links", "method", "prompt-get", "rate-limited", "read", "result-fields");
        return tests;
    }

    private static final Set<String> SUPPORTED = Set.of("resources/list", "resources/templates/list", "resources/read", "prompts/list", "prompts/get");

    /** The methods the endpoint answers: the five of the contract, and nothing else of the families (subscribe, completion). */
    private static void method(JsonNode input, JsonNode expected) {
        boolean handled = SUPPORTED.contains(input.path("method").asString());
        assertThat(handled).isEqualTo(expected.path("handled").asBoolean());
        if (!handled) {
            assertThat(expected.path("error").path("code").asInt()).isEqualTo(-32601);
            assertThat(expected.path("httpStatus").asInt()).isEqualTo("modern".equals(input.path("era").asString()) ? 404 : 200);
        }
    }

    private static void capabilities(JsonNode input, JsonNode expected) {
        tools.jackson.databind.node.ObjectNode declared = JSON.createObjectNode();
        McpEndpoint.declareCapabilities(declared);
        assertThat(declared.path("capabilities")).isEqualTo(expected.path("capabilities"));
    }

    private static void resultFields(JsonNode input, JsonNode expected) {
        tools.jackson.databind.node.ObjectNode result = JSON.createObjectNode();
        if ("modern".equals(input.path("era").asString())) {
            result.put("resultType", "complete");
            McpEndpoint.cacheFields(input.path("method").asString(), result);
        }
        assertThat(JSON.writeValueAsString(result)).isEqualTo(JSON.writeValueAsString(expected));
    }

    /** Over the limit a resources/read or prompts/get is the 429 of any request that is not a tool call (CC-156): no tool error, no X-RateLimit headers. */
    private static void rateLimited(JsonNode input, JsonNode expected) {
        org.springframework.http.ResponseEntity<String> response = pl.aiwcorpo.mcp.gateway.ratelimit.RateLimitResponse.of("0192d1b2-7c3a-7d4e-8f10-2a3b4c5d6e7f",
                input.path("retryAfterSeconds").asInt());
        assertThat(response.getStatusCode().value()).isEqualTo(expected.path("status").asInt());
        expected.path("headers").properties().forEach(h -> assertThat(response.getHeaders().getFirst(h.getKey())).isEqualTo(h.getValue().asString()));
        assertThat(response.getHeaders().headerNames()).noneMatch(name -> name.toLowerCase(java.util.Locale.ROOT).startsWith("x-ratelimit"));
        assertThat(JSON.readTree(response.getBody())).isEqualTo(expected.path("body"));
    }

    private static void links(JsonNode input, JsonNode expected) {
        LinkBlocks.Filtered filtered = LinkBlocks.filter(JSON, input.path("system").asString(), input.path("adapter").asBoolean(false), input.path("blocks"));
        assertThat(filtered.blocks()).isEqualTo(expected.path("blocks"));
        assertThat(filtered.refused() ? LinkBlocks.REFUSED : null).isEqualTo(expected.path("auditReason").asString(null));
    }

    private static void read(JsonNode input, JsonNode expected) {
        String uri = input.path("uri").asString();
        String reason;
        int step;
        String outcome;
        JsonNode error = null;
        JsonNode result = null;
        String header = input.path("header").isNull() ? null : input.path("header").asString(null);
        if ("modern".equals(input.path("era").asString()) && (header == null || !uri.equals(McpEndpoint.decodeHeaderValue(header)))) {
            assertThat(expected.path("error").path("code").asInt()).isEqualTo(-32020);
            assertThat(expected.path("auditReason").asString()).isEqualTo("header_mismatch");
            assertThat(expected.path("step").asInt()).isEqualTo(2);
            return;
        }
        ResourceUris.Resolved resolved = resolve(input.path("entries"), uri);
        boolean template = "template".equals(resolved.kind());
        JsonNode state = input.path("entry");
        JsonNode server = input.path("server");
        JsonNode credential = input.path("credential");
        ResourceReadOrder.Verdict verdict;
        if (!resolved.found()) {
            verdict = new ResourceReadOrder.Verdict(ResourceReadOrder.Answer.NOT_FOUND, resolved.reason(), 3);
        } else {
            String access = input.path("access").asString("allowed");
            verdict = ResourceReadOrder.decide("allowed".equals(access), "policy_forbid".equals(access), input.path("inFilter").asBoolean(true),
                    () -> switch (input.path("killSwitch").asString("none")) {
                        case "set" -> KillSwitches.Status.ON;
                        case "unreadable" -> KillSwitches.Status.UNREADABLE;
                        default -> KillSwitches.Status.OFF;
                    },
                    () -> "approved".equals(server.path("status").asString("approved")) && server.path("connectionApproved").asBoolean(true)
                            && server.path("policiesApproved").asBoolean(true) && server.path("enabled").asBoolean(true),
                    () -> state.path("approved").asBoolean(true) && state.path("enabled").asBoolean(true),
                    () -> state.path("definitionMatches").asBoolean(true),
                    () -> input.path("serverAvailable").asBoolean(true),
                    () -> true,
                    () -> true,
                    () -> !template || !credential.path("required").asBoolean(false) || credential.path("connected").asBoolean(false));
        }
        if (verdict.passes()) {
            JsonNode upstream = input.path("upstream");
            if (!"ok".equals(upstream.path("outcome").asString())) {
                outcome = "error";
                reason = "upstream_unavailable";
                step = 9;
                error = unavailable();
            } else {
                ResourceContents.Check check = ResourceContents.check(upstream.path("contents"), uri, upstream.path("bytes").asLong(),
                        input.path("maxBytes").asLong());
                step = 10;
                if (check.passes()) {
                    outcome = "ok";
                    reason = null;
                    result = JSON.createObjectNode().set("contents", upstream.path("contents"));
                } else {
                    outcome = "error";
                    reason = check.reason();
                    error = unavailable();
                }
            }
        } else {
            step = verdict.step();
            reason = verdict.reason();
            switch (verdict.answer()) {
                case NOT_FOUND -> {
                    outcome = "denied";
                    error = JSON.readTree("{\"code\":-32602,\"message\":\"Resource not found\",\"data\":{\"uri\":" + JSON.writeValueAsString(uri) + "}}");
                }
                case UPSTREAM_UNAVAILABLE -> {
                    outcome = "error";
                    error = unavailable();
                }
                default -> {
                    outcome = "error";
                    error = JSON.readTree("{\"code\":-32603,\"message\":\"Internal error\",\"data\":{\"error\":\"credential_required\",\"system\":"
                            + JSON.writeValueAsString(credential.path("system").asString()) + ",\"connectUrl\":"
                            + JSON.writeValueAsString(credential.path("connectUrl").asString()) + "}}");
                }
            }
        }
        assertThat(outcome).isEqualTo(expected.path("outcome").asString());
        assertThat(reason).isEqualTo(expected.path("auditReason").asString(null));
        assertThat(step).isEqualTo(expected.path("step").asInt());
        if (expected.has("error")) {
            assertThat(error).isEqualTo(expected.path("error"));
        } else {
            assertThat(result).isEqualTo(expected.path("result"));
        }
    }

    private static JsonNode unavailable() {
        return JSON.readTree("{\"code\":-32603,\"message\":\"Internal error\",\"data\":{\"error\":\"upstream_unavailable\"}}");
    }

    private static void promptGet(JsonNode input, JsonNode expected) {
        String access = input.path("access").asString("allowed");
        PromptGetOrder.Verdict verdict = PromptGetOrder.decide(input.path("known").asBoolean(true), "allowed".equals(access),
                "policy_forbid".equals(access), input.path("inFilter").asBoolean(true),
                () -> switch (input.path("killSwitch").asString("none")) {
                    case "set" -> KillSwitches.Status.ON;
                    case "unreadable" -> KillSwitches.Status.UNREADABLE;
                    default -> KillSwitches.Status.OFF;
                }, !input.path("hidden").asBoolean(false), false);
        if (verdict.passes()) {
            JsonNode render = input.path("render");
            if (render.has("error")) {
                assertThat(expected.path("outcome").asString()).isEqualTo("denied");
                assertThat(expected.path("auditReason").asString()).isEqualTo(PromptRenderer.ARGUMENT_INVALID);
                assertThat(expected.path("error").path("code").asInt()).isEqualTo(-32602);
                assertThat(expected.path("error").path("message").asString()).isEqualTo("Prompt not found");
            } else {
                assertThat(expected.path("outcome").asString()).isEqualTo("ok");
            }
            return;
        }
        assertThat(verdict.reason()).isEqualTo(expected.path("auditReason").asString());
        if (verdict.answer() == PromptGetOrder.Answer.UPSTREAM_UNAVAILABLE) {
            assertThat(unavailable()).isEqualTo(expected.path("error"));
        } else {
            assertThat(expected.path("error").path("code").asInt()).isEqualTo(-32602);
            assertThat(expected.path("error").path("message").asString()).isEqualTo("Prompt not found");
            assertThat(expected.path("error").path("data").path("name").asString()).isEqualTo(input.path("name").asString());
        }
    }

    @TestFactory
    List<DynamicTest> primitiveLists() {
        List<DynamicTest> tests = new ArrayList<>();
        for (Vectors.Vector vector : Vectors.of("endpoint-aggregate")) {
            if (!"primitive-list".equals(vector.document().path("kind").asString())) {
                continue;
            }
            JsonNode input = vector.document().path("input");
            tests.add(DynamicTest.dynamicTest(vector.name(), () -> {
                PrimitiveLists.Kind kind = PrimitiveLists.Kind.valueOf(input.path("kind").asString().toUpperCase(java.util.Locale.ROOT));
                EndpointFilter filter = EndpointFilter.parse(input.path("query").asString());
                List<PrimitiveLists.ServerEntries> servers = new ArrayList<>();
                for (JsonNode server : input.path("servers")) {
                    boolean served = "approved".equals(server.path("status").asString("approved")) && server.path("connectionApproved").asBoolean(true)
                            && server.path("policiesApproved").asBoolean(true) && server.path("enabled").asBoolean(true) && !server.path("killSwitch").asBoolean(false);
                    List<PrimitiveLists.Entry> entries = new ArrayList<>();
                    server.path("entries").forEach(e -> entries.add(new PrimitiveLists.Entry(e.path("name").asString(), e.path("approved").asBoolean(),
                            e.path("enabled").asBoolean(), e.path("definitionMatches").asBoolean(), e.path("allowedByPolicy").asBoolean())));
                    if (PrimitiveLists.throughFilter(filter, server.path("system").asString())) {
                        servers.add(new PrimitiveLists.ServerEntries(server.path("serverId").asString(), server.path("system").asString(), served,
                                server.path("available").asBoolean(), entries));
                    }
                }
                List<String> visible = new ArrayList<>();
                PrimitiveLists.visible(kind, servers).forEach(l -> visible.add(l.system() + "__" + l.name()));
                List<String> want = new ArrayList<>();
                vector.document().path("expected").path("visible").forEach(n -> want.add(n.asString()));
                assertThat(visible).as(vector.document().path("description").asString()).isEqualTo(want);
            }));
        }
        assertThat(tests).hasSize(20);
        return tests;
    }

    @TestFactory
    List<DynamicTest> primitiveCursors() {
        List<DynamicTest> tests = new ArrayList<>();
        for (Vectors.Vector vector : Vectors.of("endpoint-aggregate")) {
            if (!"primitive-cursor".equals(vector.document().path("kind").asString())) {
                continue;
            }
            JsonNode input = vector.document().path("input");
            tests.add(DynamicTest.dynamicTest(vector.name(), () -> {
                ToolsListCursor cursors = new ToolsListCursor(KEY, JSON);
                String issued = cursors.issue(input.path("issuedKind").asString(), "sub-1", "", "servicedesk__runbook", 1_800_000_000L);
                Optional<String> opened = cursors.open(input.path("presentedKind").asString(), "sub-1", "", issued, 1_800_000_001L);
                assertThat(opened.isPresent()).isEqualTo(vector.document().path("expected").path("valid").asBoolean());
            }));
        }
        assertThat(tests).hasSize(6);
        return tests;
    }

    /**
     * The traversal control of D4: a file path or a ref is a variable of a template and may carry a slash only as {@code %2F}, and the pattern of
     * its type, which is the one of the contracts, refuses {@code ..}, a hidden segment, an option of git and an empty segment, however the value is encoded.
     */
    @Test
    void aGitlabFilePathCannotTraverseWhateverTheEncoding() {
        ResourceTypes types = ResourceTypes.fromJson(Vectors.contractFile("cedar/examples/systems/gitlab/resource-types.json"));
        String template = "gitlab://project/{projectPath}/blob/{ref}/{filePath}";
        List<ResourceUris.Variable> variables = List.of(
                ResourceUris.Variable.of("projectPath", types.declaration("GitLab::Project").orElseThrow().idPattern(), 255),
                ResourceUris.Variable.of("ref", types.declaration("GitLab::Ref").orElseThrow().idPattern(), 255),
                ResourceUris.Variable.of("filePath", types.declaration("GitLab::FilePath").orElseThrow().idPattern(), 255));
        for (Vectors.Vector vector : Vectors.of("resource-ids")) {
            if (!"GitLab::FilePath".equals(vector.document().path("type").asString(null))) {
                continue;
            }
            for (JsonNode valid : vector.document().path("valid")) {
                String uri = "gitlab://project/group%2Frepo/blob/main/" + ResourceUris.encode(valid.asString());
                assertThat(ResourceUris.match(template, variables, uri).matched()).as(uri).isTrue();
                if (valid.asString().contains("/")) {
                    assertThat(ResourceUris.match(template, variables, "gitlab://project/group%2Frepo/blob/main/" + valid.asString()).matched())
                            .as("a raw slash is in no variable: " + valid.asString()).isFalse();
                }
            }
            for (JsonNode invalid : vector.document().path("invalid")) {
                String encoded = "gitlab://project/group%2Frepo/blob/main/" + ResourceUris.encode(invalid.asString());
                assertThat(ResourceUris.match(template, variables, encoded).matched()).as(encoded).isFalse();
                assertThat(ResourceUris.match(template, variables, "gitlab://project/group%2Frepo/blob/main/" + invalid.asString()).matched())
                        .as("raw: " + invalid.asString()).isFalse();
            }
        }
        assertThat(ResourceUris.match(template, variables, "gitlab://project/group/repo/blob/main/a.txt").matched()).as("a raw slash in the project path").isFalse();
        assertThat(ResourceUris.match(template, variables, "gitlab://project/group%2F..%2Frepo/blob/main/a.txt").matched()).isFalse();
    }

    @Test
    void aCursorIssuedBeforeTheKindExistedIsACursorOfTools() {
        ToolsListCursor cursors = new ToolsListCursor(KEY, JSON);
        String issued = cursors.issue("tools", "sub-1", "", "jira__get_issue", 1_800_000_000L);
        assertThat(cursors.open("sub-1", "", issued, 1_800_000_001L)).contains("jira__get_issue");
        assertThat(cursors.open(ToolsListCursor.PROMPTS, "sub-1", "", issued, 1_800_000_001L)).isEmpty();
    }

    @Test
    void theVersionConditionIsSemVerAndAPreReleaseIsOlder() {
        assertThat(ContractsVersion.supportsNewClaims("8.0.0")).isTrue();
        assertThat(ContractsVersion.supportsNewClaims("8.1.0")).isTrue();
        assertThat(ContractsVersion.supportsNewClaims("7.2.0")).isFalse();
        assertThat(ContractsVersion.supportsNewClaims("8.0")).isFalse();
        assertThat(ContractsVersion.supportsNewClaims("8.0.0-rc.1")).as("a pre-release of 8.0.0 is older than it").isFalse();
        assertThat(ContractsVersion.supportsNewClaims("8.0.1-rc.1")).isTrue();
        assertThat(ContractsVersion.supportsNewClaims("08.0.0")).as("no leading zeros in SemVer").isFalse();
        assertThat(ContractsVersion.supportsNewClaims("8.0.0+build.5")).isTrue();
        assertThat(ContractsVersion.supportsNewClaims("99999999999999999999.0.0")).isTrue();
        assertThat(ContractsVersion.supportsNewClaims(null)).isFalse();
    }

    @Test
    void theKindsOfEndpointAggregateAreKnown() {
        Set<String> kinds = new TreeSet<>();
        Vectors.of("endpoint-aggregate").forEach(v -> kinds.add(v.document().path("kind").asString()));
        assertThat(kinds).contains("primitive-list", "primitive-cursor", "list-changed");
    }
}
