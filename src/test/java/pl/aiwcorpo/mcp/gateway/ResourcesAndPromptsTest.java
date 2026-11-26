package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.test.util.ReflectionTestUtils;

import com.nimbusds.jwt.JWTClaimsSet;

import pl.aiwcorpo.mcp.gateway.agent.AgentClient;
import pl.aiwcorpo.mcp.gateway.server.Risk;
import pl.aiwcorpo.mcp.gateway.support.Contracts;
import pl.aiwcorpo.mcp.testserver.TestMcpServer;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * {@code resources/list}, {@code resources/templates/list}, {@code resources/read}, {@code prompts/list} and {@code prompts/get} over HTTP
 * (CC-259) against a server that publishes one static resource, one template and one prompt, which the administrator approves entry by entry:
 * what is listed and to whom, the one answer for everything a user may not read, the claims the server gets, what is audited, and what the
 * gateway refuses to pass on. The order of the checks is pinned by the vectors in {@code ResourcesPromptsVectorsTest}.
 */
class ResourcesAndPromptsTest extends DocsServerTestBase {

    // --- capabilities ----------------------------------------------------------------------------------------------

    @Test
    void theCapabilitiesAreDeclaredInBothErasAndCompletionNever() throws Exception {
        JsonNode modern = JSON.readTree(sendModern(reader(), "/mcp", "server/discover", null, "{}").body()).path("result").path("capabilities");
        assertThat(modern.path("resources").path("subscribe").asBoolean(true)).isFalse();
        assertThat(modern.path("resources").path("listChanged").asBoolean()).isTrue();
        assertThat(modern.path("prompts").path("listChanged").asBoolean()).isTrue();
        assertThat(modern.path("tools").path("listChanged").asBoolean()).isTrue();
        assertThat(modern.has("completions")).isFalse();

        HttpResponse<String> initialize = send(reader(), "/mcp", initializeBody(), Map.of());
        JsonNode legacy = JSON.readTree(initialize.body()).path("result").path("capabilities");
        assertThat(legacy).isEqualTo(modern);
    }

    @Test
    void theMethodsOutsideThePackageStayUnknown() throws Exception {
        for (String method : List.of("resources/subscribe", "resources/unsubscribe", "completion/complete")) {
            HttpResponse<String> modern = sendModern(reader(), "/mcp", method, null, "{}");
            assertThat(modern.statusCode()).as(method).isEqualTo(404);
            assertThat(error(modern).path("code").asInt()).isEqualTo(-32601);
        }
        JsonNode legacy = legacy(reader(), "resources/subscribe", "{\"uri\":\"" + RUNBOOK + "\"}");
        assertThat(legacy.path("error").path("code").asInt()).as("the legacy era answers 200 with the error").isEqualTo(-32601);
    }

    // --- lists -----------------------------------------------------------------------------------------------------

    @Test
    void theListsAreBuiltFromTheApprovedEntriesAndShowOnlyWhatTheUserMayRead() throws Exception {
        String token = reader();
        JsonNode resources = JSON.readTree(list(token, "/mcp", "resources/list", "resources").body()).path("result");
        assertThat(resources.path("resources")).hasSize(1);
        assertThat(resources.path("resources").get(0).path("uri").asString()).isEqualTo(RUNBOOK);
        assertThat(resources.path("resultType").asString()).isEqualTo("complete");
        assertThat(resources.path("ttlMs").asLong()).isEqualTo(60_000);
        assertThat(resources.path("cacheScope").asString()).isEqualTo("private");

        JsonNode templates = JSON.readTree(list(token, "/mcp", "resources/templates/list", "resourceTemplates").body()).path("result");
        assertThat(templates.path("resourceTemplates").get(0).path("uriTemplate").asString()).isEqualTo("docs://issue/{issueKey}");

        JsonNode prompts = JSON.readTree(list(token, "/mcp", "prompts/list", "prompts").body()).path("result");
        assertThat(prompts.path("prompts")).hasSize(1);
        assertThat(prompts.path("prompts").get(0).path("name").asString()).as("a prompt is listed as <system>__<prompt>").isEqualTo("docs__summarize_issue");
        assertThat(prompts.path("prompts").get(0).has("messages")).as("the text of the messages is not listed").isFalse();

        String stranger = env.idp.token(UUID.randomUUID().toString(), "sam", List.of("mcp-jira-read"));
        assertThat(names(list(stranger, "/mcp", "resources/list", "resources"))).isEmpty();
        assertThat(names(list(stranger, "/mcp", "resources/templates/list", "resourceTemplates"))).isEmpty();
        assertThat(names(list(stranger, "/mcp", "prompts/list", "prompts"))).isEmpty();
        assertThat(names(list(token, "/s/mcp-jira/mcp", "resources/list", "resources"))).as("another system's endpoint").isEmpty();
        assertThat(names(list(token, "/s/mcp-docs/mcp", "resources/list", "resources"))).containsExactly("runbook");
    }

    @Test
    void theLegacyEraCarriesNoneOfTheCacheFields() throws Exception {
        String token = reader();
        for (String method : List.of("resources/list", "resources/templates/list", "prompts/list")) {
            JsonNode result = legacy(token, method, "{}").path("result");
            assertThat(result.has("ttlMs")).as(method).isFalse();
            assertThat(result.has("cacheScope")).as(method).isFalse();
            assertThat(result.has("resultType")).as(method).isFalse();
        }
    }

    @Test
    void theAddressFilterNarrowsTheListsAndNeverAddsToThem() throws Exception {
        String token = reader();
        assertThat(names(list(token, "/mcp?access=read", "resources/list", "resources"))).containsExactly("runbook");
        assertThat(names(list(token, "/mcp?access=write", "resources/list", "resources"))).as("they are read only").isEmpty();
        assertThat(names(list(token, "/mcp?tools=docs__get_issue", "prompts/list", "prompts"))).as("tools narrows and adds nothing").isEmpty();
        assertThat(names(list(token, "/mcp?systems=jira", "resources/list", "resources"))).isEmpty();
        assertThat(names(list(token, "/mcp?exclude=docs", "prompts/list", "prompts"))).isEmpty();
        assertThat(names(list(token, "/mcp?exclude=docs__get_issue", "prompts/list", "prompts"))).as("a tool entry of exclude is not about them")
                .containsExactly("docs__summarize_issue");
        HttpResponse<String> read = read(token, "/mcp?access=write", RUNBOOK);
        assertThat(error(read).path("message").asString()).isEqualTo("Resource not found");
    }

    @Test
    void aCursorOfAnotherListIsRefusedLikeABadOne() throws Exception {
        String token = reader();
        HttpResponse<String> forged = sendModern(token, "/mcp", "resources/list", null, "{\"cursor\":\"AAAA.BBBB\"}");
        assertThat(forged.statusCode()).isEqualTo(400);
        assertThat(error(forged).path("code").asInt()).isEqualTo(-32602);
        assertThat(error(forged).path("message").asString()).isEqualTo("Invalid cursor");
    }

    @Test
    void aServerThatPresentsAnotherDefinitionLosesItsEntries() throws Exception {
        server.driftResources(true);
        await().atMost(Duration.ofSeconds(70)).pollInterval(Duration.ofSeconds(1)).untilAsserted(() -> {
            String token = reader();
            assertThat(names(list(token, "/mcp", "resources/list", "resources"))).isEmpty();
            assertThat(names(list(token, "/mcp", "resources/templates/list", "resourceTemplates"))).isEmpty();
            assertThat(names(list(token, "/mcp", "prompts/list", "prompts"))).as("prompts have no server definition to compare").hasSize(1);
        });
        HttpResponse<String> read = read(reader(), "/mcp", RUNBOOK);
        assertThat(error(read).path("code").asInt()).isEqualTo(-32602);
        assertThat(serverCalls("resources/read")).isEmpty();
    }

    @Test
    void aServerThatDoesNotAnswerItsListsIsSkippedAndTheOthersStay() throws Exception {
        server.failResourceLists(true);
        await().atMost(Duration.ofSeconds(70)).pollInterval(Duration.ofSeconds(1)).untilAsserted(() ->
                assertThat(names(list(reader(), "/mcp", "resources/list", "resources"))).isEmpty());
        assertThat(error(read(reader(), "/mcp", RUNBOOK)).path("data").path("error").asString()).as("not -32602: the server is unavailable")
                .isEqualTo("upstream_unavailable");
    }

    // --- resources/read --------------------------------------------------------------------------------------------

    @Test
    void aStaticResourceIsReadWithTheResourceClaimAndNeitherBrokerNorCredential(CapturedOutput output) throws Exception {
        env.broker.clear();
        HttpResponse<String> response = read(reader(), "/mcp", RUNBOOK);

        JsonNode result = JSON.readTree(response.body()).path("result");
        assertThat(result.path("contents")).hasSize(1);
        assertThat(result.path("contents").get(0).path("uri").asString()).isEqualTo(RUNBOOK);
        assertThat(result.path("contents").get(0).path("text").asString()).isEqualTo("Escalation runbook.");
        assertThat(result.path("ttlMs").asLong()).isZero();
        assertThat(result.path("cacheScope").asString()).isEqualTo("private");
        assertThat(resolveCount()).as("a static resource is a document of the catalogue: the broker is not asked").isZero();
        TestMcpServer.RecordedRequest call = serverCalls("resources/read").getLast();
        JsonNode claims = claims(call.header("authorization"));
        assertThat(claims.path("resource").asString()).isEqualTo(RUNBOOK);
        assertThat(claims.has("tool")).isFalse();
        assertThat(claims.has("pty")).as("the principal type is not emitted by this slice").isFalse();
        assertThat(call.header("x-mcp-credential")).isNull();

        JsonNode event = lastEvent(output, rid(response), "resource_read");
        assertThat(event.path("decision").asString()).isEqualTo("allow");
        assertThat(event.path("outcome").asString()).isEqualTo("ok");
        assertThat(event.path("resourceTemplate").asString()).isEqualTo("runbook");
        assertThat(event.path("contentBytes").asInt()).isEqualTo("Escalation runbook.".length());
        assertThat(event.path("contentSha256").asString()).startsWith("sha256:");
        assertThat(event.toString()).as("never the URI or the content").doesNotContain(RUNBOOK).doesNotContain("Escalation runbook.");
        assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", event)).isEmpty();
    }

    @Test
    void aTemplateIsReadWithTheCredentialOfTheUserAndTheClaimInBothTokens(CapturedOutput output) throws Exception {
        env.broker.clear();
        HttpResponse<String> response = read(reader(), "/mcp", ISSUE);

        assertThat(JSON.readTree(response.body()).path("result").path("contents").get(0).path("text").asString()).contains("ABC-123");
        assertThat(env.broker.received().stream().filter(r -> r.path().equals("/v1/credentials/resolve")))
                .allSatisfy(r -> {
                    assertThat(r.resource()).isEqualTo(ISSUE);
                    assertThat(r.tool()).isNull();
                });
        assertThat(resolveCount()).isEqualTo(1);
        TestMcpServer.RecordedRequest call = serverCalls("resources/read").getLast();
        assertThat(call.header("x-mcp-credential")).isEqualTo("Bearer alice-pat");
        assertThat(claims(call.header("authorization")).path("resource").asString()).isEqualTo(ISSUE);

        JsonNode event = lastEvent(output, rid(response), "resource_read");
        assertThat(event.path("resourceTemplate").asString()).isEqualTo("issue");
        assertThat(event.path("resource").path("type").asString()).isEqualTo("Docs::Issue");
        assertThat(event.path("resource").path("id").asString()).isEqualTo("ABC-123");
        assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", event)).isEmpty();
    }

    @Test
    void everyRefusalOfAReadIsTheSameAnswerAndTouchesNeitherTheServerNorTheBroker(CapturedOutput output) throws Exception {
        env.broker.clear();
        server.clearRequests();
        String stranger = env.idp.token(UUID.randomUUID().toString(), "sam", List.of("mcp-jira-read"));
        String bytes = null;
        for (String uri : List.of(ISSUE, "docs://nothing/here", "docs://issue/abc-123", "docs://issue/ABC-1?x=1", "docs://issue/ABC-1#top",
                "DOCS://issue/ABC-1", "docs://issue/ABC-1%2F..%2Fsecret", "docs://issue/..%2F..%2Fetc%2Fpasswd", "docs://issue/ABC-1%2541",
                "docs://issue/%41BC-1%0A", "docs://issue/", "jira://issue/ABC-1", "no-scheme")) {
            HttpResponse<String> response = read(stranger, "/mcp", uri);
            JsonNode error = error(response);
            assertThat(response.statusCode()).as(uri).isEqualTo(200);
            assertThat(error.path("code").asInt()).as(uri).isEqualTo(-32602);
            assertThat(error.path("message").asString()).as(uri).isEqualTo("Resource not found");
            assertThat(error.path("data").path("uri").asString()).as(uri).isEqualTo(uri);
            String shape = error.toString().replace(JSON.writeValueAsString(uri), "<uri>");
            bytes = bytes == null ? shape : bytes;
            assertThat(shape).as("the bytes do not tell the causes apart: " + uri).isEqualTo(bytes);
        }
        for (String uri : List.of("docs://issue/abc-123", "docs://issue/ABC-1?x=1", "docs://issue/ABC-1%2F..%2Fsecret", "docs://nothing/here")) {
            assertThat(error(read(reader(), "/mcp", uri)).path("message").asString()).as("for a reader too: " + uri).isEqualTo("Resource not found");
        }
        assertThat(serverCalls("resources/read")).isEmpty();
        assertThat(resolveCount()).isZero();
        assertThat(events(output, "resource_read").stream().map(e -> e.path("reason").asString("")))
                .contains("not_granted", "uri_no_match", "variable_invalid");
        assertThat(events(output, "resource_read")).allSatisfy(e -> assertThat(e.toString()).doesNotContain("passwd"));
    }

    @Test
    void theModernHeaderMustNameTheUriAndTheLegacyEraNeedsNone(CapturedOutput output) throws Exception {
        server.clearRequests();
        String token = reader();
        HttpResponse<String> wrong = sendModern(token, "/mcp", "resources/read", ISSUE, "{\"uri\":\"" + RUNBOOK + "\"}");
        assertThat(wrong.statusCode()).isEqualTo(400);
        assertThat(error(wrong).path("code").asInt()).isEqualTo(-32020);
        JsonNode event = lastEvent(output, rid(wrong), "resource_read");
        assertThat(event.path("reason").asString()).isEqualTo("header_mismatch");
        assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", event)).isEmpty();

        HttpResponse<String> missing = sendModern(token, "/mcp", "resources/read", null, "{\"uri\":\"" + RUNBOOK + "\"}");
        assertThat(error(missing).path("code").asInt()).isEqualTo(-32020);
        assertThat(serverCalls("resources/read")).isEmpty();

        String encoded = "=?base64?" + java.util.Base64.getEncoder().encodeToString(RUNBOOK.getBytes(java.nio.charset.StandardCharsets.UTF_8)) + "?=";
        assertThat(JSON.readTree(sendModern(token, "/mcp", "resources/read", encoded, "{\"uri\":\"" + RUNBOOK + "\"}").body()).path("result").has("contents"))
                .as("the base64 form of the header is the URI").isTrue();

        JsonNode legacy = legacy(token, "resources/read", "{\"uri\":\"" + RUNBOOK + "\"}");
        assertThat(legacy.path("result").path("contents")).hasSize(1);
        assertThat(legacy.path("result").has("ttlMs")).isFalse();
    }

    @Test
    void aTemplateNeedsTheBrokerToBeKnownToTakeTheClaimAndAStaticResourceDoesNot(CapturedOutput output) throws Exception {
        ReflectionTestUtils.setField(primitives, "brokerContractsVersion", null);
        env.broker.clear();
        server.clearRequests();

        HttpResponse<String> template = read(reader(), "/mcp", ISSUE);
        assertThat(error(template).path("code").asInt()).isEqualTo(-32603);
        assertThat(error(template).path("data").path("error").asString()).isEqualTo("upstream_unavailable");
        assertThat(lastEvent(output, rid(template), "resource_read").path("reason").asString()).isEqualTo("contracts_version_unsupported");
        assertThat(resolveCount()).as("the call is not sent to a broker that may refuse the claim").isZero();
        assertThat(serverCalls("resources/read")).isEmpty();

        assertThat(JSON.readTree(read(reader(), "/mcp", RUNBOOK).body()).path("result").has("contents")).isTrue();
    }

    @Test
    void aServerOfAnOlderContractIsNeverSentTheClaim(CapturedOutput output) throws Exception {
        server.reportContractsVersion(null);
        refresh();
        server.clearRequests();
        await().atMost(Duration.ofSeconds(10)).untilAsserted(() ->
                assertThat(names(list(reader(), "/mcp", "resources/list", "resources"))).as("unverifiable, so not listed").isEmpty());

        HttpResponse<String> response = read(reader(), "/mcp", RUNBOOK);

        assertThat(error(response).path("data").path("error").asString()).isEqualTo("upstream_unavailable");
        assertThat(lastEvent(output, rid(response), "resource_read").path("reason").asString()).isEqualTo("contracts_version_unsupported");
        assertThat(serverCalls("resources/read")).isEmpty();
        assertThat(names(list(reader(), "/mcp", "prompts/list", "prompts"))).as("a prompt needs no server").hasSize(1);
    }

    @Test
    void aMissingConnectionOfTheAccountIsCredentialRequiredWithTheLinkOfTheGateway() throws Exception {
        env.broker.mode(pl.aiwcorpo.mcp.gateway.support.BrokerStub.Mode.REQUIRED);
        try {
            JsonNode error = error(read(reader(), "/mcp", ISSUE));
            assertThat(error.path("code").asInt()).isEqualTo(-32603);
            assertThat(error.path("data").path("error").asString()).isEqualTo("credential_required");
            assertThat(error.path("data").path("system").asString()).isEqualTo("docs");
            assertThat(error.path("data").path("connectUrl").asString()).startsWith("https://").contains("docs");
        } finally {
            env.broker.mode(pl.aiwcorpo.mcp.gateway.support.BrokerStub.Mode.GRANT);
        }
    }

    @Test
    void aResultThatIsNotExactlyOneTextOfTheRequestedUriIsRefusedAndNeverPassedOn(CapturedOutput output) throws Exception {
        ObjectNode blob = JSON.createObjectNode();
        blob.putArray("contents").addObject().put("uri", RUNBOOK).put("blob", "AAAA").put("mimeType", "application/octet-stream");
        ObjectNode two = JSON.createObjectNode();
        two.putArray("contents").addObject().put("uri", RUNBOOK).put("text", "a");
        two.withArray("contents").addObject().put("uri", RUNBOOK).put("text", "b");
        ObjectNode other = JSON.createObjectNode();
        other.putArray("contents").addObject().put("uri", "docs://docs/other").put("text", "a");
        ObjectNode huge = JSON.createObjectNode();
        huge.putArray("contents").addObject().put("uri", RUNBOOK).put("text", "x".repeat(1_048_577));
        ObjectNode inputRequired = JSON.createObjectNode();
        inputRequired.put("resultType", "input_required");
        Map<String, ObjectNode> cases = new java.util.LinkedHashMap<>();
        cases.put("blob_not_supported", blob);
        cases.put("result_invalid", two);
        cases.put("result_too_large", huge);
        for (Map.Entry<String, ObjectNode> c : cases.entrySet()) {
            server.answerResourceReadWith(c.getValue());
            HttpResponse<String> response = read(reader(), "/mcp", RUNBOOK);
            assertThat(error(response).path("code").asInt()).as(c.getKey()).isEqualTo(-32603);
            assertThat(error(response).path("data").path("error").asString()).as(c.getKey()).isEqualTo("upstream_unavailable");
            JsonNode event = lastEvent(output, rid(response), "resource_read");
            assertThat(event.path("reason").asString()).isEqualTo(c.getKey());
            assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", event)).isEmpty();
        }
        server.answerResourceReadWith(other);
        assertThat(lastEvent(output, rid(read(reader(), "/mcp", RUNBOOK)), "resource_read").path("reason").asString()).as("another uri").isEqualTo("result_invalid");
        server.answerResourceReadWith(inputRequired);
        assertThat(lastEvent(output, rid(read(reader(), "/mcp", RUNBOOK)), "resource_read").path("reason").asString()).as("input_required").isEqualTo("result_invalid");
        server.answerResourceReadWith(null);
        server.failResourceRead(true);
        assertThat(error(read(reader(), "/mcp", RUNBOOK)).path("data").path("error").asString()).as("an error of the server").isEqualTo("upstream_unavailable");
        server.failResourceRead(false);
    }

    @Test
    void aSwitchedOffResourceIsNotFoundAndHiddenAndALiftedOneIsBack(CapturedOutput output) throws Exception {
        assertThat(adminCall("PUT", REGISTRY + "/resources/runbook/kill-switch", "{\"reason\":\"test\"}").statusCode()).isEqualTo(204);
        await().atMost(Duration.ofSeconds(8)).untilAsserted(() -> assertThat(error(read(reader(), "/mcp", RUNBOOK)).path("code").asInt()).isEqualTo(-32602));
        server.clearRequests();

        HttpResponse<String> response = read(reader(), "/mcp", RUNBOOK);
        assertThat(error(response).path("message").asString()).isEqualTo("Resource not found");
        assertThat(lastEvent(output, rid(response), "resource_read").path("reason").asString()).isEqualTo("kill_switch");
        assertThat(names(list(reader(), "/mcp", "resources/list", "resources"))).isEmpty();
        assertThat(names(list(reader(), "/mcp", "resources/templates/list", "resourceTemplates"))).as("the switch is of one name").containsExactly("issue");
        assertThat(names(list(reader(), "/mcp", "prompts/list", "prompts"))).as("it does not touch a prompt").hasSize(1);
        assertThat(serverCalls("resources/read")).isEmpty();
    }

    @Test
    void anEntryThatWaitsForApprovalIsNotFoundUntilItIsApproved() throws Exception {
        server.close();
        TestMcpServer fresh = env.startServer("mcp-docs", server.port());
        fresh.servePrimitives(true);
        server = fresh;
        adminCall("DELETE", SERVER_PATH, null);
        HttpResponse<String> created = adminCall("POST", "/admin/v1/servers", "{\"internalUrl\":\"https://127.0.0.1:" + server.port() + "/mcp\"}");
        assertThat(created.statusCode()).as(created.body()).isEqualTo(201);
        String fingerprint = JSON.readTree(created.body()).path("pendingConnection").path("fingerprint").asString();
        adminCall("POST", SERVER_PATH + "/connection/approve", "{\"tlsMode\":\"ca\",\"fingerprint\":\"" + fingerprint + "\"}");
        refresh();
        ObjectNode manifest = server.manifest();
        adminCall("POST", REGISTRY + "/policies/approve", "{\"policiesHash\":\"" + manifest.path("policiesHash").asString() + "\"}");

        assertThat(error(read(reader(), "/mcp", RUNBOOK)).path("code").asInt()).as("nothing approved").isEqualTo(-32602);
        assertThat(names(list(reader(), "/mcp", "resources/list", "resources"))).isEmpty();
        assertThat(error(getPrompt(reader(), "/mcp", "docs__summarize_issue", "{\"issueKey\":\"ABC-1\"}")).path("code").asInt()).isEqualTo(-32602);

        approve("resources", "runbook", manifest.path("resources").get(0));
        approve("prompts", "summarize_issue", manifest.path("prompts").get(0));
        await().atMost(Duration.ofSeconds(15)).untilAsserted(() ->
                assertThat(JSON.readTree(read(reader(), "/mcp", RUNBOOK).body()).path("result").has("contents")).isTrue());
        assertThat(error(read(reader(), "/mcp", ISSUE)).path("code").asInt()).as("the template was never approved").isEqualTo(-32602);
    }

    // --- prompts/get -----------------------------------------------------------------------------------------------

    @Test
    void aPromptIsComposedByTheGatewayFromTheApprovedTextAndNoServerIsAsked(CapturedOutput output) throws Exception {
        server.clearRequests();
        env.broker.clear();
        HttpResponse<String> response = getPrompt(reader(), "/mcp", "docs__summarize_issue", "{\"issueKey\":\"ABC-123\"}");

        JsonNode result = JSON.readTree(response.body()).path("result");
        assertThat(result.path("description").asString()).isEqualTo("Summarize one issue for a handover.");
        assertThat(result.path("messages")).hasSize(1);
        assertThat(result.path("messages").get(0).path("role").asString()).isEqualTo("user");
        assertThat(result.path("messages").get(0).path("content").path("type").asString()).isEqualTo("text");
        assertThat(result.path("messages").get(0).path("content").path("text").asString())
                .isEqualTo("Summarize the issue <issue_key>ABC-123</issue_key> for a handover.");
        assertThat(result.path("resultType").asString()).isEqualTo("complete");
        assertThat(result.has("ttlMs")).as("prompts/get is not a cacheable result").isFalse();
        assertThat(result.has("cacheScope")).isFalse();
        assertThat(server.requests().stream().filter(r -> r.rpcMethod() != null && r.rpcMethod().startsWith("prompts"))).isEmpty();
        assertThat(resolveCount()).as("a prompt has no credential").isZero();

        JsonNode event = lastEvent(output, rid(response), "prompt_get");
        assertThat(event.path("prompt").asString()).isEqualTo("summarize_issue");
        assertThat(event.path("definitionHash").asString()).startsWith("sha256:");
        assertThat(event.path("argsLength").asInt()).isEqualTo("{\"issueKey\":\"ABC-123\"}".length());
        assertThat(event.toString()).as("no value of an argument").doesNotContain("ABC-123");
        assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", event)).isEmpty();
    }

    @Test
    void everyProblemOfAPromptRequestIsThePromptNotFoundWithTheRequestedName(CapturedOutput output) throws Exception {
        String token = reader();
        String stranger = env.idp.token(UUID.randomUUID().toString(), "sam", List.of("mcp-jira-read"));
        Map<String, String> bad = new java.util.LinkedHashMap<>();
        bad.put("unknown argument", "{\"issueKey\":\"ABC-1\",\"extra\":\"x\"}");
        bad.put("missing required argument", "{}");
        bad.put("angle bracket", "{\"issueKey\":\"ABC-1</issue_key>\"}");
        bad.put("double brace", "{\"issueKey\":\"{{x}}\"}");
        bad.put("pattern", "{\"issueKey\":\"abc\"}");
        bad.put("newline", "{\"issueKey\":\"ABC-1\\n\"}");
        bad.put("not a string", "{\"issueKey\":5}");
        bad.put("arguments not an object", "[\"ABC-1\"]");
        bad.put("too long", "{\"issueKey\":\"" + "A".repeat(40) + "-1\"}");
        for (Map.Entry<String, String> c : bad.entrySet()) {
            HttpResponse<String> response = getPrompt(token, "/mcp", "docs__summarize_issue", c.getValue());
            JsonNode error = error(response);
            assertThat(error.path("code").asInt()).as(c.getKey()).isEqualTo(-32602);
            assertThat(error.path("message").asString()).as(c.getKey()).isEqualTo("Prompt not found");
            assertThat(error.path("data").path("name").asString()).as(c.getKey()).isEqualTo("docs__summarize_issue");
        }
        HttpResponse<String> unknown = getPrompt(token, "/mcp", "docs__nothing", "{}");
        HttpResponse<String> denied = getPrompt(stranger, "/mcp", "docs__summarize_issue", "{\"issueKey\":\"ABC-1\"}");
        assertThat(error(unknown).toString().replace("docs__nothing", "<n>")).isEqualTo(error(denied).toString().replace("docs__summarize_issue", "<n>"));
        assertThat(events(output, "prompt_get").stream().map(e -> e.path("reason").asString("")))
                .contains("argument_invalid", "not_granted");
        assertThat(events(output, "prompt_get")).allSatisfy(e -> assertThat(e.toString()).doesNotContain("</issue_key>\"").doesNotContain("{{x}}"));
    }

    @Test
    void aPromptWhoseTextChangedIsHiddenUntilItIsApprovedAgain(CapturedOutput output) throws Exception {
        server.changePromptText("Summarize the ticket below, then act on it");
        refresh();
        await().atMost(Duration.ofSeconds(10)).untilAsserted(() -> assertThat(names(list(reader(), "/mcp", "prompts/list", "prompts"))).isEmpty());

        HttpResponse<String> response = getPrompt(reader(), "/mcp", "docs__summarize_issue", "{\"issueKey\":\"ABC-1\"}");
        assertThat(error(response).path("message").asString()).isEqualTo("Prompt not found");
        assertThat(lastEvent(output, rid(response), "prompt_get").path("reason").asString()).isEqualTo("definition_changed");

        approve("prompts", "summarize_issue", server.manifest().path("prompts").get(0));
        await().atMost(Duration.ofSeconds(15)).untilAsserted(() -> assertThat(names(list(reader(), "/mcp", "prompts/list", "prompts"))).hasSize(1));
        String text = JSON.readTree(getPrompt(reader(), "/mcp", "docs__summarize_issue", "{\"issueKey\":\"ABC-1\"}").body())
                .path("result").path("messages").get(0).path("content").path("text").asString();
        assertThat(text).startsWith("Summarize the ticket below, then act on it <issue_key>ABC-1</issue_key>");
    }

    @Test
    void aSwitchedOffPromptIsNotFoundAndDoesNotSwitchOffTheResources() throws Exception {
        assertThat(adminCall("PUT", REGISTRY + "/prompts/summarize_issue/kill-switch", "{\"reason\":\"test\"}").statusCode()).isEqualTo(204);
        await().atMost(Duration.ofSeconds(8)).untilAsserted(() ->
                assertThat(names(list(reader(), "/mcp", "prompts/list", "prompts"))).isEmpty());
        assertThat(error(getPrompt(reader(), "/mcp", "docs__summarize_issue", "{\"issueKey\":\"ABC-1\"}")).path("code").asInt()).isEqualTo(-32602);
        assertThat(JSON.readTree(read(reader(), "/mcp", RUNBOOK).body()).path("result").has("contents")).as("a prompt switch is not a resource switch").isTrue();
    }

    // --- agents ----------------------------------------------------------------------------------------------------

    private String agentToken() {
        Instant now = Instant.now();
        JWTClaimsSet claims = env.idp.validClaims(AGENT_SUB, "service-account-" + CLIENT_AGENT).claim("azp", CLIENT_AGENT)
                .claim("groups", List.of("mcp-docs-read", "mcp-docs-write")).claim("principal_type", "agent")
                .issueTime(Date.from(now)).expirationTime(Date.from(now.plusSeconds(300))).build();
        return env.idp.sign(claims);
    }

    private void registerAgent(boolean suspended) {
        jdbc.sql("DELETE FROM agent_clients").update();
        agentStore.insert(new AgentClient(CLIENT_AGENT, AGENT_SUB, "4c7d1e90-5a2b-4e63-8f14-b2a9d0c6e358", Risk.READ_ONLY, List.of("mcp-docs-read"),
                false, ADMIN_SUB, Instant.now(), null, null));
        if (suspended) {
            agentStore.suspend(CLIENT_AGENT, ADMIN_SUB, Instant.now(), "test");
        }
        agents.refresh();
    }

    @Test
    void anAgentReadsWhatItsGroupsLeaveAndTheCeilingOfRiskDoesNotLimitReading(CapturedOutput output) throws Exception {
        registerAgent(false);
        String token = agentToken();
        assertThat(names(list(token, "/mcp", "resources/list", "resources"))).containsExactly("runbook");
        assertThat(names(list(token, "/mcp", "prompts/list", "prompts"))).containsExactly("docs__summarize_issue");
        assertThat(JSON.readTree(getPrompt(token, "/mcp", "docs__summarize_issue", "{\"issueKey\":\"ABC-1\"}").body()).path("result").has("messages"))
                .as("maxRisk READ_ONLY does not limit a prompt").isTrue();
        HttpResponse<String> response = read(token, "/mcp", RUNBOOK);
        assertThat(JSON.readTree(response.body()).path("result").has("contents")).isTrue();
        JsonNode event = lastEvent(output, rid(response), "resource_read");
        assertThat(event.path("principalType").asString()).isEqualTo("agent");
    }

    @Test
    void anAgentIsRefusedATemplateThatNeedsACredentialOfAPersonBeforeTheBroker(CapturedOutput output) throws Exception {
        registerAgent(false);
        env.broker.clear();
        server.clearRequests();

        HttpResponse<String> response = read(agentToken(), "/mcp", ISSUE);

        assertThat(error(response).path("code").asInt()).isEqualTo(-32602);
        assertThat(error(response).path("message").asString()).isEqualTo("Resource not found");
        assertThat(lastEvent(output, rid(response), "resource_read").path("reason").asString()).isEqualTo("principal_not_eligible");
        assertThat(resolveCount()).isZero();
        assertThat(serverCalls("resources/read")).isEmpty();
    }

    @Test
    void aSuspendedAgentReadsNothingAndSeesNothing(CapturedOutput output) throws Exception {
        registerAgent(true);
        String token = agentToken();
        assertThat(names(list(token, "/mcp", "resources/list", "resources"))).isEmpty();
        assertThat(names(list(token, "/mcp", "prompts/list", "prompts"))).isEmpty();
        HttpResponse<String> response = read(token, "/mcp", RUNBOOK);
        assertThat(error(response).path("message").asString()).isEqualTo("Resource not found");
        assertThat(lastEvent(output, rid(response), "resource_read").path("reason").asString()).isEqualTo("agent_suspended");
        assertThat(error(getPrompt(token, "/mcp", "docs__summarize_issue", "{\"issueKey\":\"ABC-1\"}")).path("message").asString()).isEqualTo("Prompt not found");
    }

    // --- links in tool results -------------------------------------------------------------------------------------

    @Test
    void aLinkOfAToolResultToAnotherSchemeIsRemovedAndTheCallIsAuditedForIt(CapturedOutput output) throws Exception {
        ObjectNode result = JSON.createObjectNode();
        var content = result.putArray("content");
        content.addObject().put("type", "text").put("text", "{\"key\":\"ABC-1\"}");
        content.addObject().put("type", "resource_link").put("uri", "jira://issue/ABC-1").put("name", "issue");
        content.addObject().put("type", "resource_link").put("uri", "file:///etc/passwd").put("name", "passwd");
        content.addObject().put("type", "resource").putObject("resource").put("uri", "https://elsewhere.example/x").put("text", "x");
        result.put("isError", false);
        env.jira.answerCallsWith(result);

        HttpResponse<String> response = callGetIssue(aliceToken());

        JsonNode blocks = JSON.readTree(response.body()).path("result").path("content");
        assertThat(blocks).hasSize(2);
        assertThat(blocks.get(1).path("uri").asString()).isEqualTo("jira://issue/ABC-1");
        JsonNode event = lastEvent(output, rid(response), "tool_call");
        assertThat(event.path("reason").asString()).isEqualTo("link_scheme_refused");
        assertThat(event.path("outcome").asString()).isEqualTo("ok");
    }

    @Test
    void argumentsThatAreNotAnObjectAreCheckedAfterAuthorizationAndAnswerLikeAnyBadArgument() throws Exception {
        String stranger = env.idp.token(UUID.randomUUID().toString(), "sam", List.of("mcp-jira-read"));
        HttpResponse<String> denied = getPrompt(stranger, "/mcp", "docs__summarize_issue", "[1]");
        HttpResponse<String> bad = getPrompt(reader(), "/mcp", "docs__summarize_issue", "[1]");

        assertThat(denied.statusCode()).isEqualTo(200);
        assertThat(bad.statusCode()).as("not a request error: the caller may get the prompt, so the argument is judged").isEqualTo(200);
        assertThat(error(bad).toString()).isEqualTo(error(denied).toString());
        assertThat(error(bad).path("message").asString()).isEqualTo("Prompt not found");
    }

    @Test
    void aReadOfAnEntryNobodyApprovedIsAuditedAsNotGrantedAndNotAsNoMatch(CapturedOutput output) throws Exception {
        server.close();
        TestMcpServer fresh = env.startServer("mcp-docs", server.port());
        fresh.servePrimitives(true);
        server = fresh;
        adminCall("DELETE", SERVER_PATH, null);
        HttpResponse<String> created = adminCall("POST", "/admin/v1/servers", "{\"internalUrl\":\"https://127.0.0.1:" + server.port() + "/mcp\"}");
        String fingerprint = JSON.readTree(created.body()).path("pendingConnection").path("fingerprint").asString();
        adminCall("POST", SERVER_PATH + "/connection/approve", "{\"tlsMode\":\"ca\",\"fingerprint\":\"" + fingerprint + "\"}");
        refresh();
        adminCall("POST", REGISTRY + "/policies/approve", "{\"policiesHash\":\"" + server.manifest().path("policiesHash").asString() + "\"}");

        HttpResponse<String> response = read(reader(), "/mcp", RUNBOOK);

        assertThat(error(response).path("message").asString()).isEqualTo("Resource not found");
        assertThat(lastEvent(output, rid(response), "resource_read").path("reason").asString()).isEqualTo("not_granted");
        HttpResponse<String> unknown = read(reader(), "/mcp", "docs://docs/never");
        assertThat(lastEvent(output, rid(unknown), "resource_read").path("reason").asString()).isEqualTo("uri_no_match");
    }

    @Test
    void onlyTheUriTheMimeTypeAndTheTextOfTheItemArePassedOn() throws Exception {
        ObjectNode rich = JSON.createObjectNode();
        ObjectNode item = rich.putArray("contents").addObject();
        item.put("uri", RUNBOOK).put("mimeType", "text/plain").put("text", "hello").put("extra", "x");
        item.putObject("_meta").put("note", "from the server");
        item.putObject("annotations").put("audience", "user");
        rich.put("_meta", "outer");
        server.answerResourceReadWith(rich);

        JsonNode result = JSON.readTree(read(reader(), "/mcp", RUNBOOK).body()).path("result");

        assertThat(result.path("contents").get(0).propertyNames()).containsExactlyInAnyOrder("uri", "mimeType", "text");
    }

    @Test
    void theListsOfManyReadersShareOneReadOfAServerAndAHangingServerDoesNotHoldThemUp() throws Exception {
        server.clearRequests();
        server.slowResourceLists(300);
        primitiveReadings.clear();
        String one = reader();
        List<java.util.concurrent.Future<HttpResponse<String>>> shared = new ArrayList<>();
        try (var pool = java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor()) {
            for (int i = 0; i < 5; i++) {
                shared.add(pool.submit(() -> list(one, "/mcp", "resources/list", "resources")));
            }
            for (var each : shared) {
                assertThat(names(each.get())).containsExactly("runbook");
            }
        }
        assertThat(serverCalls("resources/list")).as("one reading for five lists of one user").hasSize(1);

        primitiveReadings.clear();
        server.slowResourceLists(20_000);
        long started = System.nanoTime();
        List<java.util.concurrent.Future<HttpResponse<String>>> hung = new ArrayList<>();
        try (var pool = java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor()) {
            for (int i = 0; i < 5; i++) {
                hung.add(pool.submit(() -> list(one, "/mcp", "resources/list", "resources")));
            }
            for (var each : hung) {
                assertThat(names(each.get())).as("skipped, not stuck").isEmpty();
            }
        }
        assertThat(Duration.ofNanos(System.nanoTime() - started)).as("bounded by the time limit of a list, not by the lock").isLessThan(Duration.ofSeconds(10));

        server.slowResourceLists(0);
        primitiveReadings.clear();
        await().atMost(Duration.ofSeconds(35)).untilAsserted(() -> assertThat(names(list(reader(), "/mcp", "resources/list", "resources"))).containsExactly("runbook"));
    }
}
