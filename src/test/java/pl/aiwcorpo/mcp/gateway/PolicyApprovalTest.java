package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import pl.aiwcorpo.mcp.testserver.TestMcpServer;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * The approval of the policies of a server (C5 getPendingServerPolicies, approveServerPolicies) as a gate: nothing of the server is served
 * before it, a hash that is not the pending one is a conflict, and a running server that presents other policies than the approved ones is
 * pinned back (pending_approval, its tools blocked) until an administrator approves them.
 */
class PolicyApprovalTest extends GatewayTestBase {

    private static final String SERVER = "/admin/v1/registry/servers/mcp-pinned";
    private static final List<String> GROUPS = List.of("mcp-pinned-read");

    private TestMcpServer pinned;
    private ObjectNode manifest;

    @BeforeEach
    void addTheServer() throws Exception {
        pinned = env.startServer("mcp-pinned");
        String body = "{\"serverId\":\"mcp-pinned\",\"system\":\"pinned\",\"internalUrl\":\"https://127.0.0.1:" + pinned.port() + "/mcp\","
                + "\"credential\":{\"required\":true,\"acceptedTypes\":[\"user-secret\"],\"type\":\"user-secret\"}}";
        assertThat(adminCall("POST", "/admin/v1/servers", body).statusCode()).isEqualTo(201);
        manifest = pinned.manifest();
        HttpResponse<String> registered = admin(env.pipelineTls("mcp-pinned"), "PUT", SERVER, null, JSON.writeValueAsString(manifest));
        assertThat(registered.statusCode()).as(registered.body()).isEqualTo(200);
    }

    @AfterEach
    void removeTheServer() throws Exception {
        adminCall("DELETE", "/admin/v1/servers/mcp-pinned", null);
        pinned.close();
    }

    private String hash() {
        return manifest.path("policiesHash").asString();
    }

    private JsonNode registryEntry() throws Exception {
        for (JsonNode server : JSON.readTree(adminCall("GET", "/admin/v1/registry/servers", null).body())) {
            if ("mcp-pinned".equals(server.path("serverId").asString())) {
                return server;
            }
        }
        throw new AssertionError("mcp-pinned is not in the registry");
    }

    private List<String> listed(String token) throws Exception {
        HttpResponse<String> response = sendModern(token, "/mcp?systems=pinned", "tools/list", null, "{}");
        return JSON.readTree(response.body()).path("result").path("tools").findValuesAsString("name");
    }

    private HttpResponse<String> call(String token) throws Exception {
        return sendModern(token, "/mcp", "tools/call", "pinned__get_issue", "{\"name\":\"pinned__get_issue\",\"arguments\":{\"issueKey\":\"ABC-1\"}}");
    }

    @Test
    void theFirstRegistrationWaitsForAnApprovalThatNeedsTheHashOfWhatWaits() throws Exception {
        JsonNode waiting = registryEntry();
        assertThat(waiting.path("policiesStatus").asString()).isEqualTo("pending_approval");
        assertThat(waiting.path("pendingPoliciesHash").asString()).isEqualTo(hash());
        assertThat(waiting.has("policiesHash")).as("nothing is approved yet").isFalse();

        HttpResponse<String> pending = adminCall("GET", SERVER + "/policies/pending", null);
        assertThat(pending.statusCode()).isEqualTo(200);
        JsonNode diff = JSON.readTree(pending.body());
        assertThat(diff.path("approvedHash").isNull()).isTrue();
        assertThat(diff.path("pendingHash").asString()).isEqualTo(hash());
        assertThat(diff.path("source").asString()).isEqualTo("ci");
        assertThat(diff.path("pendingPolicies").path("namespace").asString()).isEqualTo("Pinned");
        assertThat(diff.path("pendingResourceTypes").findValuesAsString("type")).contains("Pinned::Project", "Pinned::Issue");
        assertThat(pl.aiwcorpo.mcp.gateway.support.Contracts.gatewayAdminErrors("PendingPolicies", diff)).isEmpty();

        String token = env.idp.token(UUID.randomUUID().toString(), "pia", GROUPS);
        assertThat(listed(token)).isEmpty();
        assertThat(toolError(call(token)).path("error").asString()).isEqualTo("tool_disabled");

        HttpResponse<String> wrong = adminCall("POST", SERVER + "/policies/approve", "{\"policiesHash\":\"sha256:" + "0".repeat(64) + "\"}");
        assertThat(wrong.statusCode()).isEqualTo(409);
        assertThat(JSON.readTree(wrong.body()).path("error").asString()).isEqualTo("hash_mismatch");
        assertThat(adminCall("POST", SERVER + "/policies/approve", "{\"policiesHash\":\"nope\"}").statusCode()).isEqualTo(400);
        assertThat(listed(token)).as("a refused approval changes nothing").isEmpty();

        HttpResponse<String> approved = adminCall("POST", SERVER + "/policies/approve", "{\"policiesHash\":\"" + hash() + "\"}");
        assertThat(approved.statusCode()).as(approved.body()).isEqualTo(200);
        assertThat(JSON.readTree(approved.body()).path("ignoredMappingEntries").isArray()).isTrue();
        assertThat(pl.aiwcorpo.mcp.gateway.support.Contracts.gatewayAdminErrors("ApprovePoliciesResult", JSON.readTree(approved.body()))).isEmpty();
        assertThat(registryEntry().path("policiesStatus").asString()).isEqualTo("approved");
        assertThat(registryEntry().path("policiesHash").asString()).isEqualTo(hash());
        assertThat(adminCall("GET", SERVER + "/policies/pending", null).statusCode()).as("nothing waits any more").isEqualTo(404);
        assertThat(listed(token)).contains("pinned__get_issue");
        assertThat(call(token).statusCode()).isEqualTo(200);
    }

    @Test
    void aRunningServerThatPresentsOtherPoliciesIsPinnedBackUntilTheyAreApproved() throws Exception {
        assertThat(adminCall("POST", SERVER + "/policies/approve", "{\"policiesHash\":\"" + hash() + "\"}").statusCode()).isEqualTo(200);
        String token = env.idp.token(UUID.randomUUID().toString(), "pia", GROUPS);
        assertThat(listed(token)).contains("pinned__get_issue");

        // The server is redeployed with a policy that nobody approved; nothing registered it.
        pinned.driftPolicies(true);

        await().atMost(Duration.ofSeconds(15)).pollInterval(Duration.ofMillis(500)).untilAsserted(() -> {
            assertThat(listed(token)).as("blocked at the next check of the live server").isEmpty();
            assertThat(registryEntry().path("policiesStatus").asString()).isEqualTo("pending_approval");
        });
        JsonNode entry = registryEntry();
        assertThat(entry.path("policiesHash").asString()).as("the approved hash is still the old one").isEqualTo(hash());
        String drifted = entry.path("pendingPoliciesHash").asString();
        assertThat(drifted).startsWith("sha256:").isNotEqualTo(hash());
        JsonNode diff = JSON.readTree(adminCall("GET", SERVER + "/policies/pending", null).body());
        assertThat(diff.path("source").asString()).isEqualTo("server");
        assertThat(diff.path("approvedHash").asString()).isEqualTo(hash());
        assertThat(diff.path("pendingPolicies").path("files").findValuesAsString("name")).contains("zz-drift.cedar");
        assertThat(toolError(call(token)).path("error").asString()).isEqualTo("tool_disabled");

        assertThat(adminCall("POST", SERVER + "/policies/approve", "{\"policiesHash\":\"" + hash() + "\"}").statusCode())
                .as("the hash that was approved before is not what waits").isEqualTo(409);
        assertThat(adminCall("POST", SERVER + "/policies/approve", "{\"policiesHash\":\"" + drifted + "\"}").statusCode()).isEqualTo(200);
        await().atMost(Duration.ofSeconds(15)).pollInterval(Duration.ofMillis(500)).untilAsserted(() ->
                assertThat(listed(token)).contains("pinned__get_issue"));
        assertThat(call(token).statusCode()).isEqualTo(200);
    }

    @Test
    void aServerThatGoesBackToTheApprovedPoliciesLosesItsPendingEntry() throws Exception {
        assertThat(adminCall("POST", SERVER + "/policies/approve", "{\"policiesHash\":\"" + hash() + "\"}").statusCode()).isEqualTo(200);
        String token = env.idp.token(UUID.randomUUID().toString(), "pia", GROUPS);
        pinned.driftPolicies(true);
        await().atMost(Duration.ofSeconds(15)).pollInterval(Duration.ofMillis(500)).untilAsserted(() -> {
            listed(token);
            assertThat(registryEntry().path("policiesStatus").asString()).isEqualTo("pending_approval");
        });

        pinned.driftPolicies(false);

        await().atMost(Duration.ofSeconds(15)).pollInterval(Duration.ofMillis(500)).untilAsserted(() -> {
            listed(token);
            assertThat(registryEntry().path("policiesStatus").asString()).isEqualTo("approved");
        });
        assertThat(registryEntry().has("pendingPoliciesHash")).isFalse();
    }
}
