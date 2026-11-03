package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import javax.net.ssl.SSLContext;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import pl.aiwcorpo.mcp.gateway.registry.RegistryService;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.system.CapturedOutput;

import pl.aiwcorpo.mcp.gateway.support.Contracts;
import pl.aiwcorpo.mcp.manifest.DefinitionHash;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * The channel of an adapter and the classification by an administrator over HTTP (C5, CC-193, CC-206, CC-207): mcp-opensearch is configured
 * as a server behind an adapter, the test server stands in for the foreign one. What the certificate, the body and the mode decide, in
 * that order; what a submission stores; how a classified tool is served.
 */
class AdapterChannelTest extends GatewayTestBase {

    private static final String PATH = "/admin/v1/registry/adapters/mcp-opensearch";
    private static final List<String> ADMIN = List.of("mcp-platform-admin");
    private static final String ADMIN_SUB = "3b0d6f2e-91c4-4d7a-8a52-6c1e4f7a9d10";

    @Autowired
    RegistryService registry;

    @BeforeEach
    @AfterEach
    void startFromNothing() throws Exception {
        // A manifest has at least one tool, so the state is emptied where the operator would: in the tables.
        env.forgetRegistryOf("mcp-opensearch");
        jdbc.sql("DELETE FROM registry_risk_floor WHERE server_id = ?").param("mcp-opensearch").update();
        registry.reloadChanged();
    }

    private HttpResponse<String> submit(SSLContext tls, String path, JsonNode manifest) throws Exception {
        return admin(tls, "PUT", path, null, JSON.writeValueAsString(manifest));
    }

    private HttpResponse<String> asAdmin(String method, String path, String body) throws Exception {
        return admin(method, path, ADMIN_SUB, "a.admin", ADMIN, body);
    }

    private static JsonNode toolOf(JsonNode server, String name) {
        for (JsonNode tool : server.path("tools")) {
            if (name.equals(tool.path("name").asString())) {
                return tool;
            }
        }
        return null;
    }

    private JsonNode registryEntry(String tool) throws Exception {
        for (JsonNode server : JSON.readTree(asAdmin("GET", "/admin/v1/registry/servers", null).body())) {
            if ("mcp-opensearch".equals(server.path("serverId").asString())) {
                return toolOf(server, tool);
            }
        }
        return null;
    }

    private String readerToken() {
        return env.idp.token(UUID.randomUUID().toString(), "reader", List.of("mcp-opensearch-read"));
    }

    private List<String> listed() throws Exception {
        List<String> names = new ArrayList<>();
        JSON.readTree(sendModern(readerToken(), "/s/mcp-opensearch/mcp", "tools/list", null, "{}").body()).path("result").path("tools")
                .forEach(t -> names.add(t.path("name").asString()));
        return names;
    }

    private static List<JsonNode> events(CapturedOutput output, String event, String reason) {
        List<JsonNode> found = new ArrayList<>();
        for (String line : output.getOut().split("\n")) {
            if (line.startsWith("{") && line.contains("\"event\":\"" + event + "\"") && line.contains("\"reason\":\"" + reason + "\"")) {
                found.add(JSON.readTree(line));
            }
        }
        return found;
    }

    @Test
    void theCertificateComesBeforeTheBodyAndTheBodyBeforeTheMode(CapturedOutput output) throws Exception {
        ObjectNode manifest = env.opensearch.adapterManifest();
        ObjectNode other = manifest.deepCopy();
        other.put("serverId", "mcp-gitlab");

        assertThat(submit(env.noClientCertificateTls, PATH, manifest).statusCode()).isEqualTo(401);
        assertThat(submit(env.ciOpensearchTls, PATH, manifest).statusCode()).as("the pipeline has no business here").isEqualTo(403);
        assertThat(submit(env.adapterGitlabTls, PATH, manifest).statusCode()).as("the adapter of another server").isEqualTo(403);
        ObjectNode jira = manifest.deepCopy();
        jira.put("serverId", "mcp-jira");
        assertThat(submit(env.adapterGitlabTls, "/admin/v1/registry/adapters/mcp-jira", jira).statusCode())
                .as("a caller without the right name learns nothing about the mode of a server: 403, not 422").isEqualTo(403);
        assertThat(output.getOut()).contains("\"reason\":\"client_certificate_rejected\"");

        assertThat(submit(env.adapterOpensearchTls, PATH, other).statusCode()).as("serverId of the body against the path").isEqualTo(400);
        assertThat(admin(env.adapterOpensearchTls, "PUT", PATH, null, "not json").statusCode()).isEqualTo(400);

        HttpResponse<String> notAdapterMode = submit(env.adapterJiraTls, "/admin/v1/registry/adapters/mcp-jira", jira);
        assertThat(notAdapterMode.statusCode()).isEqualTo(422);
        assertThat(JSON.readTree(notAdapterMode.body()).path("reason").asString()).isEqualTo("adapter_mode_mismatch");

        ObjectNode withoutSource = manifest.deepCopy();
        withoutSource.remove("source");
        HttpResponse<String> noSource = submit(env.adapterOpensearchTls, PATH, withoutSource);
        assertThat(noSource.statusCode()).isEqualTo(422);
        assertThat(JSON.readTree(noSource.body()).path("reason").asString()).isEqualTo("adapter_mode_mismatch");

        HttpResponse<String> pipelineForAdapterServer = submit(env.ciOpensearchTls, "/admin/v1/registry/servers/mcp-opensearch", env.opensearch.manifest());
        assertThat(pipelineForAdapterServer.statusCode()).isEqualTo(422);
        assertThat(JSON.readTree(pipelineForAdapterServer.body()).path("reason").asString()).isEqualTo("adapter_mode_mismatch");
        HttpResponse<String> adapterManifestOnPipeline = submit(env.ciGitlabTls, "/admin/v1/registry/servers/mcp-gitlab", manifest.deepCopy().put("serverId", "mcp-gitlab"));
        assertThat(adapterManifestOnPipeline.statusCode()).isEqualTo(422);
        assertThat(JSON.readTree(adapterManifestOnPipeline.body()).path("reason").asString()).isEqualTo("adapter_mode_mismatch");
        assertThat(registryEntry("get_issue")).as("nothing was stored").isNull();
        assertThat(events(output, "admin_change", "adapter_mode_mismatch")).isNotEmpty();
    }

    @Test
    void aSubmissionIsPendingAndAClassifiedToolIsServed(CapturedOutput output) throws Exception {
        ObjectNode manifest = env.opensearch.adapterManifest();
        HttpResponse<String> stored = submit(env.adapterOpensearchTls, PATH, manifest);
        assertThat(stored.statusCode()).as(stored.body()).isEqualTo(200);
        JsonNode body = JSON.readTree(stored.body());
        assertThat(Contracts.gatewayAdminErrors("AdapterRegistryServer", body)).isEmpty();
        for (JsonNode tool : body.path("tools")) {
            assertThat(tool.path("status").asString()).isEqualTo("pending_approval");
            assertThat(tool.path("source").asString()).isEqualTo("adapter");
            assertThat(tool.path("change").asString()).isEqualTo("new");
            assertThat(tool.has("risk") || tool.has("action") || tool.has("classifiedBy")).isFalse();
        }
        assertThat(events(output, "admin_change", "definition_submitted").stream().filter(e -> "mcp-opensearch".equals(e.path("server").asString())))
                .hasSize(body.path("tools").size());
        assertThat(listed()).isEmpty();
        JsonNode unclassified = toolError(sendModern(readerToken(), "/s/mcp-opensearch/mcp", "tools/call", "opensearch__get_issue",
                "{\"name\":\"opensearch__get_issue\",\"arguments\":{\"issueKey\":\"ABC-1\"}}"));
        assertThat(unclassified.path("error").asString()).as("judged as the most dangerous kind, so it tells a reader nothing").isEqualTo("not_found_or_denied");
        JsonNode listing = registryEntry("get_issue");
        assertThat(Contracts.gatewayAdminErrors("RegistryTool", listing)).isEmpty();
        String hash = listing.path("definitionHash").asString();

        String approve = "/admin/v1/registry/servers/mcp-opensearch/tools/get_issue/approve";
        // A floor above READ_ONLY (a voided classification, or one from before the tool left the manifest): the views say that approving lowers the risk.
        jdbc.sql("INSERT INTO registry_risk_floor (server_id, tool, risk) VALUES ('mcp-opensearch', 'get_issue', 1) ON CONFLICT (server_id, tool) DO UPDATE SET risk = 1").update();
        assertThat(registryEntry("get_issue").path("riskLowered").asBoolean(false)).as("the list of the registry").isTrue();
        JsonNode lowering = JSON.readTree(asAdmin("GET", "/admin/v1/registry/servers/mcp-opensearch/tools/get_issue/pending", null).body());
        assertThat(lowering.path("riskLowered").asBoolean(false)).as("the diff").isTrue();
        assertThat(Contracts.gatewayAdminErrors("PendingTool", lowering)).isEmpty();
        HttpResponse<String> withoutFlag = asAdmin("POST", approve, "{\"definitionHash\":\"" + hash + "\",\"risk\":\"READ_ONLY\",\"action\":\"read\"}");
        assertThat(withoutFlag.statusCode()).isEqualTo(422);
        assertThat(JSON.readTree(withoutFlag.body()).path("reason").asString()).isEqualTo("risk_lowered");
        jdbc.sql("DELETE FROM registry_risk_floor WHERE server_id = 'mcp-opensearch' AND tool = 'get_issue'").update();
        assertThat(registryEntry("get_issue").path("riskLowered").asBoolean(false)).as("no floor, no lowering").isFalse();

        HttpResponse<String> required = asAdmin("POST", approve, "{\"definitionHash\":\"" + hash + "\"}");
        assertThat(required.statusCode()).isEqualTo(422);
        assertThat(JSON.readTree(required.body()).path("reason").asString()).isEqualTo("classification_required");
        HttpResponse<String> inconsistent = asAdmin("POST", approve, "{\"definitionHash\":\"" + hash + "\",\"risk\":\"READ_ONLY\",\"action\":\"delete\"}");
        assertThat(inconsistent.statusCode()).isEqualTo(422);
        assertThat(JSON.readTree(inconsistent.body()).path("reason").asString()).isEqualTo("classification_inconsistent");
        HttpResponse<String> writes = asAdmin("POST", approve, "{\"definitionHash\":\"" + hash + "\",\"risk\":\"UPDATE\",\"action\":\"update\"}");
        assertThat(writes.statusCode()).as("a tool of an adapter is read only (CC-227)").isEqualTo(422);
        assertThat(JSON.readTree(writes.body()).path("reason").asString()).isEqualTo("classification_not_allowed");
        assertThat(asAdmin("POST", approve, "{\"definitionHash\":\"" + hash + "\",\"risk\":\"BOGUS\",\"action\":\"read\"}").statusCode()).isEqualTo(400);

        HttpResponse<String> approved = asAdmin("POST", approve, "{\"definitionHash\":\"" + hash + "\",\"risk\":\"READ_ONLY\",\"action\":\"read\"}");
        assertThat(approved.statusCode()).as(approved.body()).isEqualTo(204);
        await().atMost(Duration.ofSeconds(8)).untilAsserted(() -> assertThat(listed()).containsExactly("opensearch__get_issue"));
        assertThat(events(output, "admin_change", "definition_approved").stream().filter(e -> "mcp-opensearch".equals(e.path("server").asString())
                && "read".equals(e.path("action").asString()))).singleElement().satisfies(e -> {
            assertThat(e.path("risk").asString()).isEqualTo("READ_ONLY");
            assertThat(e.path("sub").asString()).isEqualTo(ADMIN_SUB);
            assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", e)).isEmpty();
        });
        JsonNode classified = registryEntry("get_issue");
        assertThat(Contracts.gatewayAdminErrors("RegistryTool", classified)).isEmpty();
        assertThat(classified.path("risk").asString()).isEqualTo("READ_ONLY");
        assertThat(classified.path("classifiedBy").asString()).isEqualTo(ADMIN_SUB);

        JsonNode served = toolError(sendModern(readerToken(), "/s/mcp-opensearch/mcp", "tools/call", "opensearch__get_issue",
                "{\"name\":\"opensearch__get_issue\",\"arguments\":{\"issueKey\":\"ABC-1\"}}"));
        assertThat(served.has("error")).as(served.toString()).isFalse();
        assertThat(env.opensearch.requests()).anyMatch(r -> "tools/call".equals(r.rpcMethod()) && "get_issue".equals(r.toolName()));
        JsonNode token = claims(env.opensearch.requests().stream().filter(r -> "tools/call".equals(r.rpcMethod()) && "get_issue".equals(r.toolName()))
                .reduce((a, b) -> b).orElseThrow().header("authorization"));
        assertThat(token.path("mcp_risk").asString()).as("the classification of the administrator, for the sidecar").isEqualTo("READ_ONLY");
        assertThat(token.path("mcp_action").asString()).isEqualTo("read");

        HttpResponse<String> again = submit(env.adapterOpensearchTls, PATH, manifest);
        assertThat(again.statusCode()).isEqualTo(200);
        JsonNode stays = toolOf(JSON.readTree(again.body()), "get_issue");
        assertThat(stays.path("status").asString()).isEqualTo("approved");
        assertThat(stays.path("risk").asString()).as("the adapter sees the classification, not who gave it").isEqualTo("READ_ONLY");
        assertThat(stays.has("classifiedBy")).isFalse();
        assertThat(Contracts.gatewayAdminErrors("AdapterRegistryServer", JSON.readTree(again.body()))).isEmpty();
        assertThat(listed()).contains("opensearch__get_issue");

        ObjectNode changed = manifest.deepCopy();
        ObjectNode entry = (ObjectNode) toolOf(changed, "get_issue");
        ((ObjectNode) entry.get("definition")).put("description", "Returns one issue, and this text is new.");
        entry.put("definitionHash", DefinitionHash.ofManifestTool(JSON.writeValueAsString(changed), "get_issue"));
        HttpResponse<String> second = submit(env.adapterOpensearchTls, PATH, changed);
        assertThat(JSON.readTree(second.body()).path("tools").get(0).path("status").asString()).isEqualTo("pending_approval");
        JsonNode diff = JSON.readTree(asAdmin("GET", "/admin/v1/registry/servers/mcp-opensearch/tools/get_issue/pending", null).body());
        assertThat(Contracts.gatewayAdminErrors("PendingTool", diff)).isEmpty();
        assertThat(diff.path("source").asString()).isEqualTo("adapter");
        assertThat(diff.path("approvedEntry").path("risk").asString()).as("the earlier classification, as a suggestion").isEqualTo("READ_ONLY");
        assertThat(diff.path("pendingEntry").has("risk")).isFalse();
    }
}
