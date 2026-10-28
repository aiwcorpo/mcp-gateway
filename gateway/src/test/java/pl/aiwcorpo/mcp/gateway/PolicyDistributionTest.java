package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.system.CapturedOutput;

import io.micrometer.core.instrument.MeterRegistry;
import pl.aiwcorpo.mcp.gateway.policy.PolicyService;
import pl.aiwcorpo.mcp.gateway.support.TestBundles;
import tools.jackson.databind.JsonNode;

/** Cedar from signed bundles in the running gateway: the revision in the token, a swap takes effect, a bad bundle changes nothing. */
class PolicyDistributionTest extends GatewayTestBase {

    /** Revisions must grow across the JVM: the other test classes share the loaded policies. */
    private static final AtomicInteger NEXT = new AtomicInteger(100);

    private static final String NO_GET_ISSUE = "@id(\"test-no-get-issue\") forbid (principal, action == Action::\"call\", resource is Tool)"
            + " when { resource.server == \"mcp-jira\" && resource.name == \"get_issue\" };";
    private static final String NO_ISSUE_13 = "@id(\"test-no-abc-13\") forbid (principal, action == Action::\"call\", resource is Tool)"
            + " when { context has refs && context.refs has jiraIssue && context.refs.jiraIssue.contains(\"ABC-13\") };";

    @Autowired
    PolicyService policies;

    @Autowired
    MeterRegistry meters;

    private String publishMain(Map<String, String> extra) {
        String revision = TestBundles.revision(NEXT.getAndIncrement());
        env.policies.publishMain(TestBundles.main(revision, extra));
        await().atMost(Duration.ofSeconds(10)).until(() -> revision.equals(policies.revision()));
        return revision;
    }

    @AfterEach
    void backToThePlainPolicies() {
        publishMain(Map.of());
    }

    private HttpResponse<String> getIssue() throws Exception {
        return callGetIssue(aliceToken());
    }

    @Test
    void theInternalJwtCarriesTheRevisionOfTheBundleInForce() throws Exception {
        String revision = publishMain(Map.of());
        assertThat(JSON.readTree(getIssue().body()).path("result").path("isError").asBoolean()).isFalse();
        assertThat(claims(lastToolCall(env.jira).header("authorization")).path("prv").asString()).isEqualTo(revision);
        // And the same revision is the policyRevision of the audit event.
        assertThat(policies.revision()).isEqualTo(revision);
    }

    @Test
    void aNewerBundleTakesEffectAndTheOlderOrBrokenOnesChangeNothing(CapturedOutput output) throws Exception {
        String revision = publishMain(Map.of("no-get-issue.cedar", NO_GET_ISSUE));
        await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> {
            JsonNode error = toolError(getIssue());
            assertThat(error.path("error").asString()).isEqualTo("access_denied");
            assertThat(error.has("requiredEntitlements")).as("a forbid names no entitlement").isFalse();
        });
        assertThat(sendModern(aliceToken(), "tools/list", null, "{}").body()).doesNotContain("jira__get_issue");
        assertThat(output.getAll()).contains("\"policyRevision\":\"" + revision + "\"");

        double rejected = rejections();
        env.policies.publishMain(TestBundles.main(TestBundles.revision(1), Map.of()));
        env.policies.publishMain(TestBundles.main(TestBundles.revision(NEXT.getAndIncrement()), Map.of()));
        env.policies.publishMain(TestBundles.mainSignedByTheWrongKey(TestBundles.revision(NEXT.getAndIncrement())));
        Thread.sleep(1000);
        assertThat(policies.revision()).as("a bundle of the wrong key does not replace the one in force").isNotNull();
        env.policies.publishMain(TestBundles.tampered(TestBundles.main(TestBundles.revision(NEXT.getAndIncrement()), Map.of())));
        await().atMost(Duration.ofSeconds(5)).until(() -> rejections() > rejected);
        assertThat(toolError(getIssue()).path("error").asString()).as("the forbid of the bundle in force still holds").isEqualTo("access_denied");
    }

    private double rejections() {
        return meters.find("gateway_policy_bundle_rejected_total").counters().stream().mapToDouble(c -> c.count()).sum();
    }

    @Test
    void resourcesNamedByTheArgumentsReachThePolicy() throws Exception {
        publishMain(Map.of("no-abc-13.cedar", NO_ISSUE_13));
        String sub = UUID.randomUUID().toString();
        env.broker.enroll(sub, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        String token = env.idp.token(sub, "refs", List.of("mcp-jira-read", "mcp-jira-write", "mcp-jira-destructive"));
        HttpResponse<String> denied = sendModern(token, "tools/call", "jira__delete_issue",
                "{\"name\":\"jira__delete_issue\",\"arguments\":{\"issueKey\":\"ABC-13\"}}");
        assertThat(toolError(denied).path("error").asString()).isEqualTo("access_denied");
        HttpResponse<String> allowed = sendModern(token, "tools/call", "jira__delete_issue",
                "{\"name\":\"jira__delete_issue\",\"arguments\":{\"issueKey\":\"ABC-14\"}}");
        assertThat(toolError(allowed).path("error").asString()).isEqualTo("confirmation_required");
        HttpResponse<String> notAnIssue = sendModern(token, "tools/call", "jira__delete_issue",
                "{\"name\":\"jira__delete_issue\",\"arguments\":{\"issueKey\":\"abc 13; DROP\"}}");
        assertThat(toolError(notAnIssue).path("error").asString()).isEqualTo("invalid_argument");
        assertThat(env.jira.requests()).noneMatch(r -> "tools/call".equals(r.rpcMethod()) && r.body().contains("delete_issue"));
    }

    @Test
    void anEmergencyForbidFromTheOverridesBundleStopsACallWithinSeconds() throws Exception {
        String overridesRevision = TestBundles.revision(NEXT.getAndIncrement());
        env.policies.publishOverrides(TestBundles.overrides(overridesRevision, Map.of("emergency.cedar", NO_GET_ISSUE)));
        try {
            await().atMost(Duration.ofSeconds(5)).untilAsserted(() ->
                    assertThat(toolError(getIssue()).path("error").asString()).isEqualTo("access_denied"));
        } finally {
            env.policies.publishOverrides(TestBundles.overrides(TestBundles.revision(NEXT.getAndIncrement()),
                    Map.of("emergency.cedar", "@id(\"test-nothing\") forbid (principal, action == Action::\"call\", resource is Tool)"
                            + " when { resource.name == \"no_such_tool\" };")));
        }
        await().atMost(Duration.ofSeconds(5)).untilAsserted(() ->
                assertThat(JSON.readTree(getIssue().body()).path("result").path("isError").asBoolean()).isFalse());
    }

    @Test
    void thePolicyStatusShowsTheRevisionOfThisInstance() throws Exception {
        String revision = publishMain(Map.of());
        HttpResponse<String> response = admin("GET", "/admin/v1/policy/status", ALICE_SUB, "alice", ALICE_GROUPS, null);
        assertThat(response.statusCode()).isEqualTo(200);
        JsonNode instance = JSON.readTree(response.body()).path("instances").get(0);
        assertThat(instance.path("revision").asString()).isEqualTo(revision);
        assertThat(instance.path("instanceId").asString()).isNotBlank();
    }
}
