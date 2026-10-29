package pl.aiwcorpo.mcp.gateway.authz;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import pl.aiwcorpo.mcp.cedar.entities.Caller;
import pl.aiwcorpo.mcp.cedar.entities.ToolDescriptor;
import pl.aiwcorpo.mcp.gateway.config.GatewayProperties;
import pl.aiwcorpo.mcp.gateway.policy.BundleFetcher;
import pl.aiwcorpo.mcp.gateway.policy.PolicyService;
import pl.aiwcorpo.mcp.gateway.support.PolicyServer;
import pl.aiwcorpo.mcp.gateway.support.TestBundles;
import tools.jackson.databind.json.JsonMapper;

/** The type of the credential reaches the Cedar context of every decision, from the configuration of the system (CC-136). */
class CredentialTypeContextTest {

    private static final String NO_SERVICE_ACCOUNT = "@id(\"no-service-account\") forbid (principal, action, resource is Tool) "
            + "when { context has credentialType && context.credentialType == \"service-account\" };";

    private static PolicyServer server;
    private static PolicyService policies;
    private static CedarToolAuthorizer authorizer;

    @BeforeAll
    static void load() throws Exception {
        server = new PolicyServer();
        server.publishMain(TestBundles.main(TestBundles.revision(1), Map.of("no-service-account.cedar", NO_SERVICE_ACCOUNT)));
        Path keys = Files.createTempDirectory("policy-keys");
        Files.writeString(keys.resolve("main.pem"), TestBundles.publicKeyPem("test-policy-bundle"));
        policies = new PolicyService(new GatewayProperties.Policy(URI.create(server.mainUrl()), null, "test-policy-bundle",
                keys.resolve("main.pem").toString(), null, null, true, null, null, null, Duration.ofMinutes(1),
                Duration.ofMinutes(1), Duration.ofSeconds(10), Duration.ofSeconds(1)), new BundleFetcher(), new SimpleMeterRegistry(), true)
                .start();
        authorizer = new CedarToolAuthorizer(policies, JsonMapper.builder().build());
    }

    @AfterAll
    static void stop() {
        policies.destroy();
        server.close();
    }

    private static boolean allowed(String credentialType) {
        ToolDescriptor tool = new ToolDescriptor("mcp-jira", "jira", "search_issues", "READ_ONLY", "read", List.of());
        Caller caller = Caller.of("6f1c2a9e-4d4b-4c51-9a53-1e0f0c7d2b11", "alice", List.of("mcp-jira-read"), "claude-code");
        return authorizer.evaluate(caller, tool, Map.of(), List.of(), credentialType).decision().allowed();
    }

    @Test
    void thePolicyDecidesOnTheTypeTheGatewayGives() {
        assertThat(allowed("user-secret")).isTrue();
        assertThat(allowed("token-exchange")).isTrue();
        assertThat(allowed("service-account")).as("the rule that forbids the service account sees it").isFalse();
    }

    @Test
    void aSystemWithoutACredentialGivesNoTypeAndTheRuleDoesNotApply() {
        assertThat(allowed(null)).isTrue();
    }
}
