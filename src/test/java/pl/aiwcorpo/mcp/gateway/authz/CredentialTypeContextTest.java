package pl.aiwcorpo.mcp.gateway.authz;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import pl.aiwcorpo.mcp.cedar.entities.Caller;
import pl.aiwcorpo.mcp.cedar.entities.ResourceTypes;
import pl.aiwcorpo.mcp.cedar.entities.ScopeMapping;
import pl.aiwcorpo.mcp.cedar.entities.ToolDescriptor;
import pl.aiwcorpo.mcp.gateway.support.Snapshots;
import tools.jackson.databind.json.JsonMapper;

/** The type of the credential reaches the Cedar context of every decision, from the settings of the server (CC-136). */
class CredentialTypeContextTest {

    private static final String NO_SERVICE_ACCOUNT = "@id(\"override-no-service-account\") forbid (principal, action == Action::\"call\", "
            + "resource is Tool) when { context has credentialType && context.credentialType == \"service-account\" };";

    private static final CedarToolAuthorizer AUTHORIZER = new CedarToolAuthorizer(Snapshots.source(Snapshots.of(1, ResourceTypes.empty(),
            ScopeMapping.empty(), Map.of("no-service-account.cedar", NO_SERVICE_ACCOUNT), List.of("claude-code"))), JsonMapper.builder().build());

    private static boolean allowed(String credentialType) {
        ToolDescriptor tool = new ToolDescriptor("mcp-jira", "jira", "search_issues", "READ_ONLY", "read", List.of());
        Caller caller = Caller.of("6f1c2a9e-4d4b-4c51-9a53-1e0f0c7d2b11", "alice", List.of("mcp-jira-read"), "claude-code");
        return AUTHORIZER.evaluate(caller, tool, Map.of(), List.of(), credentialType).decision().allowed();
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
