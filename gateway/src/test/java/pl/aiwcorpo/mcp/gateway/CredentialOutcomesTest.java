package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.system.CapturedOutput;

import pl.aiwcorpo.mcp.gateway.broker.CredentialCache;
import pl.aiwcorpo.mcp.gateway.support.BrokerStub;
import pl.aiwcorpo.mcp.gateway.support.Contracts;
import tools.jackson.databind.JsonNode;

/** What the gateway does with the answers of the broker that CC-157 and CC-158 add: exchange_denied, system_not_configured, a token without an end. */
class CredentialOutcomesTest extends GatewayTestBase {

    private static final List<String> GROUPS = List.of("mcp-jira-read", "mcp-jira-write");

    @AfterEach
    void grantAgain() {
        env.broker.grant("alice-pat", 60);
    }

    private static List<JsonNode> events(CapturedOutput output, String sub, String event) {
        return output.getOut().lines().filter(l -> l.startsWith("{") && l.contains(sub) && l.contains("\"event\":\"" + event + "\""))
                .map(l -> JSON.readTree(l)).toList();
    }

    @Test
    void aRefusedExchangeIsAccessDeniedWithoutAGroupToRequestAndIsAudited(CapturedOutput output) throws Exception {
        String sub = UUID.randomUUID().toString();
        env.broker.mode(BrokerStub.Mode.EXCHANGE_DENIED);

        JsonNode error = toolError(callGetIssue(env.idp.token(sub, "denied", GROUPS)));

        assertThat(error.path("error").asString()).isEqualTo("access_denied");
        assertThat(error.has("requiredEntitlements")).as("nothing to request: the IdP decided").isFalse();
        assertThat(Contracts.schemaErrors("schemas/tool-error.schema.json", error)).isEmpty();
        JsonNode resolve = events(output, sub, "credential_resolve").getFirst();
        assertThat(resolve.path("reason").asString()).isEqualTo("exchange_denied");
        assertThat(resolve.path("outcome").asString()).isEqualTo("denied");
        assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", resolve)).isEmpty();
        JsonNode call = events(output, sub, "tool_call").getFirst();
        assertThat(call.path("decision").asString()).as("the gateway let it through, the IdP refused (CC-165)").isEqualTo("allow");
        assertThat(call.path("outcome").asString()).isEqualTo("denied");
        assertThat(call.path("reason").asString()).isEqualTo("exchange_denied");
        assertThat(call.path("errorCode").asString()).isEqualTo("access_denied");
        assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", call)).isEmpty();
        assertThat(env.jira.requests()).noneMatch(r -> "tools/call".equals(r.rpcMethod()));
        assertThat(credentialCache.get(new CredentialCache.Key(sub, "jira", List.of()))).isNull();
    }

    @Test
    void aSystemTheBrokerDoesNotKnowIsInternalErrorForTheClientAndAnotherCauseInTheLogAndTheAudit(CapturedOutput output) throws Exception {
        String sub = UUID.randomUUID().toString();
        env.broker.mode(BrokerStub.Mode.SYSTEM_NOT_CONFIGURED);

        JsonNode error = toolError(callGetIssue(env.idp.token(sub, "unconfigured", GROUPS)));

        assertThat(error.path("error").asString()).isEqualTo("internal_error");
        assertThat(error.toString()).doesNotContain("configured");
        assertThat(output.getOut()).contains("system_not_configured");
        JsonNode resolve = events(output, sub, "credential_resolve").getFirst();
        assertThat(resolve.path("reason").asString()).isEqualTo("system_not_configured");
        assertThat(resolve.path("outcome").asString()).isEqualTo("error");
        assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", resolve)).isEmpty();
        assertThat(env.jira.requests()).noneMatch(r -> "tools/call".equals(r.rpcMethod()));
    }

    @Test
    void anExchangedTokenWithoutAnEndIsNotUsedOrCached() throws Exception {
        String sub = UUID.randomUUID().toString();
        env.broker.mode(BrokerStub.Mode.EXCHANGED_WITHOUT_EXPIRY);

        JsonNode error = toolError(callGetIssue(env.idp.token(sub, "forever", GROUPS)));

        assertThat(error.path("error").asString()).isEqualTo("internal_error");
        assertThat(env.jira.requests()).noneMatch(r -> "tools/call".equals(r.rpcMethod()));
        assertThat(credentialCache.get(new CredentialCache.Key(sub, "jira", List.of()))).isNull();
    }

    @Test
    void aTypeFromTheBrokerOutsideTheSetOfTheSystemIsInternalErrorAndIsNeverUsedOrCached(CapturedOutput output) throws Exception {
        String sub = UUID.randomUUID().toString();
        env.broker.mode(BrokerStub.Mode.OTHER_TYPE);

        JsonNode error = toolError(callGetIssue(env.idp.token(sub, "other-type", GROUPS)));

        assertThat(error.path("error").asString()).isEqualTo("internal_error");
        JsonNode resolve = events(output, sub, "credential_resolve").getFirst();
        assertThat(resolve.path("reason").asString()).isEqualTo("credential_type_mismatch");
        assertThat(resolve.path("outcome").asString()).isEqualTo("error");
        assertThat(resolve.path("errorCode").asString()).isEqualTo("internal_error");
        assertThat(resolve.path("credentialType").asString()).as("the type the broker returned").isEqualTo("user-oauth");
        assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", resolve)).isEmpty();
        assertThat(env.jira.requests()).noneMatch(r -> "tools/call".equals(r.rpcMethod()));
        assertThat(credentialCache.get(new CredentialCache.Key(sub, "jira", List.of()))).isNull();
    }

    @Test
    void aTypeOutsideTheFourTypesOfTheContractIsNeverUsedOrCachedEither(CapturedOutput output) throws Exception {
        String sub = UUID.randomUUID().toString();
        env.broker.mode(BrokerStub.Mode.UNKNOWN_TYPE);

        JsonNode error = toolError(callGetIssue(env.idp.token(sub, "unknown-type", GROUPS)));

        assertThat(error.path("error").asString()).isEqualTo("internal_error");
        assertThat(env.jira.requests()).noneMatch(r -> "tools/call".equals(r.rpcMethod()));
        assertThat(credentialCache.get(new CredentialCache.Key(sub, "jira", List.of()))).isNull();
        assertThat(output.getAll()).doesNotContain("service-token");
        for (JsonNode event : events(output, sub, "credential_resolve")) {
            assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", event)).isEmpty();
        }
    }
}
