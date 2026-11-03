package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.Test;

import com.nimbusds.jwt.JWTClaimsSet;

import tools.jackson.databind.JsonNode;

/**
 * A token of the IdP with claims nobody reads (CC-201, the vectors of {@code idp-token-claims/}): the unknown claims, {@code vs} and
 * {@code vsc} among them, change nothing about the checks and never reach the internal JWT, which the gateway builds from the fields it
 * knows.
 */
class IdpTokenClaimsTest extends GatewayTestBase {

    private String tokenWith(Map<String, Object> extra) {
        JWTClaimsSet.Builder claims = env.idp.validClaims(UUID.randomUUID().toString(), "claims").claim("groups",
                List.of("mcp-jira-read", "mcp-jira-write", "mcp-jira-destructive"));
        extra.forEach(claims::claim);
        return env.idp.sign(claims.build());
    }

    @Test
    void aValidTokenWithVsAndVscIsAcceptedAndTheClaimsStayWhereTheyAre() throws Exception {
        String token = tokenWith(Map.of("vs", "team-a-dev", "vsc", Map.of("jiraProjects", List.of("ABC")), "something_else", 7));
        env.jira.clearRequests();

        HttpResponse<String> response = callGetIssue(token);

        assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
        assertThat(toolError(response).has("error")).isFalse();
        JsonNode internal = claims(lastToolCall(env.jira).header("authorization"));
        List<String> names = new ArrayList<>();
        internal.propertyNames().forEach(names::add);
        assertThat(names).doesNotContain("vs", "vsc", "something_else");
        assertThat(names).allMatch(n -> List.of("iss", "aud", "sub", "usr", "grp", "azp", "rid", "prv", "iat", "exp", "jti", "tool").contains(n));
    }

    @Test
    void theClaimsDoNotSaveATokenThatTheChecksRefuse() throws Exception {
        JWTClaimsSet expired = env.idp.validClaims(UUID.randomUUID().toString(), "claims")
                .issueTime(java.util.Date.from(java.time.Instant.now().minusSeconds(3600)))
                .expirationTime(java.util.Date.from(java.time.Instant.now().minusSeconds(600))).claim("vs", "team-a-dev").build();
        assertThat(send(env.idp.sign(expired), "/mcp", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}", Map.of()).statusCode())
                .isEqualTo(401);
        JWTClaimsSet withoutSub = new JWTClaimsSet.Builder(env.idp.validClaims("x", "claims").build()).subject(null).claim("vs", "x").build();
        assertThat(send(env.idp.sign(withoutSub), "/mcp", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}", Map.of()).statusCode())
                .isEqualTo(401);
    }
}
