package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.http.HttpResponse;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.system.CapturedOutput;

import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisURI;
import io.lettuce.core.api.StatefulRedisConnection;
import pl.aiwcorpo.mcp.gateway.broker.CredentialCache;
import pl.aiwcorpo.mcp.gateway.redis.KeyHash;
import pl.aiwcorpo.mcp.gateway.support.Contracts;
import pl.aiwcorpo.mcp.gateway.support.GatewayTestEnvironment;
import tools.jackson.databind.JsonNode;

/** POST /admin/v1/users/{sub}/purge (CC-155): what the gateway forgets of a user who left, what it keeps, and who may ask. */
class OffboardingTest extends GatewayTestBase {

    private static final String SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    private static final List<String> GROUPS = List.of("mcp-jira-read", "mcp-jira-write", "mcp-jira-destructive");

    @BeforeEach
    void provenStore() {
        redis(commands -> commands.set("gw:conf:epoch", Long.toString(System.currentTimeMillis() - 3_600_000L)));
    }

    private static String purgePath(String sub) {
        return "/admin/v1/users/" + sub + "/purge";
    }

    private HttpResponse<String> purge(String sub) throws Exception {
        return admin(env.offboardingTls, "POST", purgePath(sub), null, null);
    }

    private <T> T redis(java.util.function.Function<io.lettuce.core.api.sync.RedisCommands<String, String>, T> work) {
        RedisClient client = RedisClient.create(RedisURI.builder().withHost(env.redis.getHost()).withPort(env.redis.getMappedPort(6379))
                .withAuthentication("admin", GatewayTestEnvironment.REDIS_ADMIN_PASSWORD.toCharArray()).build());
        try (StatefulRedisConnection<String, String> connection = client.connect()) {
            return work.apply(connection.sync());
        } finally {
            client.shutdown();
        }
    }

    private long exists(String key) {
        return redis(c -> c.exists(key));
    }

    private static List<JsonNode> summaries(CapturedOutput output, String sub) {
        return output.getOut().lines().filter(l -> l.startsWith("{") && l.contains("\"event\":\"admin_change\"") && l.contains(sub))
                .map(l -> JSON.readTree(l)).toList();
    }

    @Test
    void aUserWhoLeftLosesSessionsPendingConfirmationsAndCachedCredentials(CapturedOutput output) throws Exception {
        String sub = UUID.randomUUID().toString();
        String token = env.idp.token(sub, "leaver", GROUPS);
        env.broker.enroll(sub, SECRET);
        String session = initialize(token, "2025-11-25");
        assertThat(callGetIssue(token).statusCode()).isEqualTo(200);
        CredentialCache.Key cached = new CredentialCache.Key(sub, "jira", List.of());
        assertThat(credentialCache.get(cached)).as("the credential is cached").isNotNull();
        assertThat(JSON.readTree(sendModern(token, "tools/call", "jira__delete_issue",
                "{\"name\":\"jira__delete_issue\",\"arguments\":{\"issueKey\":\"ABC-9\"}}").body()).path("result").path("content").get(0)
                .path("text").asString()).contains("confirmation_required");
        String stateKey = "gw:conf:u:" + KeyHash.of(sub);
        assertThat(exists(stateKey)).as("a pending confirmation").isEqualTo(1L);
        long activityBefore = jdbc.sql("SELECT count(*) FROM activity_events WHERE sub = ?").param(sub).query(Long.class).single();
        assertThat(activityBefore).isPositive();

        HttpResponse<String> response = purge(sub);

        assertThat(response.statusCode()).isEqualTo(204);
        assertThat(response.body()).isEmpty();
        assertThat(sendRpc(token, session, "2025-11-25", "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/list\"}", java.util.Map.of())
                .statusCode()).as("the MCP session").isEqualTo(404);
        assertThat(exists(stateKey)).as("the pending confirmation and its traces").isZero();
        assertThat(credentialCache.get(cached)).as("the cached credential").isNull();
        assertThat(jdbc.sql("SELECT count(*) FROM activity_events WHERE sub = ?").param(sub).query(Long.class).single())
                .as("the activity stays until its retention ends").isEqualTo(activityBefore);

        List<JsonNode> events = summaries(output, sub);
        JsonNode summary = events.stream().filter(e -> "user_purged".equals(e.path("reason").asString())).findFirst().orElseThrow();
        assertThat(summary.path("outcome").asString()).isEqualTo("ok");
        assertThat(summary.path("sub").asString()).isEqualTo(sub);
        assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", summary)).isEmpty();
    }

    @Test
    void aPurgeOfNobodyAnswers204AndStillLeavesOneSummaryEvent(CapturedOutput output) throws Exception {
        String sub = UUID.randomUUID().toString();

        assertThat(purge(sub).statusCode()).isEqualTo(204);
        assertThat(purge(sub).statusCode()).as("idempotent").isEqualTo(204);

        assertThat(summaries(output, sub)).hasSize(2).allSatisfy(e -> {
            assertThat(e.path("reason").asString()).isEqualTo("user_purged");
            assertThat(e.path("outcome").asString()).isEqualTo("ok");
        });
    }

    @Test
    void aPurgeDoesNotTouchAnotherUser() throws Exception {
        String leaver = UUID.randomUUID().toString();
        String stays = UUID.randomUUID().toString();
        String token = env.idp.token(stays, "stays", GROUPS);
        String session = initialize(token, "2025-11-25");

        assertThat(purge(leaver).statusCode()).isEqualTo(204);

        assertThat(sendRpc(token, session, "2025-11-25", "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/list\"}", java.util.Map.of())
                .statusCode()).isEqualTo(200);
    }

    @Test
    void onlyTheOffboardingProcessMayPurgeAndWithoutAToken() throws Exception {
        String sub = UUID.randomUUID().toString();
        String bffToken = env.idp.token(sub, "x", List.of(), "mcp-gateway-admin", "mcp-portal-bff");
        assertThat(admin(env.bffTls, "POST", purgePath(sub), bffToken, null).statusCode()).as("the BFF").isEqualTo(403);
        assertThat(admin(env.otherComponentTls, "POST", purgePath(sub), null, null).statusCode()).as("another component").isEqualTo(403);
        assertThat(admin(env.noClientCertificateTls, "POST", purgePath(sub), null, null).statusCode()).as("no certificate").isEqualTo(401);
        assertThat(admin(env.foreignCaTls, "POST", purgePath(sub), null, null).statusCode()).as("a foreign CA").isEqualTo(401);
        assertThat(admin(env.offboardingTls, "GET", purgePath(sub), null, null).statusCode()).as("not a GET").isNotEqualTo(204);
        assertThat(admin(env.offboardingTls, "POST", purgePath(sub) + "/more", null, null).statusCode()).isEqualTo(403);
        assertThat(admin(env.offboardingTls, "POST", "/admin/v1/users/" + "x".repeat(256) + "/purge", null, null).statusCode()).isEqualTo(400);
        assertThat(admin(env.offboardingTls, "POST", "/admin/v1/catalog", null, "{}").statusCode()).as("the certificate opens nothing else").isEqualTo(403);
    }
}
