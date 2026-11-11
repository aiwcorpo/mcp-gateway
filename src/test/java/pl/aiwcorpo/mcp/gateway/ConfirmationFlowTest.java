package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.system.CapturedOutput;

import io.lettuce.core.RedisClient;
import pl.aiwcorpo.mcp.gateway.broker.CredentialCache;
import io.lettuce.core.RedisURI;
import io.lettuce.core.api.StatefulRedisConnection;
import pl.aiwcorpo.mcp.gateway.support.Contracts;
import pl.aiwcorpo.mcp.gateway.support.GatewayTestEnvironment;
import pl.aiwcorpo.mcp.testserver.Totp;
import tools.jackson.databind.JsonNode;

/**
 * C11 end to end: IdP token, gateway, Redis (real), the broker stand-in with the TOTP rules, the test MCP server. The
 * state machine itself is covered by the vectors; this is the wiring, the atomicity on Redis and the fail-closed cases.
 */
class ConfirmationFlowTest extends GatewayTestBase {

    private static final String SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    private static final List<String> GROUPS = List.of("mcp-jira-read", "mcp-jira-write", "mcp-jira-destructive");

    /**
     * The gateway treats a store without a continuity marker (a fresh Redis, a flush) as lost state and burns the codes of a
     * user at the first DESTRUCTIVE call for 210 s. The tests that are not about that start from a proven store.
     */
    @org.junit.jupiter.api.BeforeEach
    void provenStore() {
        redis(commands -> commands.set("gw:conf:epoch", Long.toString(System.currentTimeMillis() - 3_600_000L)));
    }

    private record Person(String sub, String username) {
        Person() {
            this(UUID.randomUUID().toString(), "u" + UUID.randomUUID().toString().substring(0, 8));
        }
    }

    private String token(Person p) {
        return env.idp.token(p.sub(), p.username(), GROUPS);
    }

    private Person enrolled() {
        Person p = new Person();
        env.broker.enroll(p.sub(), SECRET);
        return p;
    }

    private static String code() {
        return Totp.currentCode(SECRET, System.currentTimeMillis() / 1000);
    }

    private HttpResponse<String> delete(Person p, String key, String code) throws Exception {
        return deleteWith(p, "{\"issueKey\":\"" + key + "\"" + (code == null ? "" : ",\"confirmation_code\":\"" + code + "\"") + "}");
    }

    private HttpResponse<String> deleteWith(Person p, String arguments) throws Exception {
        return sendModern(token(p), "tools/call", "jira__delete_issue",
                "{\"name\":\"jira__delete_issue\",\"arguments\":" + arguments + "}");
    }

    private static JsonNode error(HttpResponse<String> response) {
        JsonNode error = toolError(response);
        if (error.isEmpty()) {
            return error;
        }
        assertThat(Contracts.schemaErrors("schemas/tool-error.schema.json", error)).as(error.toString()).isEmpty();
        return error;
    }

    private long deletesAtTheServer() {
        return env.jira.requests().stream().filter(r -> "tools/call".equals(r.rpcMethod())).count();
    }

    private HttpResponse<String> adminAs(Person p, String method, String path) throws Exception {
        return admin(method, path, p.sub(), p.username(), GROUPS, null);
    }

    @Test
    void firstCallCreatesAPendingCallAndTheRightCodeRunsTheToolOnce(CapturedOutput output) throws Exception {
        Person p = enrolled();
        long resolves = resolveCount();
        HttpResponse<String> first = delete(p, "ABC-1", null);
        JsonNode pending = error(first);
        assertThat(pending.path("error").asString()).isEqualTo("confirmation_required");
        assertThat(pending.path("confirmationId").asString()).startsWith("cnf_");
        assertThat(pending.path("previewUrl").asString()).isEqualTo(GatewayTestEnvironment.PUBLIC_URL + "/confirm/"
                + pending.path("confirmationId").asString());
        assertThat(pending.path("description").asString()).startsWith("jira__delete_issue (jira): issueKey=\"ABC-1\"");
        assertThat(deletesAtTheServer()).isZero();
        assertThat(resolveCount()).as("the account is checked before the confirmation gate (CC-178); the credential is not used")
                .isEqualTo(resolves + 1);
        assertThat(JSON.readTree(first.body()).path("result").path("isError").asBoolean()).isTrue();

        // The same first call again returns the same record (no new pending call, the TTL does not move).
        assertThat(error(delete(p, "ABC-1", null)).path("confirmationId").asString())
                .isEqualTo(pending.path("confirmationId").asString());

        JsonNode wrong = error(delete(p, "ABC-1", "000000"));
        assertThat(wrong.path("error").asString()).isEqualTo("confirmation_failed");
        assertThat(deletesAtTheServer()).isZero();

        String good = code();
        HttpResponse<String> done = delete(p, "ABC-1", good);
        JsonNode result = JSON.readTree(done.body()).path("result");
        assertThat(result.path("isError").asBoolean()).as(done.body()).isFalse();
        assertThat(result.path("content").get(0).path("text").asString()).contains("ABC-1");
        assertThat(deletesAtTheServer()).isEqualTo(1);

        // Once: the same call with the same code finds nothing pending.
        assertThat(error(delete(p, "ABC-1", good)).path("error").asString()).isEqualTo("confirmation_failed");
        assertThat(deletesAtTheServer()).isEqualTo(1);

        // A used step cannot confirm the next operation either.
        assertThat(error(delete(p, "ABC-2", null)).path("error").asString()).isEqualTo("confirmation_required");
        assertThat(error(delete(p, "ABC-2", good)).path("error").asString()).isEqualTo("confirmation_failed");

        assertThat(output.getAll()).as("a code must never be logged").doesNotContain("\"" + good + "\"").doesNotContain("confirmation_code\":\"" + good);
    }

    @Test
    void theServerNeverSeesTheCode() throws Exception {
        Person p = enrolled();
        delete(p, "ABC-3", null);
        HttpResponse<String> done = delete(p, "ABC-3", code());
        assertThat(JSON.readTree(done.body()).path("result").path("isError").asBoolean()).as(done.body()).isFalse();
        assertThat(lastToolCall(env.jira).body()).doesNotContain("confirmation_code");
    }

    @Test
    void toolsListOffersTheCodeFieldForDestructiveToolsOnly() throws Exception {
        Person p = enrolled();
        HttpResponse<String> list = sendModern(token(p), "tools/list", null, "{}");
        JsonNode tools = JSON.readTree(list.body()).path("result").path("tools");
        boolean seen = false;
        for (JsonNode tool : tools) {
            boolean hasCode = tool.path("inputSchema").path("properties").has("confirmation_code");
            if ("jira__delete_issue".equals(tool.path("name").asString())) {
                seen = true;
                assertThat(hasCode).isTrue();
                assertThat(tool.path("inputSchema").path("properties").path("confirmation_code").path("pattern").asString())
                        .isEqualTo("^[0-9]{6}$");
            } else {
                assertThat(hasCode).as(tool.path("name").asString()).isFalse();
            }
        }
        assertThat(seen).isTrue();
    }

    @Test
    void aMalformedCodeIsAnArgumentErrorAndCostsNothing() throws Exception {
        Person p = enrolled();
        delete(p, "ABC-4", null);
        long verifies = env.broker.count("/v1/authenticator/verify");
        for (String bad : List.of("12345", "1234567", "12345a", " 12345", "")) {
            assertThat(error(delete(p, "ABC-4", bad)).path("error").asString()).as(bad).isEqualTo("invalid_argument");
        }
        assertThat(env.broker.count("/v1/authenticator/verify")).isEqualTo(verifies);
    }

    @Test
    void aCallWithMoreArgumentsThanThePreviewListsIsRefusedAndNeverRuns() throws Exception {
        Person p = enrolled();
        StringBuilder arguments = new StringBuilder("{\"issueKey\":\"ABC-70\"");
        for (int i = 0; i < 50; i++) {
            arguments.append(",\"a").append(String.format("%02d", i)).append("\":0");
        }
        JsonNode first = error(deleteWith(p, arguments + "}"));
        assertThat(first.path("error").asString()).isEqualTo("invalid_argument");
        assertThat(first.has("confirmationId")).isFalse();
        JsonNode retry = error(deleteWith(p, arguments + ",\"confirmation_code\":\"" + code() + "\"}"));
        assertThat(retry.path("error").asString()).isEqualTo("invalid_argument");
        assertThat(deletesAtTheServer()).isZero();
    }

    @Test
    void anIntegerThatADoubleCannotHoldExactlyIsRefusedAndNeverRuns() throws Exception {
        Person p = enrolled();
        JsonNode first = error(deleteWith(p, "{\"issueKey\":\"ABC-60\",\"n\":9007199254740993}"));
        assertThat(first.path("error").asString()).isEqualTo("invalid_argument");
        assertThat(first.has("confirmationId")).isFalse();
        JsonNode retry = error(deleteWith(p, "{\"issueKey\":\"ABC-60\",\"n\":9007199254740992,\"confirmation_code\":\"" + code() + "\"}"));
        assertThat(retry.path("error").asString()).isEqualTo("invalid_argument");
        assertThat(deletesAtTheServer()).isZero();
    }

    @Test
    void withoutAnAuthenticatorThereIsOnlyARegisterUrl() throws Exception {
        Person p = new Person();
        JsonNode error = error(delete(p, "ABC-5", null));
        assertThat(error.path("error").asString()).isEqualTo("confirmation_required");
        assertThat(error.path("registerUrl").asString()).isEqualTo(GatewayTestEnvironment.PUBLIC_URL + "/authenticator");
        assertThat(error.has("confirmationId")).isFalse();
        assertThat(deletesAtTheServer()).isZero();
    }

    @Test
    void anUnavailableBrokerNeverMeansConfirmed() throws Exception {
        Person p = enrolled();
        env.broker.authenticatorDown(true);
        try {
            assertThat(error(delete(p, "ABC-6", null)).path("error").asString()).isEqualTo("upstream_unavailable");
        } finally {
            env.broker.authenticatorDown(false);
        }
        delete(p, "ABC-6", null);
        env.broker.authenticatorDown(true);
        try {
            assertThat(error(delete(p, "ABC-6", code())).path("error").asString()).isEqualTo("upstream_unavailable");
        } finally {
            env.broker.authenticatorDown(false);
        }
        assertThat(deletesAtTheServer()).isZero();
    }

    @Test
    void anUnavailableBrokerLeavesAnEventOfTheAttempt(CapturedOutput output) throws Exception {
        Person p = enrolled();
        env.broker.authenticatorDown(true);
        try {
            HttpResponse<String> response = delete(p, "ABC-40", null);
            String rid = response.headers().firstValue("X-Request-Id").orElseThrow();
            List<JsonNode> events = auditEvents(output, rid).stream().filter(e -> "confirmation".equals(e.path("event").asString())).toList();
            assertThat(events).hasSize(1);
            assertThat(events.getFirst().path("reason").asString()).isEqualTo("upstream_unavailable");
            assertThat(events.getFirst().path("outcome").asString()).isEqualTo("error");
            assertThat(events.getFirst().path("errorCode").asString()).isEqualTo("upstream_unavailable");
            assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", events.getFirst())).isEmpty();
        } finally {
            env.broker.authenticatorDown(false);
        }
    }

    @Test
    void aUserWithoutTheDestructiveGroupIsRefusedBeforeAnyPendingCall() throws Exception {
        Person p = new Person();
        env.broker.enroll(p.sub(), SECRET);
        HttpResponse<String> response = sendModern(env.idp.token(p.sub(), p.username(), List.of("mcp-jira-read", "mcp-jira-write")),
                "tools/call", "jira__delete_issue", "{\"name\":\"jira__delete_issue\",\"arguments\":{\"issueKey\":\"ABC-7\"}}");
        JsonNode error = error(response);
        assertThat(error.path("error").asString()).isEqualTo("not_found_or_denied");
        assertThat(env.broker.received().stream().filter(r -> r.path().startsWith("/v1/authenticator"))).isEmpty();
    }

    @Test
    void theOwnerSeesThePreviewOthersGetA404AndTheViewBlocksAnotherOperation() throws Exception {
        Person p = enrolled();
        Person stranger = enrolled();
        String id = error(delete(p, "ABC-8", null)).path("confirmationId").asString();

        HttpResponse<String> view = adminAs(p, "GET", "/admin/v1/confirmations/" + id);
        assertThat(view.statusCode()).as(view.body()).isEqualTo(200);
        assertThat(view.headers().firstValue("Cache-Control").orElse("")).contains("no-store");
        JsonNode body = JSON.readTree(view.body());
        assertThat(Contracts.gatewayAdminErrors("ConfirmationView", body)).isEmpty();
        assertThat(body.path("tool").asString()).isEqualTo("jira__delete_issue");
        assertThat(body.path("system").asString()).isEqualTo("jira");
        assertThat(body.path("resource").path("id").asString()).isEqualTo("ABC-8");
        assertThat(body.path("resource").has("parent")).as("no system knowledge in the gateway: the parent is not derived from the id").isFalse();
        assertThat(body.path("arguments").get(0).path("name").asString()).isEqualTo("issueKey");

        for (String method : List.of("GET", "POST")) {
            String path = "/admin/v1/confirmations/" + id + ("GET".equals(method) ? "" : "/viewed");
            assertThat(adminAs(stranger, method, path).statusCode()).as(method + " by someone else").isEqualTo(404);
        }
        assertThat(adminAs(p, "POST", "/admin/v1/confirmations/" + id + "/viewed").statusCode()).isEqualTo(204);
        assertThat(adminAs(p, "POST", "/admin/v1/confirmations/" + id + "/viewed").statusCode()).as("idempotent").isEqualTo(204);

        JsonNode blocked = error(delete(p, "ABC-9", null));
        assertThat(blocked.path("error").asString()).isEqualTo("confirmation_blocked");
        assertThat(blocked.path("retryAfterSeconds").asInt()).isBetween(1, 120);
        // The viewed call is still there and still confirmable.
        assertThat(adminAs(p, "GET", "/admin/v1/confirmations/" + id).statusCode()).isEqualTo(200);
        assertThat(JSON.readTree(delete(p, "ABC-8", code()).body()).path("result").path("isError").asBoolean()).isFalse();
    }

    @Test
    void withoutAViewANewDestructiveOperationReplacesTheOlderOne() throws Exception {
        Person p = enrolled();
        String a = error(delete(p, "ABC-10", null)).path("confirmationId").asString();
        String b = error(delete(p, "ABC-11", null)).path("confirmationId").asString();
        assertThat(a).isNotEqualTo(b);
        assertThat(adminAs(p, "GET", "/admin/v1/confirmations/" + a).statusCode()).isEqualTo(404);
        assertThat(error(delete(p, "ABC-10", code())).path("error").asString()).isEqualTo("confirmation_superseded");
        assertThat(deletesAtTheServer()).isZero();
        assertThat(JSON.readTree(delete(p, "ABC-11", code()).body()).path("result").path("isError").asBoolean()).isFalse();
    }

    @Test
    void cancellingBurnsTheCodesAndTheRetryIsCancelled(CapturedOutput output) throws Exception {
        Person p = enrolled();
        String id = error(delete(p, "ABC-12", null)).path("confirmationId").asString();
        String held = code();
        long burns = env.broker.count("/v1/authenticator/invalidate-codes");
        HttpResponse<String> cancel = adminAs(p, "POST", "/admin/v1/confirmations/" + id + "/cancel");
        assertThat(cancel.statusCode()).isEqualTo(204);
        assertThat(env.broker.count("/v1/authenticator/invalidate-codes")).isEqualTo(burns + 1);
        assertThat(adminAs(p, "POST", "/admin/v1/confirmations/" + id + "/cancel").statusCode()).as("idempotent").isEqualTo(204);
        assertThat(env.broker.count("/v1/authenticator/invalidate-codes")).as("only the first cancel burns").isEqualTo(burns + 1);

        assertThat(error(delete(p, "ABC-12", held)).path("error").asString()).isEqualTo("confirmation_cancelled");
        // The held code is of a burned step: it confirms nothing new either, and it is not a wrong code.
        assertThat(error(delete(p, "ABC-13", null)).path("error").asString()).isEqualTo("confirmation_required");
        JsonNode burned = error(delete(p, "ABC-13", held));
        assertThat(burned.path("error").asString()).isEqualTo("confirmation_failed");
        assertThat(deletesAtTheServer()).isZero();
        assertThat(output.getAll()).contains("cancelled_by_owner").contains("code_burned");
    }

    @Test
    void cancelOfSomeoneElsesOrUnknownCallIs404AndABrokerFailureIs503() throws Exception {
        Person p = enrolled();
        Person stranger = enrolled();
        String id = error(delete(p, "ABC-14", null)).path("confirmationId").asString();
        assertThat(adminAs(stranger, "POST", "/admin/v1/confirmations/" + id + "/cancel").statusCode()).isEqualTo(404);
        assertThat(adminAs(p, "POST", "/admin/v1/confirmations/cnf_doesNotExist00000/cancel").statusCode()).isEqualTo(404);
        env.broker.authenticatorDown(true);
        try {
            assertThat(adminAs(p, "POST", "/admin/v1/confirmations/" + id + "/cancel").statusCode()).isEqualTo(503);
        } finally {
            env.broker.authenticatorDown(false);
        }
        // Nothing was cancelled.
        assertThat(adminAs(p, "GET", "/admin/v1/confirmations/" + id).statusCode()).isEqualTo(200);
    }

    @Test
    void parallelWrongCodesReachTheBrokerAtMostOncePerAttempt() throws Exception {
        Person p = enrolled();
        delete(p, "ABC-15", null);
        long before = env.broker.count("/v1/authenticator/verify");
        ExecutorService pool = Executors.newFixedThreadPool(12);
        try {
            List<Future<HttpResponse<String>>> futures = new ArrayList<>();
            for (int i = 0; i < 12; i++) {
                futures.add(pool.submit(() -> delete(p, "ABC-15", "000000")));
            }
            for (Future<HttpResponse<String>> f : futures) {
                assertThat(error(f.get()).path("error").asString()).isEqualTo("confirmation_failed");
            }
        } finally {
            pool.shutdownNow();
        }
        assertThat(env.broker.count("/v1/authenticator/verify") - before).as("three attempts, no more questions to the broker")
                .isEqualTo(3);
        assertThat(deletesAtTheServer()).isZero();
    }

    @Test
    void parallelRightCodesExecuteOnce() throws Exception {
        Person p = enrolled();
        delete(p, "ABC-16", null);
        String good = code();
        ExecutorService pool = Executors.newFixedThreadPool(6);
        int executed = 0;
        try {
            List<Future<HttpResponse<String>>> futures = new ArrayList<>();
            for (int i = 0; i < 6; i++) {
                futures.add(pool.submit(() -> delete(p, "ABC-16", good)));
            }
            for (Future<HttpResponse<String>> f : futures) {
                if (!JSON.readTree(f.get().body()).path("result").path("isError").asBoolean()) {
                    executed++;
                }
            }
        } finally {
            pool.shutdownNow();
        }
        assertThat(executed).isEqualTo(1);
        assertThat(deletesAtTheServer()).isEqualTo(1);
    }

    @Test
    void parallelFirstCallsOfDifferentOperationsLeaveOnePending() throws Exception {
        Person p = enrolled();
        ExecutorService pool = Executors.newFixedThreadPool(6);
        try {
            List<Future<HttpResponse<String>>> futures = new ArrayList<>();
            for (int i = 0; i < 6; i++) {
                String key = "ABC-" + (20 + i);
                futures.add(pool.submit(() -> delete(p, key, null)));
            }
            for (Future<HttpResponse<String>> f : futures) {
                f.get();
            }
        } finally {
            pool.shutdownNow();
        }
        // Every operation except the one that won the race has been replaced.
        long superseded = 0;
        for (int i = 0; i < 6; i++) {
            if ("confirmation_superseded".equals(error(delete(p, "ABC-" + (20 + i), "111111")).path("error").asString())) {
                superseded++;
            }
        }
        assertThat(superseded).as("five of six were replaced").isEqualTo(5);
    }

    @Test
    void lostStateIsNeverConfirmedAndTheFirstCallAfterItBurnsTheCodes() throws Exception {
        Person p = enrolled();
        delete(p, "ABC-30", null);
        flushRedis();
        long burns = env.broker.count("/v1/authenticator/invalidate-codes");
        assertThat(error(delete(p, "ABC-30", code())).path("error").asString()).isEqualTo("confirmation_failed");
        assertThat(deletesAtTheServer()).isZero();
        // The epoch marker is gone too: the next DESTRUCTIVE call burns the codes before it creates a pending call.
        assertThat(error(delete(p, "ABC-31", null)).path("error").asString()).isEqualTo("confirmation_required");
        assertThat(env.broker.count("/v1/authenticator/invalidate-codes")).isGreaterThan(burns);
    }

    @Test
    void aFailedBurnAfterLostStateCreatesNothing() throws Exception {
        Person p = enrolled();
        flushRedis();
        env.broker.invalidateFails(true);
        try {
            assertThat(error(delete(p, "ABC-32", null)).path("error").asString()).isEqualTo("upstream_unavailable");
        } finally {
            env.broker.invalidateFails(false);
        }
        assertThat(adminAs(p, "GET", "/admin/v1/confirmations/cnf_anythingatall00000").statusCode()).isEqualTo(404);
        assertThat(error(delete(p, "ABC-32", null)).path("error").asString()).isEqualTo("confirmation_required");
    }

    private void flushRedis() {
        redis(commands -> {
            for (String key : commands.keys("gw:conf:*")) {
                commands.del(key);
            }
        });
    }

    private void redis(java.util.function.Consumer<io.lettuce.core.api.sync.RedisCommands<String, String>> action) {
        RedisClient client = RedisClient.create(RedisURI.builder().withHost(env.redis.getHost())
                .withPort(env.redis.getMappedPort(6379))
                .withAuthentication("admin", GatewayTestEnvironment.REDIS_ADMIN_PASSWORD.toCharArray()).build());
        try (StatefulRedisConnection<String, String> connection = client.connect()) {
            action.accept(connection.sync());
        } finally {
            client.shutdown();
        }
    }

    @Test
    void theCredentialOfACallWithoutACodeIsNeverCachedAndTheCallWithTheCodeResolvesUnderItsOwnRequestId() throws Exception {
        Person p = enrolled();
        credentialCache.clear();
        long before = resolveCount();
        CredentialCache.Key key = new CredentialCache.Key(p.sub(), "jira", List.of());

        HttpResponse<String> first = delete(p, "ABC-31", null);
        assertThat(error(first).path("error").asString()).isEqualTo("confirmation_required");
        assertThat(delete(p, "ABC-31", null).statusCode()).isEqualTo(200);
        assertThat(resolveCount()).as("each call without a code asks the broker, as CC-178 orders the account check first").isEqualTo(before + 2);
        assertThat(credentialCache.get(key)).as("nothing stored for a call that does not use the credential").isNull();

        HttpResponse<String> confirmed = delete(p, "ABC-31", code());
        assertThat(error(confirmed).has("error")).as(confirmed.body()).isFalse();
        String confirmedId = confirmed.headers().firstValue("X-Request-Id").orElseThrow();
        assertThat(env.broker.received()).as("the call with the code has its own credential_resolve")
                .anyMatch(r -> r.path().equals("/v1/credentials/resolve") && confirmedId.equals(r.requestId()));
        assertThat(credentialCache.get(key)).as("a call that used the credential may cache it").isNotNull();
    }
}
