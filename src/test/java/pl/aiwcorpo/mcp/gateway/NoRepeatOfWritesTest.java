package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.http.HttpResponse;
import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import pl.aiwcorpo.mcp.testserver.Totp;

/**
 * A server that lost the session answers 404. A READ_ONLY call is sent again on a new session, an UPDATE call is not: the gateway never
 * repeats a call that may change something, the client decides (CC-204). An UPDATE call needs a confirmation, so each one here is
 * confirmed with a code of its own.
 */
class NoRepeatOfWritesTest extends GatewayTestBase {

    private static final String SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    /**
     * The broker accepts a code of the previous, the current and the next step, each step once and in order: starting one step back gives
     * three codes without waiting for the clock.
     */
    private long stepOffsetSeconds = -30;

    private String nextCode() {
        String code = Totp.currentCode(SECRET, System.currentTimeMillis() / 1000 + stepOffsetSeconds);
        stepOffsetSeconds += 30;
        return code;
    }

    @AfterEach
    void back() {
        env.jira.updateTool(false);
    }

    private HttpResponse<String> callAddComment(String token) throws Exception {
        HttpResponse<String> pending = sendModern(token, "/s/mcp-jira/mcp", "tools/call", "jira__add_comment",
                "{\"name\":\"jira__add_comment\",\"arguments\":{\"issueKey\":\"ABC-1\"}}");
        assertThat(toolError(pending).path("error").asString()).isEqualTo("confirmation_required");
        return sendModern(token, "/s/mcp-jira/mcp", "tools/call", "jira__add_comment",
                "{\"name\":\"jira__add_comment\",\"arguments\":{\"issueKey\":\"ABC-1\",\"confirmation_code\":\"" + nextCode() + "\"}}");
    }

    private long executed(String tool) {
        return env.jira.requests().stream().filter(r -> "tools/call".equals(r.rpcMethod()) && tool.equals(r.toolName()) && r.status() == 200).count();
    }

    @Test
    void anUpdateCallIsNotSentAgainWhenTheServerLostTheSession() throws Exception {
        env.jira.updateTool(true);
        String sub = UUID.randomUUID().toString();
        env.broker.enroll(sub, SECRET);
        String token = env.idp.token(sub, "writer", ALICE_GROUPS);
        assertThat(toolError(callAddComment(token)).has("error")).isFalse();
        assertThat(executed("add_comment")).isEqualTo(1);

        env.jira.dropSessions();
        HttpResponse<String> lost = callAddComment(token);

        assertThat(toolError(lost).path("error").asString()).isEqualTo("upstream_unavailable");
        assertThat(executed("add_comment")).as("not sent again").isEqualTo(1);
        assertThat(toolError(callAddComment(token)).has("error")).as("the next call starts a new session").isFalse();
        assertThat(executed("add_comment")).isEqualTo(2);
    }

    @Test
    void aReadIsSentAgainOnANewSession() throws Exception {
        String token = env.idp.token(UUID.randomUUID().toString(), "reader", ALICE_GROUPS);
        assertThat(toolError(callGetIssue(token)).has("error")).isFalse();

        env.jira.dropSessions();

        assertThat(toolError(callGetIssue(token)).has("error")).isFalse();
        assertThat(executed("get_issue")).isGreaterThanOrEqualTo(2);
    }
}
