package pl.aiwcorpo.mcp.gateway.confirm;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;

class ConfirmationStateSizeTest {

    @Test
    void anAgentLoopingOverNewOperationsLeavesAtMostTwentyReplacedTraces() {
        UserConfirmations state = UserConfirmations.EMPTY;
        long now = 1_000_000;
        for (int i = 0; i < 300; i++) {
            ConfirmationRules.Operation operation = new ConfirmationRules.Operation("mcp-jira", "delete_issue", "DESTRUCTIVE", "sha256:" + i);
            ConfirmationRules.FirstCallPlan plan = ConfirmationRules.planFirstCall(state, operation, now + i, 3, false);
            PendingCall created = new PendingCall("cnf_" + i, "mcp-jira", "delete_issue", "DESTRUCTIVE", "sha256:" + i, now + i, 3, null,
                    null, false, null, null, "claude-code", null,
                    new PendingCall.Display("jira__delete_issue", "jira", null, List.of(), "x"));
            state = ConfirmationRules.applyCreate(state, created, (ConfirmationRules.FirstCallPlan.Create) plan);
        }
        assertThat(state.calls().size()).isLessThanOrEqualTo(ConfirmationRules.MAX_REPLACED_TRACES + 1);
        assertThat(state.calls().stream().filter(c -> c.supersededBy() == null)).extracting(PendingCall::confirmationId)
                .containsExactly("cnf_299");
    }

    @Test
    void stateWrittenByTheFourPointXGatewayIsReadAndKeepsItsOperation() {
        // The record of M4 had "virtualServer" where it now has "filter"; both instances of a rolling update read what the other wrote.
        String old = "{\"calls\":[{\"confirmationId\":\"cnf_old\",\"serverId\":\"mcp-jira\",\"tool\":\"delete_issue\","
                + "\"risk\":\"DESTRUCTIVE\",\"argsSha256\":\"sha256:1\",\"createdAt\":1000,\"attemptsLeft\":3,\"previewViewedAt\":null,"
                + "\"ended\":null,\"burned\":false,\"supersededBy\":null,\"cancelledAt\":null,\"client\":\"claude-code\","
                + "\"virtualServer\":\"team-a\",\"display\":{\"qualifiedTool\":\"jira__delete_issue\",\"system\":\"jira\","
                + "\"resource\":null,\"arguments\":[],\"description\":\"x\"}}]}";
        UserConfirmations read = tools.jackson.databind.json.JsonMapper.builder().build().readValue(old, UserConfirmations.class);
        assertThat(read.find("cnf_old")).isPresent();
        assertThat(read.find("cnf_old").orElseThrow().filter()).isNull();
        assertThat(read.find("cnf_old").orElseThrow().sameOperation("mcp-jira", "delete_issue", "sha256:1")).isTrue();
    }
}
