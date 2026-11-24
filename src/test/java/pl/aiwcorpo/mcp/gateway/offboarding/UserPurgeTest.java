package pl.aiwcorpo.mcp.gateway.offboarding;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.Test;
import org.springframework.transaction.CannotCreateTransactionException;

import pl.aiwcorpo.mcp.gateway.agent.AgentAdmin;
import pl.aiwcorpo.mcp.gateway.audit.AuditLog;
import pl.aiwcorpo.mcp.gateway.broker.CredentialCache;
import pl.aiwcorpo.mcp.gateway.confirm.ConfirmationService;
import pl.aiwcorpo.mcp.gateway.mcp.ClientSessionStore;
import pl.aiwcorpo.mcp.gateway.stream.ToolStreams;
import pl.aiwcorpo.mcp.gateway.upstream.UpstreamSessions;

/** The purge of CC-155 completes its local cleanup and its summary event whatever the registry of agents does. */
class UserPurgeTest {

    @Test
    void aDatabaseThatCannotStartATransactionStillLetsThePurgeFinishItsCleanupAndReportItIncomplete() {
        CredentialCache credentials = mock(CredentialCache.class);
        UpstreamSessions upstream = mock(UpstreamSessions.class);
        ToolStreams streams = mock(ToolStreams.class);
        AgentAdmin agents = mock(AgentAdmin.class);
        AuditLog audit = mock(AuditLog.class);
        doThrow(new CannotCreateTransactionException("database down")).when(agents).suspendAgentsOf("rid", "owner-1");
        UserPurge purge = new UserPurge(mock(ConfirmationService.class), mock(ClientSessionStore.class), upstream, credentials, audit, "mcp-gateway",
                streams, agents);

        boolean complete = purge.purge("rid", "owner-1");

        assertThat(complete).isFalse();
        verify(credentials).invalidateUser("owner-1");
        verify(upstream).forgetUser("owner-1");
        verify(streams).closeUser("owner-1");
        verify(audit).emit(org.mockito.ArgumentMatchers.argThat(event -> "user_purged".equals(event.view().get("reason"))
                && "error".equals(event.view().get("outcome"))));
    }
}
