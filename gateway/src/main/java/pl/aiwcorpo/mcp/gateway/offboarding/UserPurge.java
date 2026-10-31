package pl.aiwcorpo.mcp.gateway.offboarding;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;

import pl.aiwcorpo.mcp.gateway.audit.AuditEvent;
import pl.aiwcorpo.mcp.gateway.audit.AuditLog;
import pl.aiwcorpo.mcp.gateway.broker.CredentialCache;
import pl.aiwcorpo.mcp.gateway.confirm.ConfirmationService;
import pl.aiwcorpo.mcp.gateway.confirm.ConfirmationStore;
import pl.aiwcorpo.mcp.gateway.mcp.ClientSessionStore;
import pl.aiwcorpo.mcp.gateway.upstream.UpstreamSessions;

/**
 * Removes what the gateway keeps about a user who left (C5 purgeUser, CC-155): the pending confirmations and their
 * traces, the MCP sessions of the client and the credentials in the cache. The activity records stay until their retention ends
 * (CC-134). Idempotent: nothing to remove is no failure. The sub is not blocked afterwards; a token issued before keeps working
 * until it expires (at most 60 minutes), a window the decision of 2026-10-29 accepts.
 */
public final class UserPurge {

    private static final Logger log = LoggerFactory.getLogger(UserPurge.class);

    private final ConfirmationService confirmations;
    private final ClientSessionStore sessions;
    private final UpstreamSessions upstream;
    private final CredentialCache credentials;
    private final AuditLog audit;
    private final String componentId;

    public UserPurge(ConfirmationService confirmations, ClientSessionStore sessions, UpstreamSessions upstream,
                     CredentialCache credentials, AuditLog audit, String componentId) {
        this.confirmations = confirmations;
        this.sessions = sessions;
        this.upstream = upstream;
        this.credentials = credentials;
        this.audit = audit;
        this.componentId = componentId;
    }

    /**
     * @return true when everything is removed; false when Redis did not answer, so that nothing is guaranteed
     *         and the caller repeats the call. One summary event is written either way, also when there was nothing to remove.
     */
    public boolean purge(String requestId, String sub) {
        boolean complete = true;
        try {
            confirmations.purge(sub);
            sessions.deleteAllOf(sub);
        } catch (ConfirmationStore.StoreUnavailableException | DataAccessException e) {
            complete = false;
            log.error("purge rid={}: Redis state could not be removed: {}", requestId, e.getClass().getName());
        }
        credentials.invalidateUser(sub);
        upstream.forgetUser(sub);
        AuditEvent summary = AuditEvent.of("admin_change", requestId, componentId).sub(sub).reason("user_purged");
        audit.emit(complete ? summary.outcome("ok") : summary.outcome("error", "upstream_unavailable"));
        return complete;
    }
}
