package pl.aiwcorpo.mcp.gateway.confirm;

import java.time.Clock;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pl.aiwcorpo.mcp.gateway.audit.AuditEvent;
import pl.aiwcorpo.mcp.gateway.audit.AuditLog;
import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.broker.AuthenticatorPort;
import pl.aiwcorpo.mcp.gateway.confirm.ConfirmationRules.FirstCallPlan;
import pl.aiwcorpo.mcp.gateway.confirm.ConfirmationRules.Operation;
import pl.aiwcorpo.mcp.gateway.confirm.ConfirmationRules.Verdict;
import pl.aiwcorpo.mcp.gateway.confirm.ConfirmationStore.StoreUnavailableException;
import pl.aiwcorpo.mcp.gateway.confirm.ConfirmationStore.Versioned;

/**
 * C11 for the gateway: a pending call per DESTRUCTIVE operation, the code checked by the broker, one pending DESTRUCTIVE
 * call per user, "first wins after the preview", the burn of codes. All state changes are compare-and-set on the user's
 * value; the broker is called between a read and its write, and a lost race repeats the step. Any trouble with the store
 * or the broker ends in "not confirmed" (upstream_unavailable), never in an execution.
 */
public final class ConfirmationService {

    private static final Logger log = LoggerFactory.getLogger(ConfirmationService.class);
    private static final int MAX_ATTEMPTS_OF_A_STEP = 12;

    /** Who calls and what for: everything an event and a record of the pending call need. */
    public record CallInfo(GatewayUser user, String requestId, String clientRequestId, String virtualServer,
                           String serverId, String toolName, Operation operation, PendingCall.Display display) {
    }

    public sealed interface FirstCallResult {
        record Pending(PendingCall call) implements FirstCallResult {
        }

        /** No usable authenticator (none or disabled): no pending call, the user registers first. */
        record Register(String reason) implements FirstCallResult {
        }

        record Blocked(long retryAfterSeconds) implements FirstCallResult {
        }

        record RateLimited(long retryAfterSeconds) implements FirstCallResult {
        }

        record Unavailable() implements FirstCallResult {
        }
    }

    public sealed interface RetryResult {
        /** The code was right: run the tool. {@code confirmationId} links the audit events of the call. */
        record Execute(String confirmationId) implements RetryResult {
        }

        record Failed() implements RetryResult {
        }

        record Superseded() implements RetryResult {
        }

        record Cancelled() implements RetryResult {
        }

        record RateLimited(long retryAfterSeconds) implements RetryResult {
        }

        record Register() implements RetryResult {
        }

        record Unavailable() implements RetryResult {
        }
    }

    public sealed interface CancelResult {
        record Cancelled() implements CancelResult {
        }

        record NotFound() implements CancelResult {
        }

        record Unavailable() implements CancelResult {
        }
    }

    private final ConfirmationStore store;
    private final AuthenticatorPort broker;
    private final AuditLog audit;
    private final String componentId;
    private final Clock clock;
    private final int pendingLimit;
    private final Supplier<String> ids;

    public ConfirmationService(ConfirmationStore store, AuthenticatorPort broker, AuditLog audit, String componentId, Clock clock,
                               int pendingLimit, Supplier<String> ids) {
        this.store = store;
        this.broker = broker;
        this.audit = audit;
        this.componentId = componentId;
        this.clock = clock;
        this.pendingLimit = pendingLimit;
        this.ids = ids;
    }

    // ---------------------------------------------------------------- first call

    public FirstCallResult firstCall(CallInfo info) {
        AuthenticatorPort.State registration = broker.state(info.user(), info.toolName(), info.requestId());
        switch (registration) {
            case UNAVAILABLE -> {
                unavailable(info, null);
                return new FirstCallResult.Unavailable();
            }
            case NONE -> {
                event(info, null, "deny", "authenticator_not_registered", "denied", "confirmation_required");
                return new FirstCallResult.Register("authenticator_not_registered");
            }
            case DISABLED -> {
                event(info, null, "deny", "authenticator_disabled", "denied", "confirmation_required");
                return new FirstCallResult.Register("authenticator_disabled");
            }
            default -> {
            }
        }
        String sub = info.user().sub();
        try {
            for (int attempt = 0; attempt < MAX_ATTEMPTS_OF_A_STEP; attempt++) {
                Versioned read = store.read(sub);
                long now = clock.millis();
                UserConfirmations state = ConfirmationRules.prune(read.state(), now);
                boolean unproven = info.operation().risk().equals("DESTRUCTIVE") && continuityUnproven(sub, now);
                FirstCallPlan plan = ConfirmationRules.planFirstCall(state, info.operation(), now, pendingLimit, unproven);
                switch (plan) {
                    case FirstCallPlan.Same same -> {
                        event(info, same.call(), "confirmation_pending", null, null, null);
                        return new FirstCallResult.Pending(same.call());
                    }
                    case FirstCallPlan.Blocked blocked -> {
                        event(info, null, "deny", "pending_exists", "denied", "confirmation_blocked");
                        return new FirstCallResult.Blocked(blocked.retryAfterSeconds());
                    }
                    case FirstCallPlan.RateLimited limited -> {
                        event(info, null, "deny", "rate_limited", "denied", "rate_limited");
                        return new FirstCallResult.RateLimited(limited.retryAfterSeconds());
                    }
                    case FirstCallPlan.Create create -> {
                        if (create.burnCodes() && !broker.invalidateCodes(info.user(), info.toolName(), info.requestId())) {
                            log.warn("confirmation rid={}: burning the codes failed, nothing created", info.requestId());
                            unavailable(info, null);
                            return new FirstCallResult.Unavailable();
                        }
                        PendingCall created = new PendingCall(ids.get(), info.serverId(), info.toolName(), info.operation().risk(),
                                info.operation().argsSha256(), now, ConfirmationRules.MAX_ATTEMPTS, null, null, false, null, null,
                                info.user().client(), info.virtualServer(), info.display());
                        UserConfirmations next = ConfirmationRules.applyCreate(state, created, create);
                        if (store.commit(sub, read, next, next.lastRelevantAt(ConfirmationRules.TTL_MILLIS,
                                ConfirmationRules.CODE_VALIDITY_MILLIS) + 1000)) {
                            if (unproven) {
                                store.markBurnedInEpoch(sub, store.epochStartedAt(now), 210_000);
                            }
                            for (String supersededId : create.supersededIds()) {
                                state.find(supersededId).ifPresent(old -> event(info.user(), info.requestId(), old, "deny",
                                        "superseded", "denied", "confirmation_superseded"));
                            }
                            event(info, created, "confirmation_pending", null, null, null);
                            return new FirstCallResult.Pending(created);
                        }
                    }
                }
            }
            log.error("confirmation rid={}: the state of the user kept changing", info.requestId());
            unavailable(info, null);
            return new FirstCallResult.Unavailable();
        } catch (StoreUnavailableException e) {
            log.error("confirmation rid={}: store unavailable: {}", info.requestId(), e.getMessage());
            unavailable(info, null);
            return new FirstCallResult.Unavailable();
        }
    }

    /**
     * The state of the store is proven continuous when its marker is older than the longest life of a code. Inside that
     * window the first DESTRUCTIVE call of a user burns the codes, because a code typed before the loss could confirm it.
     */
    private boolean continuityUnproven(String sub, long now) throws StoreUnavailableException {
        long epoch = store.epochStartedAt(now);
        if (now >= epoch + ConfirmationRules.TTL_MILLIS + ConfirmationRules.CODE_VALIDITY_MILLIS) {
            return false;
        }
        return !store.burnedInEpoch(sub, epoch);
    }

    // ---------------------------------------------------------------- retry with a code

    public RetryResult retry(CallInfo info, String code) {
        String sub = info.user().sub();
        PendingCall subject;
        try {
            Reserved reserved = reserveAttempt(info, sub);
            if (reserved.refusal() != null) {
                return reserved.refusal();
            }
            subject = reserved.call();
        } catch (StoreUnavailableException e) {
            log.error("confirmation rid={}: store unavailable: {}", info.requestId(), e.getMessage());
            unavailable(info, null);
            return new RetryResult.Unavailable();
        }
        AuthenticatorPort.Verdict answer = broker.verify(info.user(), info.toolName(), code, info.requestId());
        Verdict verdict = switch (answer.result()) {
            case "ok" -> Verdict.OK;
            case "invalid" -> Verdict.INVALID;
            case "replayed" -> Verdict.REPLAYED;
            case "burned" -> Verdict.BURNED;
            case "locked" -> Verdict.LOCKED;
            case "disabled" -> Verdict.DISABLED;
            case "not_registered" -> Verdict.NOT_REGISTERED;
            default -> Verdict.UNAVAILABLE;
        };
        try {
            for (int attempt = 0; attempt < MAX_ATTEMPTS_OF_A_STEP; attempt++) {
                Versioned read = store.read(sub);
                long now = clock.millis();
                ConfirmationRules.Settlement settlement = ConfirmationRules.settle(read.state(), subject.confirmationId(), verdict, now);
                if (settlement.next() != read.state() && !store.commit(sub, read, settlement.next(), keepUntil(settlement.next()))) {
                    continue;
                }
                return outcome(info, subject, settlement, answer.retryAfterSeconds());
            }
        } catch (StoreUnavailableException e) {
            log.error("confirmation rid={}: store unavailable while settling: {}", info.requestId(), e.getMessage());
        }
        // The code may have been right, but it cannot be written down: not confirmed.
        unavailable(info, subject);
        return new RetryResult.Unavailable();
    }

    private record Reserved(PendingCall call, RetryResult refusal) {
    }

    private Reserved reserveAttempt(CallInfo info, String sub) throws StoreUnavailableException {
        for (int attempt = 0; attempt < MAX_ATTEMPTS_OF_A_STEP; attempt++) {
            Versioned read = store.read(sub);
            long now = clock.millis();
            UserConfirmations state = ConfirmationRules.prune(read.state(), now);
            ConfirmationRules.Reservation reservation = ConfirmationRules.reserve(state, info.operation(), now);
            switch (reservation) {
                case ConfirmationRules.Reservation.Failed failed -> {
                    event(info, failed.call(), "deny", failed.auditReason(), "denied", "confirmation_failed");
                    return new Reserved(null, new RetryResult.Failed());
                }
                case ConfirmationRules.Reservation.Superseded superseded -> {
                    event(info, superseded.call(), "deny", "superseded", "denied", "confirmation_superseded");
                    return new Reserved(null, new RetryResult.Superseded());
                }
                case ConfirmationRules.Reservation.Cancelled cancelled -> {
                    event(info, cancelled.call(), "deny", "cancelled_by_owner", "denied", "confirmation_cancelled");
                    return new Reserved(null, new RetryResult.Cancelled());
                }
                case ConfirmationRules.Reservation.Reserved reserved -> {
                    if (store.commit(sub, read, reserved.next(), keepUntil(reserved.next()))) {
                        return new Reserved(reserved.call(), null);
                    }
                }
            }
        }
        throw new StoreUnavailableException("the state kept changing");
    }

    private RetryResult outcome(CallInfo info, PendingCall subject, ConfirmationRules.Settlement settlement, int retryAfter) {
        switch (settlement.outcome()) {
            case EXECUTE -> {
                event(info, subject, "allow", settlement.auditReason(), "ok", null);
                return new RetryResult.Execute(subject.confirmationId());
            }
            case FAILED -> {
                event(info, subject, "deny", settlement.auditReason(), "denied", "confirmation_failed");
                return new RetryResult.Failed();
            }
            case RATE_LIMITED -> {
                event(info, subject, "deny", settlement.auditReason(), "denied", "rate_limited");
                return new RetryResult.RateLimited(Math.max(1, retryAfter));
            }
            case REGISTER -> {
                event(info, subject, "deny", settlement.auditReason(), "denied", "confirmation_required");
                return new RetryResult.Register();
            }
            case CANCELLED -> {
                event(info, subject, "deny", "cancelled_by_owner", "denied", "confirmation_cancelled");
                return new RetryResult.Cancelled();
            }
            case SUPERSEDED -> {
                event(info, subject, "deny", "superseded", "denied", "confirmation_superseded");
                return new RetryResult.Superseded();
            }
            default -> {
                unavailable(info, subject);
                return new RetryResult.Unavailable();
            }
        }
    }

    /** Nothing was confirmed because the broker or the store did not answer: still an event, so the attempt is visible. */
    private void unavailable(CallInfo info, PendingCall subject) {
        event(info, subject, "deny", "upstream_unavailable", "error", "upstream_unavailable");
    }

    // ---------------------------------------------------------------- the owner (C5)

    /** What the preview shows, or empty for 404 (unknown, foreign, expired, replaced, executed, cancelled). */
    public Optional<PendingCall> view(String sub, String confirmationId) throws StoreUnavailableException {
        return ConfirmationRules.previewable(store.read(sub).state(), confirmationId, clock.millis());
    }

    /** Records the view; false for 404. The record and the check of a new DESTRUCTIVE call are atomic with each other. */
    public boolean markViewed(String sub, String confirmationId) throws StoreUnavailableException {
        for (int attempt = 0; attempt < MAX_ATTEMPTS_OF_A_STEP; attempt++) {
            Versioned read = store.read(sub);
            Optional<UserConfirmations> next = ConfirmationRules.markViewed(read.state(), confirmationId, clock.millis());
            if (next.isEmpty()) {
                return false;
            }
            if (next.get() == read.state() || store.commit(sub, read, next.get(), keepUntil(next.get()))) {
                return true;
            }
        }
        throw new StoreUnavailableException("the state kept changing");
    }

    public CancelResult cancel(GatewayUser owner, String requestId, String confirmationId) {
        String sub = owner.sub();
        try {
            for (int attempt = 0; attempt < MAX_ATTEMPTS_OF_A_STEP; attempt++) {
                Versioned read = store.read(sub);
                long now = clock.millis();
                Optional<ConfirmationRules.CancelPlan> plan = ConfirmationRules.planCancel(read.state(), confirmationId, now);
                if (plan.isEmpty()) {
                    return new CancelResult.NotFound();
                }
                PendingCall call = plan.get().call();
                if (plan.get().changesState() && !broker.invalidateCodes(owner, call.tool(), requestId)) {
                    return new CancelResult.Unavailable();
                }
                UserConfirmations next = ConfirmationRules.applyCancel(read.state(), confirmationId, now);
                if (!plan.get().changesState() || store.commit(sub, read, next, keepUntil(next))) {
                    event(owner, requestId, call, "deny", "cancelled_by_owner", "denied", "confirmation_cancelled");
                    return new CancelResult.Cancelled();
                }
            }
        } catch (StoreUnavailableException e) {
            log.error("cancel rid={}: store unavailable: {}", requestId, e.getMessage());
        }
        return new CancelResult.Unavailable();
    }

    // ---------------------------------------------------------------- audit

    private long keepUntil(UserConfirmations state) {
        return state.lastRelevantAt(ConfirmationRules.TTL_MILLIS, ConfirmationRules.CODE_VALIDITY_MILLIS) + 1000;
    }

    private void event(CallInfo info, PendingCall subject, String decision, String reason, String outcome, String errorCode) {
        PendingCall about = subject;
        AuditEvent event = AuditEvent.of("confirmation", info.requestId(), componentId)
                .clientRequestId(info.clientRequestId()).user(info.user()).virtualServer(info.virtualServer())
                .server(info.serverId()).tool(info.toolName()).risk(info.operation().risk())
                .resource(about != null && about.display() != null ? about.display().resource() : info.display().resource())
                .decision(decision, reason).callKey(about == null ? info.requestId() : about.confirmationId());
        if (outcome != null) {
            event.outcome(outcome, errorCode);
        }
        audit.emit(event);
    }

    private void event(GatewayUser owner, String requestId, PendingCall call, String decision, String reason, String outcome,
                       String errorCode) {
        AuditEvent event = AuditEvent.of("confirmation", requestId, componentId).userWithoutClient(owner)
                .client(call.client()).virtualServer(call.virtualServer()).server(call.serverId()).tool(call.tool())
                .risk(call.risk()).resource(call.display() == null ? null : call.display().resource())
                .decision(decision, reason).outcome(outcome, errorCode).callKey(call.confirmationId());
        audit.emit(event);
    }

    List<PendingCall> peek(String sub) throws StoreUnavailableException {
        return store.read(sub).state().calls();
    }
}
