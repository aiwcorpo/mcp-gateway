package pl.aiwcorpo.mcp.gateway.confirm;

import java.util.List;
import java.util.Optional;

/**
 * The rules of C11 as pure functions of the user's state and the time (the Java form of {@code scripts/lib/confirmation.mjs}
 * of mcp-contracts, which the vectors of {@code confirmation-binding/} are generated from). No I/O here: the broker
 * calls that the rules call for ({@code invalidate-codes}, {@code verify}) are made by {@link ConfirmationService}
 * between a read of the state and its compare-and-set.
 */
public final class ConfirmationRules {

    public static final long TTL_MILLIS = 120_000;
    /** A code stays valid up to 90 s (30 s step, window of one step each way). */
    public static final long CODE_VALIDITY_MILLIS = 90_000;
    public static final int MAX_ATTEMPTS = 3;

    private ConfirmationRules() {
    }

    /** The operation a call asks for: bound to (server, tool, SHA-256 of the canonical arguments without the code). */
    public record Operation(String serverId, String tool, String risk, String argsSha256) {
        boolean destructive() {
            return "DESTRUCTIVE".equals(risk);
        }
    }

    public sealed interface FirstCallPlan {
        /** The same operation is already pending: its record is returned, the TTL does not move. */
        record Same(PendingCall call) implements FirstCallPlan {
        }

        /** Another DESTRUCTIVE operation is pending with its preview open (CC-127). */
        record Blocked(long retryAfterSeconds) implements FirstCallPlan {
        }

        /** The limit of pending confirmations of another risk than DESTRUCTIVE. */
        record RateLimited(long retryAfterSeconds) implements FirstCallPlan {
        }

        /**
         * A new pending call. {@code burnCodes}: the broker must burn the current codes before it is created and the
         * burn must succeed (a code typed for a viewed A could confirm it).
         */
        record Create(List<String> supersededIds, boolean burnCodes) implements FirstCallPlan {
        }
    }

    /** A call that is waiting: not replaced, not ended, not cancelled and inside its TTL. */
    static boolean live(PendingCall call, long now) {
        return call.supersededBy() == null && call.ended() == null && call.cancelledAt() == null
                && now <= call.createdAt() + TTL_MILLIS;
    }

    /** Drops what no longer matters: a record is a trace until its TTL plus the validity of a code has passed. */
    public static UserConfirmations prune(UserConfirmations state, long now) {
        return state.without(call -> now > call.createdAt() + TTL_MILLIS + CODE_VALIDITY_MILLIS);
    }

    /**
     * What a first call (the call without a code) leads to. {@code burnAnyway} is set by the caller when it cannot
     * show that its state is continuous (a lost store): the burn is then needed for any new DESTRUCTIVE call.
     */
    public static FirstCallPlan planFirstCall(UserConfirmations state, Operation op, long now, int pendingLimit,
                                              boolean burnAnyway) {
        List<PendingCall> live = state.calls().stream().filter(c -> live(c, now)).toList();
        Optional<PendingCall> same = live.stream().filter(c -> c.sameOperation(op.serverId(), op.tool(), op.argsSha256())).findFirst();
        if (same.isPresent()) {
            return new FirstCallPlan.Same(same.get());
        }
        if (op.destructive()) {
            // First wins after the preview: the owner opened the preview of a DESTRUCTIVE call A, so a different
            // DESTRUCTIVE operation B is refused until A is confirmed or the block ends at max(A.expiresAt, view + 90 s),
            // also when A ran out of attempts or expired earlier.
            long blockedUntil = 0;
            for (PendingCall c : state.calls()) {
                if (c.destructive() && c.previewViewedAt() != null && !PendingCall.CONFIRMED.equals(c.ended())
                        && !PendingCall.CANCELLED.equals(c.ended()) && c.cancelledAt() == null && c.supersededBy() == null
                        && !c.sameOperation(op.serverId(), op.tool(), op.argsSha256())) {
                    long until = Math.max(c.createdAt() + TTL_MILLIS, c.previewViewedAt() + CODE_VALIDITY_MILLIS);
                    if (now <= until) {
                        blockedUntil = Math.max(blockedUntil, until);
                    }
                }
            }
            if (blockedUntil > 0) {
                return new FirstCallPlan.Blocked(Math.max(1, ceilSeconds(blockedUntil - now)));
            }
            // The block has ended, but a code typed for a viewed, unconfirmed A can still be valid (up to 90 s after A
            // expired), and after a confirmed A a second code typed "for A" could confirm the repeated operation. So the
            // codes are burned first. The same operation is exempt only while A was not executed; a cancel burned already.
            boolean toBurn = state.calls().stream().anyMatch(c -> c.destructive() && c.previewViewedAt() != null
                    && !PendingCall.CANCELLED.equals(c.ended()) && c.cancelledAt() == null && c.supersededBy() == null
                    && !c.burned()
                    && !(!PendingCall.CONFIRMED.equals(c.ended()) && c.sameOperation(op.serverId(), op.tool(), op.argsSha256()))
                    && now <= c.createdAt() + TTL_MILLIS + CODE_VALIDITY_MILLIS);
            List<String> superseded = live.stream().filter(PendingCall::destructive).map(PendingCall::confirmationId).toList();
            return new FirstCallPlan.Create(superseded, toBurn || burnAnyway);
        }
        List<PendingCall> others = live.stream().filter(c -> !c.destructive()).toList();
        if (others.size() >= pendingLimit) {
            long oldestEnds = others.stream().mapToLong(c -> c.createdAt() + TTL_MILLIS).min().orElse(now);
            return new FirstCallPlan.RateLimited(Math.max(1, ceilSeconds(oldestEnds - now)));
        }
        return new FirstCallPlan.Create(List.of(), false);
    }

    /** The state after a pending call is created (and the older DESTRUCTIVE ones are replaced, and the burn is recorded). */
    public static UserConfirmations applyCreate(UserConfirmations state, PendingCall created, FirstCallPlan.Create plan) {
        UserConfirmations next = state.map(c -> {
            PendingCall changed = c;
            if (plan.supersededIds().contains(c.confirmationId())) {
                changed = changed.withSupersededBy(created.confirmationId());
            }
            if (plan.burnCodes() && c.previewViewedAt() != null) {
                changed = changed.withBurned();
            }
            return changed;
        });
        // A new pending call for an operation replaces the trace of a replaced one under the same key.
        next = next.without(c -> c.supersededBy() != null && !c.supersededBy().equals(created.confirmationId())
                && c.sameOperation(created.serverId(), created.tool(), created.argsSha256()));
        return next.with(created);
    }

    public sealed interface Reservation {
        /** Nothing pending for this call (or it cannot be confirmed): confirmation_failed without asking the broker. */
        record Failed(String auditReason, PendingCall call) implements Reservation {
        }

        record Superseded(PendingCall call) implements Reservation {
        }

        record Cancelled(PendingCall call) implements Reservation {
        }

        /** An attempt is reserved (the counter is already lower); the broker may be asked. */
        record Reserved(PendingCall call, UserConfirmations next) implements Reservation {
        }
    }

    /** First half of a retry with a code: find the pending call of the operation and reserve one attempt. */
    public static Reservation reserve(UserConfirmations state, Operation op, long now) {
        Optional<PendingCall> found = state.findOperation(op.serverId(), op.tool(), op.argsSha256());
        if (found.isEmpty()) {
            return new Reservation.Failed(null, null);
        }
        PendingCall call = found.get();
        if (now > call.createdAt() + TTL_MILLIS) {
            return new Reservation.Failed("confirmation_expired", call);
        }
        if (call.supersededBy() != null) {
            return new Reservation.Superseded(call);
        }
        if (call.cancelledAt() != null) {
            return new Reservation.Cancelled(call);
        }
        if (PendingCall.CONFIRMED.equals(call.ended())) {
            return new Reservation.Failed(null, call);
        }
        if (call.attemptsLeft() <= 0 || PendingCall.EXHAUSTED.equals(call.ended())) {
            return new Reservation.Failed("attempts_exhausted", call);
        }
        PendingCall reserved = call.withAttemptsLeft(call.attemptsLeft() - 1);
        return new Reservation.Reserved(reserved, state.replace(call.confirmationId(), c -> reserved));
    }

    /** What the broker said about the code (C4 {@code verifyAuthenticatorCode}); {@code UNAVAILABLE} for any failure. */
    public enum Verdict { OK, INVALID, REPLAYED, BURNED, LOCKED, DISABLED, NOT_REGISTERED, UNAVAILABLE }

    public enum Outcome { EXECUTE, FAILED, RATE_LIMITED, REGISTER, UNAVAILABLE, CANCELLED, SUPERSEDED }

    /** Result of {@link #settle}: the outcome, the audit reason (may be null) and the new state. */
    public record Settlement(Outcome outcome, String auditReason, UserConfirmations next) {
    }

    /**
     * Second half of a retry: apply the broker's answer to the record. A right code consumes the record with a
     * compare-and-delete, so it executes once; a cancel or a replacement that came in while the broker was asked wins.
     */
    public static Settlement settle(UserConfirmations state, String confirmationId, Verdict verdict, long now) {
        Optional<PendingCall> found = state.find(confirmationId);
        if (found.isEmpty()) {
            return new Settlement(Outcome.FAILED, null, state);
        }
        PendingCall call = found.get();
        if (call.cancelledAt() != null) {
            return new Settlement(Outcome.CANCELLED, "cancelled_by_owner", state);
        }
        if (call.supersededBy() != null) {
            return new Settlement(Outcome.SUPERSEDED, "superseded", state);
        }
        boolean waiting = call.ended() == null;
        switch (verdict) {
            case OK -> {
                // A right code whose attempt was reserved in time counts even when other attempts used up the counter while the
                // broker was asked: the number of questions to the broker is bounded by the three reservations anyway.
                if (call.ended() != null && !PendingCall.EXHAUSTED.equals(call.ended())) {
                    return new Settlement(Outcome.FAILED, null, state);
                }
                if (now > call.createdAt() + TTL_MILLIS) {
                    return new Settlement(Outcome.FAILED, "confirmation_expired", state);
                }
                String reason = call.previewViewedAt() != null ? "user_confirmed" : "user_confirmed_no_preview";
                return new Settlement(Outcome.EXECUTE, reason, state.replace(confirmationId, c -> c.withEnded(PendingCall.CONFIRMED)));
            }
            case INVALID, REPLAYED -> {
                if (waiting && call.attemptsLeft() <= 0) {
                    return new Settlement(Outcome.FAILED, "attempts_exhausted",
                            state.replace(confirmationId, c -> c.withEnded(PendingCall.EXHAUSTED)));
                }
                return new Settlement(Outcome.FAILED, null, state);
            }
            case BURNED -> {
                return new Settlement(Outcome.FAILED, "code_burned", giveBack(state, call));
            }
            case LOCKED -> {
                return new Settlement(Outcome.RATE_LIMITED, "rate_limited", giveBack(state, call));
            }
            case DISABLED -> {
                return new Settlement(Outcome.REGISTER, "authenticator_disabled", giveBack(state, call));
            }
            case NOT_REGISTERED -> {
                return new Settlement(Outcome.REGISTER, "authenticator_not_registered", giveBack(state, call));
            }
            default -> {
                return new Settlement(Outcome.UNAVAILABLE, null, giveBack(state, call));
            }
        }
    }

    /** The reservation of an attempt returns when the broker did not judge the code (locked, burned, down...). */
    private static UserConfirmations giveBack(UserConfirmations state, PendingCall call) {
        if (call.ended() != null) {
            return state;
        }
        return state.replace(call.confirmationId(), c -> c.withAttemptsLeft(Math.min(MAX_ATTEMPTS, c.attemptsLeft() + 1)));
    }

    /** A call that the owner may still see, mark as viewed or be shown: waiting, or out of attempts but viewed before. */
    public static Optional<PendingCall> previewable(UserConfirmations state, String confirmationId, long now) {
        return state.find(confirmationId).filter(c -> c.supersededBy() == null && now <= c.createdAt() + TTL_MILLIS
                && !PendingCall.CONFIRMED.equals(c.ended()) && !PendingCall.CANCELLED.equals(c.ended()) && c.cancelledAt() == null
                && (c.ended() == null || c.previewViewedAt() != null));
    }

    /** Records the view of the preview; the first view stays. Empty when the call cannot be viewed (404). */
    public static Optional<UserConfirmations> markViewed(UserConfirmations state, String confirmationId, long now) {
        return previewable(state, confirmationId, now).map(call -> call.previewViewedAt() != null ? state
                : state.replace(confirmationId, c -> c.withPreviewViewedAt(now)));
    }

    public record CancelPlan(PendingCall call, boolean changesState) {
    }

    /** The call the owner may cancel: until its expiry, not replaced, not executed. */
    public static Optional<CancelPlan> planCancel(UserConfirmations state, String confirmationId, long now) {
        return state.find(confirmationId)
                .filter(c -> c.supersededBy() == null && now <= c.createdAt() + TTL_MILLIS && !PendingCall.CONFIRMED.equals(c.ended()))
                .map(c -> new CancelPlan(c, !PendingCall.CANCELLED.equals(c.ended())));
    }

    public static UserConfirmations applyCancel(UserConfirmations state, String confirmationId, long now) {
        return state.replace(confirmationId, c -> PendingCall.CANCELLED.equals(c.ended()) ? c : c.withCancelled(now));
    }

    private static long ceilSeconds(long millis) {
        return (millis + 999) / 1000;
    }
}
