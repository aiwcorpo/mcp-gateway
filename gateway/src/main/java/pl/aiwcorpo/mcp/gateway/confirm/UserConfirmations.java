package pl.aiwcorpo.mcp.gateway.confirm;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.UnaryOperator;

/**
 * Everything the gateway keeps about the confirmations of one user. It is one value: every change is a pure function
 * of the previous value and is stored with a compare-and-set, so "create B and supersede A", "record the view" and
 * "reserve an attempt" are atomic per user without a lock (C11, normative atomicity).
 */
public record UserConfirmations(List<PendingCall> calls) {

    public static final UserConfirmations EMPTY = new UserConfirmations(List.of());

    public UserConfirmations {
        calls = List.copyOf(calls);
    }

    public Optional<PendingCall> find(String confirmationId) {
        return calls.stream().filter(c -> c.confirmationId().equals(confirmationId)).findFirst();
    }

    /** The newest record of an operation (server, tool, arguments): the one a retry with a code binds to. */
    public Optional<PendingCall> findOperation(String serverId, String tool, String argsSha256) {
        return calls.stream().filter(c -> c.sameOperation(serverId, tool, argsSha256))
                .max(java.util.Comparator.comparingLong(PendingCall::createdAt));
    }

    public UserConfirmations replace(String confirmationId, UnaryOperator<PendingCall> change) {
        List<PendingCall> next = new ArrayList<>(calls.size());
        for (PendingCall call : calls) {
            next.add(call.confirmationId().equals(confirmationId) ? change.apply(call) : call);
        }
        return new UserConfirmations(next);
    }

    public UserConfirmations map(UnaryOperator<PendingCall> change) {
        return new UserConfirmations(calls.stream().map(change).toList());
    }

    public UserConfirmations with(PendingCall added) {
        List<PendingCall> next = new ArrayList<>(calls);
        next.add(added);
        return new UserConfirmations(next);
    }

    public UserConfirmations without(java.util.function.Predicate<PendingCall> removed) {
        return new UserConfirmations(calls.stream().filter(c -> !removed.test(c)).toList());
    }

    /** Latest moment any record still matters: the end of the longest trace. */
    public long lastRelevantAt(long ttlMillis, long codeValidityMillis) {
        return calls.stream().mapToLong(c -> c.createdAt() + ttlMillis + codeValidityMillis).max().orElse(0);
    }
}
