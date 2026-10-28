package pl.aiwcorpo.mcp.gateway.confirm;

/**
 * Durable state of the confirmations (C11, invariant 6): one value per user, changed only by compare-and-set. An
 * unreachable store is {@link StoreUnavailableException}; callers answer upstream_unavailable and never "confirmed".
 */
public interface ConfirmationStore {

    /** The state as read, with the raw form that {@link #commit} compares against. */
    record Versioned(UserConfirmations state, String raw) {
    }

    Versioned read(String sub) throws StoreUnavailableException;

    /** Writes {@code next} if the stored value is still {@code expected}; false when someone else changed it. */
    boolean commit(String sub, Versioned expected, UserConfirmations next, long keepUntilEpochMillis) throws StoreUnavailableException;

    /**
     * Start of the current epoch of the state: the moment the store was found without its continuity marker. A marker
     * that is missing (first start, lost or flushed data) is written now, so the answer says "continuity cannot be shown
     * since this moment" (README, loss of the state).
     */
    long epochStartedAt(long nowEpochMillis) throws StoreUnavailableException;

    /** Whether the codes of this user were burned since the epoch began. */
    boolean burnedInEpoch(String sub, long epoch) throws StoreUnavailableException;

    void markBurnedInEpoch(String sub, long epoch, long ttlMillis) throws StoreUnavailableException;

    class StoreUnavailableException extends Exception {
        public StoreUnavailableException(Throwable cause) {
            super(cause.getClass().getSimpleName());
        }

        public StoreUnavailableException(String message) {
            super(message);
        }
    }
}
