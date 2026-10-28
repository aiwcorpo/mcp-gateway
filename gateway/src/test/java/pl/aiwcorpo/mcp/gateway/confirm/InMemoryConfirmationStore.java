package pl.aiwcorpo.mcp.gateway.confirm;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/** The store of the vector tests: the same compare-and-set contract as Redis, in memory. */
final class InMemoryConfirmationStore implements ConfirmationStore {

    private record Entry(UserConfirmations state, long version) {
    }

    private final Map<String, Entry> states = new HashMap<>();
    private final Set<String> burned = new HashSet<>();
    private long versions;
    private long epoch;
    private boolean down;

    InMemoryConfirmationStore(long epoch) {
        this.epoch = epoch;
    }

    synchronized void put(String sub, UserConfirmations state) {
        states.put(sub, new Entry(state, ++versions));
    }

    synchronized UserConfirmations get(String sub) {
        Entry entry = states.get(sub);
        return entry == null ? UserConfirmations.EMPTY : entry.state();
    }

    synchronized void down(boolean value) {
        this.down = value;
    }

    private void check() throws StoreUnavailableException {
        if (down) {
            throw new StoreUnavailableException("down");
        }
    }

    @Override
    public synchronized Versioned read(String sub) throws StoreUnavailableException {
        check();
        Entry entry = states.get(sub);
        return entry == null ? new Versioned(UserConfirmations.EMPTY, null)
                : new Versioned(entry.state(), Long.toString(entry.version()));
    }

    @Override
    public synchronized boolean commit(String sub, Versioned expected, UserConfirmations next, long keepUntil)
            throws StoreUnavailableException {
        check();
        Entry entry = states.get(sub);
        String raw = entry == null ? null : Long.toString(entry.version());
        if (!java.util.Objects.equals(raw, expected.raw())) {
            return false;
        }
        put(sub, next);
        return true;
    }

    @Override
    public synchronized long epochStartedAt(long now) throws StoreUnavailableException {
        check();
        return epoch;
    }

    @Override
    public synchronized boolean burnedInEpoch(String sub, long epoch) throws StoreUnavailableException {
        check();
        return burned.contains(epoch + ":" + sub);
    }

    @Override
    public synchronized void markBurnedInEpoch(String sub, long epoch, long ttlMillis) throws StoreUnavailableException {
        check();
        burned.add(epoch + ":" + sub);
    }
}
