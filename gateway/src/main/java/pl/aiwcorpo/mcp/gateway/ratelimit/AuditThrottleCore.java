package pl.aiwcorpo.mcp.gateway.ratelimit;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The rule that limits the audit of refusals a client can repeat at will (CC-190, CC-191), with the time given by the caller so that the
 * vectors of {@code endpoint-aggregate/audit-throttle-*} can be run on it. The key of an interval is (user, reason, target); a user and
 * reason keep at most {@code maxTargets} keys live and further targets share one key. The first refusal of a user and reason opens a
 * window of one interval; when it closes, a summary says how many refusals of the window were left out. Not thread-safe: the wrapper
 * synchronizes.
 *
 * @param <U> what the summary needs to write an event for the user (the first user of the window)
 */
final class AuditThrottleCore<U> {

    /** At most this many different suppressed targets are remembered per window; the count saturates there. */
    static final int MAX_REMEMBERED_TARGETS = 1000;
    private static final String OVERFLOW_TARGET = "*";

    record Summary<U>(long closedAtMillis, String sub, String reason, U user, int suppressedCount, int suppressedTargets) {
    }

    private static final class Window<U> {
        final long start;
        final U user;
        int suppressed;
        final Set<String> targets = new HashSet<>();

        Window(long start, U user) {
            this.start = start;
            this.user = user;
        }
    }

    private static final class Group<U> {
        final String sub;
        final String reason;
        final Map<String, Long> lastEmitted = new HashMap<>();
        Window<U> window;

        Group(String sub, String reason) {
            this.sub = sub;
            this.reason = reason;
        }
    }

    private final long intervalMillis;
    private final int maxTargets;
    private final Map<String, Group<U>> groups = new HashMap<>();

    AuditThrottleCore(long intervalMillis, int maxTargets) {
        this.intervalMillis = intervalMillis;
        this.maxTargets = maxTargets;
    }

    /** True when the event of this refusal is due; false when it is left out (the refusal itself is never affected). */
    boolean admit(long now, String sub, String reason, String target, U user) {
        Group<U> group = groups.computeIfAbsent(sub + "\n" + reason, k -> new Group<>(sub, reason));
        String key = target;
        if (!group.lastEmitted.containsKey(key) || now - group.lastEmitted.get(key) >= intervalMillis) {
            long live = group.lastEmitted.values().stream().filter(at -> now - at < intervalMillis).count();
            if (!group.lastEmitted.containsKey(key) && live >= maxTargets) {
                key = OVERFLOW_TARGET;
            }
        }
        Long at = group.lastEmitted.get(key);
        boolean emit = at == null || now - at >= intervalMillis;
        if (group.window == null) {
            group.window = new Window<>(now, user);
        }
        if (emit) {
            group.lastEmitted.put(key, now);
        } else {
            group.window.suppressed++;
            if (group.window.targets.size() < MAX_REMEMBERED_TARGETS) {
                group.window.targets.add(target);
            }
        }
        return emit;
    }

    /** Closes the windows that are due at {@code now}, forgets what no longer matters and returns the summaries, oldest first. */
    List<Summary<U>> closeDue(long now) {
        return close(now, false);
    }

    /** Closes every window as if it ended now (a controlled shutdown). */
    List<Summary<U>> flush(long now) {
        return close(now, true);
    }

    private List<Summary<U>> close(long now, boolean all) {
        List<Summary<U>> summaries = new ArrayList<>();
        for (Iterator<Group<U>> it = groups.values().iterator(); it.hasNext();) {
            Group<U> group = it.next();
            Window<U> window = group.window;
            if (window != null && (all || window.start + intervalMillis <= now)) {
                if (window.suppressed > 0) {
                    summaries.add(new Summary<>(all ? now : window.start + intervalMillis, group.sub, group.reason, window.user,
                            window.suppressed, window.targets.size()));
                }
                group.window = null;
            }
            group.lastEmitted.values().removeIf(at -> now - at >= intervalMillis);
            if (group.window == null && group.lastEmitted.isEmpty()) {
                it.remove();
            }
        }
        summaries.sort(java.util.Comparator.comparingLong(Summary::closedAtMillis));
        return summaries;
    }

    int groups() {
        return groups.size();
    }
}
