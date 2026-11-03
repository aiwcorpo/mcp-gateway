package pl.aiwcorpo.mcp.gateway.stream;

import java.util.ArrayList;
import java.util.List;

import pl.aiwcorpo.mcp.manifest.EndpointFilter;

/**
 * When a stream tells its client that the list of tools changed (CC-176, CC-192, CC-207; the Java form of {@code listChangedSequence} of
 * mcp-contracts, whose vectors it passes). A snapshot is the list of the user before the filter of the address; it is compared with the
 * snapshot before it, after the filter, by name, risk and hash of the definition. At most one notification per window: a change inside
 * the window of the last one waits for its end and is sent once for all changes so far, even when the list went back meanwhile. The
 * notification is empty. Time is given by the caller, so that the vectors run without waiting.
 */
public final class ListChangeTracker {

    /** One tool of the list of a user; {@code hash} is null for a tool of the static configuration. */
    public record Tool(String name, String risk, String hash) {
    }

    private final EndpointFilter filter;
    private final long windowMillis;
    private List<String> previous;
    private long lastSent = Long.MIN_VALUE;
    private boolean pending;

    /** @param opened the list of the user when the stream was opened: the reference of the first comparison */
    public ListChangeTracker(EndpointFilter filter, List<Tool> opened, long windowMillis) {
        this.filter = filter;
        this.windowMillis = windowMillis;
        this.previous = entries(opened);
    }

    /**
     * A new snapshot at {@code now}. Returns the times at which a notification is to be sent: the one that was waiting for the end of a
     * window, if that end has come, and the one for this snapshot, if it is due at once. Empty when nothing is to be sent.
     */
    public List<Long> observe(long now, List<Tool> tools) {
        List<Long> sends = new ArrayList<>(advance(now));
        List<String> next = entries(tools);
        boolean differs = !next.equals(previous);
        previous = next;
        if (!differs) {
            return sends;
        }
        if (lastSent == Long.MIN_VALUE || now - lastSent >= windowMillis) {
            lastSent = now;
            pending = false;
            sends.add(now);
        } else {
            pending = true;
        }
        return sends;
    }

    /** The notification that waited for the end of its window, if that end is at or before {@code now}. */
    public List<Long> advance(long now) {
        if (pending && lastSent + windowMillis <= now) {
            lastSent += windowMillis;
            pending = false;
            return List.of(lastSent);
        }
        return List.of();
    }

    /** When a waiting notification is due, or {@code Long.MAX_VALUE} when none waits. */
    public long nextDueAt() {
        return pending ? lastSent + windowMillis : Long.MAX_VALUE;
    }

    private List<String> entries(List<Tool> tools) {
        List<String> out = new ArrayList<>();
        for (Tool tool : tools) {
            if (filter.allows(tool.name(), tool.risk())) {
                out.add(tool.name() + " " + tool.risk() + " " + (tool.hash() == null ? "" : tool.hash()));
            }
        }
        return out;
    }
}
