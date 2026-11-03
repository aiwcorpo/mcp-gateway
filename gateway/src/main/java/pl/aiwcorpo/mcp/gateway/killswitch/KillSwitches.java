package pl.aiwcorpo.mcp.gateway.killswitch;

import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;

/**
 * What an instance knows of the emergency switches (CC-194). The state is read from the database and kept for at most {@code ttl}
 * (5 s at most, the decision of the human): a switch put on another instance is in force here within that time, and a copy is never
 * lengthened when a read fails. A state that cannot be read is {@link Status#UNREADABLE}: the caller refuses (fail-closed) and lists
 * nothing. After a failed read the database is not asked again for a second, so that a stalled database does not queue every request on
 * its connection timeout.
 */
public final class KillSwitches {

    public enum Status { OFF, ON, UNREADABLE }

    private static final Logger log = LoggerFactory.getLogger(KillSwitches.class);
    private static final long RETRY_AFTER_FAILURE_NANOS = Duration.ofSeconds(1).toNanos();

    private record Snapshot(List<KillSwitchStore.Entry> entries, Set<String> keys, long readAtNanos) {
    }

    private final Supplier<List<KillSwitchStore.Entry>> reader;
    private final long ttlNanos;
    private final LongSupplier nanoTime;
    private volatile Snapshot snapshot;
    private volatile long failedAtNanos;
    private volatile boolean failed;
    private final Object refreshing = new Object();
    private final java.util.List<Runnable> listeners = new java.util.concurrent.CopyOnWriteArrayList<>();

    /** @param reader reads the switches from the database; a failure is a RuntimeException */
    public KillSwitches(Supplier<List<KillSwitchStore.Entry>> reader, Duration ttl, LongSupplier nanoTime, MeterRegistry meters) {
        this.reader = reader;
        this.ttlNanos = ttl.toNanos();
        this.nanoTime = nanoTime;
        Gauge.builder("mcp_gateway_kill_switches_active", this, k -> {
            Snapshot current = k.snapshot;
            return current == null ? 0 : current.entries().size();
        }).description("Emergency switches that are on, as this instance last read them").register(meters);
        Gauge.builder("mcp_gateway_kill_switches_unreadable", this, k -> k.readable() ? 0 : 1)
                .description("1 when this instance cannot read the emergency switches and refuses calls (fail-closed)").register(meters);
        refresh();
    }

    /** Told when what this instance knows of the switches changed: a switch put or lifted, or the store lost or found again. */
    public void onChange(Runnable listener) {
        listeners.add(listener);
    }

    /** Whether the tool is switched off, by its own switch or by the one of its server. */
    public Status status(String serverId, String tool) {
        Snapshot current = fresh();
        if (current == null) {
            return Status.UNREADABLE;
        }
        return current.keys().contains(key(serverId, null)) || current.keys().contains(key(serverId, tool)) ? Status.ON : Status.OFF;
    }

    /** The switches as they are now, or empty when they cannot be read. */
    public Optional<List<KillSwitchStore.Entry>> entries() {
        Snapshot current = fresh();
        return current == null ? Optional.empty() : Optional.of(current.entries());
    }

    public boolean readable() {
        return fresh() != null;
    }

    /** Reads the state now (after a change is announced, and on the timer); a failure leaves nothing to trust. */
    public boolean refresh() {
        boolean changed;
        boolean ok;
        synchronized (refreshing) {
            Snapshot before = snapshot;
            try {
                List<KillSwitchStore.Entry> entries = reader.get();
                Set<String> keys = new HashSet<>();
                entries.forEach(entry -> keys.add(key(entry.serverId(), entry.tool())));
                snapshot = new Snapshot(List.copyOf(entries), Set.copyOf(keys), nanoTime.getAsLong());
                failed = false;
                changed = before == null || !before.keys().equals(keys);
                ok = true;
            } catch (RuntimeException e) {
                log.error("the emergency switches cannot be read, calls are refused until they can: {}", e.getClass().getName());
                snapshot = null;
                failed = true;
                failedAtNanos = nanoTime.getAsLong();
                changed = before != null;
                ok = false;
            }
        }
        if (changed) {
            listeners.forEach(listener -> {
                try {
                    listener.run();
                } catch (RuntimeException e) {
                    log.warn("a listener of the emergency switches failed: {}", e.getClass().getName());
                }
            });
        }
        return ok;
    }

    /** A copy not older than the TTL, or a new read, or null. */
    private Snapshot fresh() {
        Snapshot current = snapshot;
        long now = nanoTime.getAsLong();
        if (current != null && now - current.readAtNanos() <= ttlNanos) {
            return current;
        }
        if (failed && now - failedAtNanos < RETRY_AFTER_FAILURE_NANOS) {
            return null;
        }
        synchronized (refreshing) {
            current = snapshot;
            if (current != null && nanoTime.getAsLong() - current.readAtNanos() <= ttlNanos) {
                return current;
            }
        }
        refresh();
        return snapshot;
    }

    /** True when a copy is old enough that the timer should read again before the callers have to. */
    public boolean dueForRefresh() {
        Snapshot current = snapshot;
        return current == null || nanoTime.getAsLong() - current.readAtNanos() > ttlNanos / 2;
    }

    private static String key(String serverId, String tool) {
        return serverId + "\u0000" + (tool == null ? "" : tool);
    }
}
