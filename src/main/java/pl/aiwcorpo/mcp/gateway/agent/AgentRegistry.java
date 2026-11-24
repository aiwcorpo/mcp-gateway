package pl.aiwcorpo.mcp.gateway.agent;

import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;

/**
 * What an instance knows of the agents (CC-266), read from the database and kept for at most {@code ttl}: the suspension of an agent is
 * an emergency switch and has the 5 s bound of the others, so a copy is never lengthened when a read fails. A registry that cannot be
 * read refuses agents (fail-closed) and leaves humans alone. After a failed read the database is not asked again for a second.
 */
public final class AgentRegistry {

    /** The answer for one client id: an entry, none, or no answer because the registry cannot be read. */
    public sealed interface Lookup {
        record Found(AgentClient agent) implements Lookup {
        }

        record Absent() implements Lookup {
        }

        record Unreadable() implements Lookup {
        }
    }

    private static final Logger log = LoggerFactory.getLogger(AgentRegistry.class);
    private static final long RETRY_AFTER_FAILURE_NANOS = Duration.ofSeconds(1).toNanos();

    private record Snapshot(Map<String, AgentClient> byClientId, long readAtNanos) {
    }

    private final Supplier<List<AgentClient>> reader;
    private final long ttlNanos;
    private final LongSupplier nanoTime;
    private volatile Snapshot snapshot;
    private volatile long failedAtNanos;
    private volatile boolean failed;
    private final Object refreshing = new Object();
    private final List<Runnable> listeners = new java.util.concurrent.CopyOnWriteArrayList<>();

    public AgentRegistry(Supplier<List<AgentClient>> reader, Duration ttl, LongSupplier nanoTime, MeterRegistry meters) {
        this.reader = reader;
        this.ttlNanos = ttl.toNanos();
        this.nanoTime = nanoTime;
        Gauge.builder("mcp_gateway_agents_unreadable", this, registry -> registry.readable() ? 0 : 1)
                .description("1 when this instance cannot read the agent registry and refuses agents (fail-closed)").register(meters);
        refresh();
    }

    /** A registry that holds nothing and is always readable: for a gateway object that is built without agents. */
    public static AgentRegistry empty() {
        return new AgentRegistry(List::of, Duration.ofDays(1), System::nanoTime, new io.micrometer.core.instrument.simple.SimpleMeterRegistry());
    }

    /** Told when the agents this instance knows of changed (an agent added, changed, suspended or removed, or the store lost or found again). */
    public void onChange(Runnable listener) {
        listeners.add(listener);
    }

    public Lookup find(String clientId) {
        Snapshot current = fresh();
        if (current == null) {
            return new Lookup.Unreadable();
        }
        AgentClient agent = current.byClientId().get(clientId);
        return agent == null ? new Lookup.Absent() : new Lookup.Found(agent);
    }

    /** The agents as they are now, or empty when they cannot be read. */
    public Optional<List<AgentClient>> all() {
        Snapshot current = fresh();
        return current == null ? Optional.empty() : Optional.of(current.byClientId().values().stream()
                .sorted(java.util.Comparator.comparing(AgentClient::clientId)).toList());
    }

    public boolean readable() {
        return fresh() != null;
    }

    public boolean refresh() {
        boolean changed;
        boolean ok;
        synchronized (refreshing) {
            Snapshot before = snapshot;
            long startedNanos = nanoTime.getAsLong();
            try {
                Map<String, AgentClient> read = new HashMap<>();
                reader.get().forEach(agent -> read.put(agent.clientId(), agent));
                snapshot = new Snapshot(Map.copyOf(read), startedNanos);
                failed = false;
                changed = before == null || !before.byClientId().equals(snapshot.byClientId());
                ok = true;
            } catch (RuntimeException e) {
                log.error("the agent registry cannot be read, agents are refused until it can: {}", e.getClass().getName());
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
                    log.warn("a listener of the agent registry failed: {}", e.getClass().getName());
                }
            });
        }
        return ok;
    }

    public boolean dueForRefresh() {
        Snapshot current = snapshot;
        return current == null || nanoTime.getAsLong() - current.readAtNanos() > ttlNanos / 2;
    }

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
}
