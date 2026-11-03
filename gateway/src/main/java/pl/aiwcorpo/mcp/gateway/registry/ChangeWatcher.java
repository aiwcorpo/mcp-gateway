package pl.aiwcorpo.mcp.gateway.registry;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;

import pl.aiwcorpo.mcp.gateway.killswitch.KillSwitches;

/**
 * Looks at the counter of changes on a timer. When it moved, another instance (or this one) changed the registry or a switch: the
 * registry is read again, the switches are read and the listeners are told, which is how a streaming session learns that its list may
 * have changed (CC-192). The switches are read also when their copy is half way to its end, so that the calls rarely read them.
 */
public final class ChangeWatcher implements DisposableBean {

    private static final Logger log = LoggerFactory.getLogger(ChangeWatcher.class);

    private final ChangeCounter counter;
    private final RegistryService registry;
    private final KillSwitches switches;
    private final List<Runnable> listeners;
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread thread = new Thread(r, "change-watcher");
        thread.setDaemon(true);
        return thread;
    });
    private long seen = -1;

    public ChangeWatcher(ChangeCounter counter, RegistryService registry, KillSwitches switches, Duration interval, List<Runnable> listeners) {
        this.counter = counter;
        this.registry = registry;
        this.switches = switches;
        this.listeners = List.copyOf(listeners);
        scheduler.scheduleWithFixedDelay(this::tick, interval.toMillis(), interval.toMillis(), TimeUnit.MILLISECONDS);
    }

    /** One look; public for the tests, which do not wait for the timer. */
    public void tick() {
        try {
            long now = counter.read();
            boolean moved = now != seen;
            if (moved || switches.dueForRefresh()) {
                switches.refresh();
            }
            if (moved) {
                registry.reloadChanged();
                seen = now;
                listeners.forEach(Runnable::run);
            }
        } catch (RuntimeException e) {
            log.warn("the counter of changes could not be read: {}", e.getClass().getName());
            if (switches.dueForRefresh()) {
                switches.refresh();
            }
        }
    }

    @Override
    public void destroy() {
        scheduler.shutdownNow();
    }
}
