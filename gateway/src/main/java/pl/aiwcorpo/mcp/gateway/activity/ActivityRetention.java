package pl.aiwcorpo.mcp.gateway.activity;

import java.time.Clock;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;

/** Deletes activity events older than the 30 days of the contract, once at start and then hourly. */
public final class ActivityRetention implements DisposableBean {

    private static final Logger log = LoggerFactory.getLogger(ActivityRetention.class);

    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread thread = new Thread(r, "activity-retention");
        thread.setDaemon(true);
        return thread;
    });

    public ActivityRetention(ActivityStore store, Clock clock) {
        scheduler.scheduleWithFixedDelay(() -> {
            try {
                int removed = store.deleteOlderThan(clock.instant().minus(ActivityService.RETENTION));
                if (removed > 0) {
                    log.info("removed {} activity events older than {}", removed, ActivityService.RETENTION);
                }
            } catch (RuntimeException e) {
                log.warn("activity retention failed: {}", e.getClass().getName());
            }
        }, 1, 60, TimeUnit.MINUTES);
    }

    @Override
    public void destroy() {
        scheduler.shutdownNow();
    }
}
