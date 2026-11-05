package pl.aiwcorpo.mcp.gateway.activity;

import java.time.Clock;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;

/** Deletes activity events older than the configured retention (30 days by default, CC-134), an hour after the start and then hourly. */
public final class ActivityRetention implements DisposableBean {

    private static final Logger log = LoggerFactory.getLogger(ActivityRetention.class);

    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread thread = new Thread(r, "activity-retention");
        thread.setDaemon(true);
        return thread;
    });

    public ActivityRetention(ActivityStore store, Clock clock, java.time.Duration retention) {
        scheduler.scheduleWithFixedDelay(() -> {
            try {
                int removed = store.deleteOlderThan(clock.instant().minus(retention));
                if (removed > 0) {
                    log.info("removed {} activity events older than {}", removed, retention);
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
