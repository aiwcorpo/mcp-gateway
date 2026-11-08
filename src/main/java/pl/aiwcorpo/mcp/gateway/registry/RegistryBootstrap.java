package pl.aiwcorpo.mcp.gateway.registry;

import java.time.Duration;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;

/**
 * Every {@code retry}: takes approvals that another instance stored, looks again at servers whose policies wait for approval (one that went
 * back to the approved ones is freed without a user) and, when bootstrap is enabled (development), approves what a server that was just
 * added brought ({@link DevBootstrap}).
 */
public final class RegistryBootstrap implements DisposableBean {

    private static final Logger log = LoggerFactory.getLogger(RegistryBootstrap.class);

    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread thread = new Thread(r, "registry-bootstrap");
        thread.setDaemon(true);
        return thread;
    });

    public RegistryBootstrap(RegistryService registry, Runnable development, Duration retry) {
        scheduler.scheduleWithFixedDelay(() -> {
            try {
                registry.reloadChanged();
                registry.recheckPendingPolicies();
                if (development != null) {
                    development.run();
                }
            } catch (RuntimeException e) {
                log.warn("registry refresh failed: {}", e.getClass().getName());
            }
        }, retry.toMillis(), retry.toMillis(), TimeUnit.MILLISECONDS);
    }

    @Override
    public void destroy() {
        scheduler.shutdownNow();
    }
}
