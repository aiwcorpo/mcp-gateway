package pl.aiwcorpo.mcp.gateway.registry;

import java.time.Duration;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;

/**
 * Every {@code retry}: takes approvals that another instance stored, looks again at servers that were pinned back for the policies they
 * presented and, when bootstrap is enabled (development), asks servers without any stored approval for the manifest they serve.
 */
public final class RegistryBootstrap implements DisposableBean {

    private static final Logger log = LoggerFactory.getLogger(RegistryBootstrap.class);

    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread thread = new Thread(r, "registry-bootstrap");
        thread.setDaemon(true);
        return thread;
    });

    public RegistryBootstrap(RegistryService registry, boolean enabled, Duration retry) {
        scheduler.scheduleWithFixedDelay(() -> {
            try {
                registry.reloadChanged();
                registry.recheckServerPolicies();
                if (enabled) {
                    registry.bootstrapMissing();
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
