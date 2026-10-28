package pl.aiwcorpo.mcp.gateway.registry;

import java.time.Duration;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;

/** Asks servers without an approved manifest for the one they serve, every {@code retry} until every server has one. */
public final class RegistryBootstrap implements DisposableBean {

    private static final Logger log = LoggerFactory.getLogger(RegistryBootstrap.class);

    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread thread = new Thread(r, "registry-bootstrap");
        thread.setDaemon(true);
        return thread;
    });

    public RegistryBootstrap(RegistryService registry, boolean enabled, Duration retry) {
        if (enabled) {
            scheduler.scheduleWithFixedDelay(() -> {
                try {
                    registry.bootstrapMissing();
                } catch (RuntimeException e) {
                    log.warn("manifest bootstrap failed: {}", e.getClass().getName());
                }
            }, 0, retry.toMillis(), TimeUnit.MILLISECONDS);
        }
    }

    @Override
    public void destroy() {
        scheduler.shutdownNow();
    }
}
