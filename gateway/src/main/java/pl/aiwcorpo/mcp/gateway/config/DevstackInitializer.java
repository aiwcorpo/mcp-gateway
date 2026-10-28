package pl.aiwcorpo.mcp.gateway.config;

import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;

/**
 * Runs {@link DevstackGuard} before the first bean exists (registered in {@code META-INF/spring.factories}), so that nothing is
 * pulled over a relaxed setting (policy bundles over http, the IdP keys, manifests) before the start is refused. It reads the
 * configuration with a plain binder; when that does not bind (a required setting is missing) the normal validation of the
 * properties fails the start a moment later, and the guard bean checks the validated properties again.
 */
public final class DevstackInitializer implements ApplicationContextInitializer<ConfigurableApplicationContext> {

    @Override
    public void initialize(ConfigurableApplicationContext context) {
        GatewayProperties properties;
        try {
            properties = Binder.get(context.getEnvironment()).bind("gateway", GatewayProperties.class).orElse(null);
        } catch (RuntimeException e) {
            return;
        }
        if (properties != null) {
            DevstackGuard.enforce(properties, context.getEnvironment(), System.getenv());
        }
    }
}
