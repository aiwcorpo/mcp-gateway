package pl.aiwcorpo.mcp.gateway.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.DependsOn;

/**
 * The beans that act on a relaxed setting (keys, addresses, manifests, the IdP) are created after the guard bean, by an explicit
 * {@code @DependsOn}, not by a parameter their bodies do not use. Removing the annotation fails here.
 */
class DevstackWiringTest {

    private static final List<String> GUARDED = List.of("publicUrls", "signingKeys", "policyService", "registryBootstrap",
            "tokenExchangeClient", "serverRegistry", "idpKeySet");

    @Test
    void everyBeanThatActsOnARelaxedSettingDependsOnTheGuard() {
        List<Method> beans = Arrays.stream(new Class<?>[] {GatewayConfiguration.class, SecurityConfiguration.class})
                .flatMap(type -> Arrays.stream(type.getDeclaredMethods())).filter(m -> m.isAnnotationPresent(Bean.class)).toList();
        for (String name : GUARDED) {
            Method method = beans.stream().filter(m -> m.getName().equals(name)).findFirst()
                    .orElseThrow(() -> new AssertionError("no bean method " + name));
            DependsOn dependsOn = method.getAnnotation(DependsOn.class);
            assertThat(dependsOn).as(name + " is annotated with @DependsOn").isNotNull();
            assertThat(dependsOn.value()).as(name).contains("devstackGuard");
        }
    }

    @Test
    void theGuardBeanExistsAndHasNoCondition() throws Exception {
        Method guard = Arrays.stream(GatewayConfiguration.class.getDeclaredMethods()).filter(m -> m.getName().equals("devstackGuard"))
                .findFirst().orElseThrow();
        assertThat(guard.getAnnotations()).extracting(a -> a.annotationType().getSimpleName()).containsExactly("Bean");
    }
}
