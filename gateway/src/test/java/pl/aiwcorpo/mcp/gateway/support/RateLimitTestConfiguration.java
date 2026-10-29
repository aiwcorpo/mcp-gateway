package pl.aiwcorpo.mcp.gateway.support;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.core.StringRedisTemplate;

import io.micrometer.core.instrument.MeterRegistry;
import pl.aiwcorpo.mcp.gateway.config.GatewayProperties;
import pl.aiwcorpo.mcp.gateway.ratelimit.RateLimiter;

/**
 * The limiter of the shared test context reads its settings from here, so that one test can set small limits for its own user, client
 * and tool while the other tests, which make hundreds of requests as the same users, run under limits they never reach.
 */
@TestConfiguration
public class RateLimitTestConfiguration {

    public static final GatewayProperties.RateLimit GENEROUS = settings(1_000_000, 1_000_000, 1_000_000, 1_000_000, Map.of());

    private static final AtomicReference<GatewayProperties.RateLimit> CURRENT = new AtomicReference<>(GENEROUS);

    public static GatewayProperties.RateLimit settings(int perUser, int perClient, int perTool, int destructivePerTool,
                                                       Map<String, Integer> tools) {
        return new GatewayProperties.RateLimit(true, Duration.ofSeconds(30), perUser, perClient, perTool, destructivePerTool, tools,
                Duration.ofSeconds(10));
    }

    public static void use(GatewayProperties.RateLimit next) {
        CURRENT.set(next);
    }

    public static void restore() {
        CURRENT.set(GENEROUS);
    }

    @Bean
    @Primary
    RateLimiter testRateLimiter(StringRedisTemplate redis, GatewayProperties properties, MeterRegistry meters) {
        return new RateLimiter(redis, properties.redis().keyPrefix(), CURRENT::get, meters);
    }
}
