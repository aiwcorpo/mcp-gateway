package pl.aiwcorpo.mcp.gateway.ratelimit;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;

import io.micrometer.core.instrument.MeterRegistry;
import pl.aiwcorpo.mcp.gateway.config.GatewayProperties;
import pl.aiwcorpo.mcp.gateway.redis.KeyHash;
import pl.aiwcorpo.mcp.gateway.server.Risk;

/**
 * Request limits per user, per (user, AI client) and per (user, tool) (CC-135, CC-156), counted in Redis so that every instance of
 * the gateway shares them. A counter is a fixed window that starts with the first request and lives {@code window}; the request
 * that finds one at its limit is refused and counts nowhere, so a refused tool call does not use up the budget of the user. A
 * tool of risk DESTRUCTIVE has its own, lower limit; a limit can be set for any single tool. Redis that does not answer refuses the
 * request as upstream_unavailable (fail-closed, decision of 2026-10-29), with a WARN and a counter.
 */
public final class RateLimiter {

    private static final Logger log = LoggerFactory.getLogger(RateLimiter.class);

    /** The three dimensions in the order they are checked; the name is the audit reason of the refusal. */
    public enum Dimension {
        USER("rate_limited_user"), CLIENT("rate_limited_client"), TOOL("rate_limited_tool");

        private final String reason;

        Dimension(String reason) {
            this.reason = reason;
        }

        public String reason() {
            return reason;
        }
    }

    /**
     * A refusal: which limit, and when to come back (whole seconds, at least 1). A null {@code dimension} means the counters could not
     * be reached: the request is refused as upstream_unavailable (fail-closed), not as a limit.
     */
    public record Limited(Dimension dimension, int retryAfterSeconds) {
        public static final String UNAVAILABLE_REASON = "upstream_unavailable";

        public boolean unavailable() {
            return dimension == null;
        }

        public String reason() {
            return dimension == null ? UNAVAILABLE_REASON : dimension.reason();
        }
    }

    /** Seconds a client is told to wait when Redis does not answer. */
    private static final int UNAVAILABLE_RETRY_SECONDS = 10;

    private static final DefaultRedisScript<List> CHECK_AND_COUNT = new DefaultRedisScript<>("""
            for i = 1, #KEYS do
              local current = tonumber(redis.call('GET', KEYS[i]) or '0')
              if current >= tonumber(ARGV[1 + i]) then
                local ttl = redis.call('PTTL', KEYS[i])
                if ttl < 0 then ttl = tonumber(ARGV[1]) end
                return {i, ttl}
              end
            end
            for i = 1, #KEYS do
              if redis.call('INCR', KEYS[i]) == 1 then redis.call('PEXPIRE', KEYS[i], ARGV[1]) end
            end
            return {0, 0}
            """, List.class);

    private final StringRedisTemplate redis;
    private final String prefix;
    private final java.util.function.Supplier<GatewayProperties.RateLimit> settings;
    private final MeterRegistry meters;

    /** @param settings read on every request, so that a deployment that reloads its configuration changes the limits without a restart */
    public RateLimiter(StringRedisTemplate redis, String keyPrefix, java.util.function.Supplier<GatewayProperties.RateLimit> settings,
                       MeterRegistry meters) {
        this.redis = redis;
        this.prefix = keyPrefix + "rl:";
        this.settings = settings;
        this.meters = meters;
    }

    /**
     * Counts one request and refuses it when a limit of the user, of the user's client or of the tool is reached.
     *
     * @param qualifiedTool {@code <system>__<tool>} of a tool the gateway knows, or null (no tool dimension)
     * @param risk risk of that tool, which picks the lower limit of DESTRUCTIVE tools
     */
    public Optional<Limited> check(String sub, String client, String qualifiedTool, Risk risk) {
        GatewayProperties.RateLimit config = settings.get();
        if (!config.enabled()) {
            return Optional.empty();
        }
        List<Dimension> dimensions = new ArrayList<>();
        List<String> keys = new ArrayList<>();
        List<String> arguments = new ArrayList<>();
        arguments.add(Long.toString(config.window().toMillis()));
        add(dimensions, keys, arguments, Dimension.USER, "u:" + KeyHash.of(sub), config.perUser());
        if (client != null) {
            add(dimensions, keys, arguments, Dimension.CLIENT, "c:" + KeyHash.of(sub + "\n" + client), config.perClient());
        }
        if (qualifiedTool != null) {
            add(dimensions, keys, arguments, Dimension.TOOL, "t:" + KeyHash.of(sub + "\n" + qualifiedTool), toolLimit(config, qualifiedTool, risk));
        }
        try {
            List<?> answer = redis.execute(CHECK_AND_COUNT, keys, arguments.toArray());
            int which = ((Number) answer.get(0)).intValue();
            if (which == 0) {
                return Optional.empty();
            }
            long ttlMillis = ((Number) answer.get(1)).longValue();
            Dimension dimension = dimensions.get(which - 1);
            meters.counter("mcp.gateway.rate.limited", "dimension", dimension.name().toLowerCase(java.util.Locale.ROOT)).increment();
            return Optional.of(new Limited(dimension, (int) Math.max(1, Math.ceil(ttlMillis / 1000.0))));
        } catch (RuntimeException e) {
            meters.counter("mcp.gateway.rate.unavailable").increment();
            log.warn("rate limits not checked, Redis did not answer; the request is refused: {}", e.getClass().getName());
            return Optional.of(new Limited(null, UNAVAILABLE_RETRY_SECONDS));
        }
    }

    private static int toolLimit(GatewayProperties.RateLimit config, String qualifiedTool, Risk risk) {
        Integer own = config.tools().get(qualifiedTool);
        if (own != null) {
            return own;
        }
        return risk == Risk.DESTRUCTIVE ? config.destructivePerTool() : config.perTool();
    }

    private void add(List<Dimension> dimensions, List<String> keys, List<String> arguments, Dimension dimension, String key, int limit) {
        dimensions.add(dimension);
        keys.add(prefix + key);
        arguments.add(Integer.toString(limit));
    }
}
