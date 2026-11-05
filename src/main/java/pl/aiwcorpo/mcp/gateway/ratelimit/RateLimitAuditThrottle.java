package pl.aiwcorpo.mcp.gateway.ratelimit;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import io.micrometer.core.instrument.MeterRegistry;

/**
 * Keeps the audit from being flooded by a client that keeps hitting a limit (CC-156, as for CC-125): per user and reason one event
 * in each interval, the rest only in {@code mcp_audit_rate_limited_suppressed_total{reason}}. Per instance, in memory.
 */
public final class RateLimitAuditThrottle {

    private static final int MAX_ENTRIES = 10_000;

    private final Map<String, Long> lastEmitted = new ConcurrentHashMap<>();
    private final long intervalNanos;
    private final java.util.function.LongSupplier nanoTime;
    private final MeterRegistry meters;

    public RateLimitAuditThrottle(Duration interval, java.util.function.LongSupplier nanoTime, MeterRegistry meters) {
        this.intervalNanos = interval.toNanos();
        this.nanoTime = nanoTime;
        this.meters = meters;
    }

    /** True when an event for this user and reason is due now; false (and counted) when one was written within the interval. */
    public boolean due(String sub, String reason) {
        long now = nanoTime.getAsLong();
        if (lastEmitted.size() > MAX_ENTRIES) {
            lastEmitted.values().removeIf(at -> now - at >= intervalNanos);
        }
        boolean[] emit = {false};
        lastEmitted.compute(sub + "\n" + reason, (key, at) -> {
            if (at == null || now - at >= intervalNanos) {
                emit[0] = true;
                return now;
            }
            return at;
        });
        if (!emit[0]) {
            meters.counter("mcp_audit_rate_limited_suppressed_total", "reason", reason).increment();
        }
        return emit[0];
    }
}
