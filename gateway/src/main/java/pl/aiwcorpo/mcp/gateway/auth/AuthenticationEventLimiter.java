package pl.aiwcorpo.mcp.gateway.auth;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.function.LongSupplier;

import io.micrometer.core.instrument.MeterRegistry;

/**
 * Per-process caps on {@code authentication} events that cost the sender nothing, so that nobody who reaches a port
 * can fill the audit stream (CC-120, CC-125).
 *
 * <p>{@code missing_token} (no credentials) and {@code malformed} (a token that does not even parse) have a budget per
 * second of their own: a flood of one must not use up the other. {@code client_certificate_rejected} on the admin port
 * is sampled: one event per source address per minute. What is over a budget is only counted in
 * {@value #METRIC}{component, reason} and neither audited nor logged. Nothing else is capped: a token that got past
 * parsing and the key lookup is an attempt, not noise.
 */
public final class AuthenticationEventLimiter {

    public static final int DEFAULT_PER_SECOND = 20;
    public static final String METRIC = "mcp_audit_authentication_suppressed_total";
    public static final String COMPONENT = "gateway";
    static final int MAX_SOURCES = 4096;

    private static final Set<String> CAPPED_PER_SECOND = Set.of("missing_token", "malformed");
    private static final String CERTIFICATE_REJECTED = "client_certificate_rejected";
    private static final long SECOND_NANOS = 1_000_000_000L;

    private final int perSecond;
    private final long sourceIntervalNanos;
    private final LongSupplier nanoClock;
    private final MeterRegistry meters;
    private final Map<String, long[]> windows = new HashMap<>();
    private final Map<String, Long> sourceSeen = new HashMap<>();

    public AuthenticationEventLimiter(int perSecond, java.time.Duration sourceInterval, LongSupplier nanoClock,
                                      MeterRegistry meters) {
        if (perSecond < 1) {
            throw new IllegalArgumentException("perSecond must be at least 1, got " + perSecond);
        }
        this.perSecond = perSecond;
        this.sourceIntervalNanos = sourceInterval.toNanos();
        this.nanoClock = nanoClock;
        this.meters = meters;
    }

    /** True when the event may be written; false (and counted) when the budget of this reason is spent. */
    public synchronized boolean permit(String reason, String source) {
        long now = nanoClock.getAsLong();
        boolean permitted;
        if (CAPPED_PER_SECOND.contains(reason)) {
            long[] window = windows.computeIfAbsent(reason, r -> new long[] {now, 0});
            if (now - window[0] >= SECOND_NANOS) {
                window[0] = now;
                window[1] = 0;
            }
            permitted = ++window[1] <= perSecond;
        } else if (CERTIFICATE_REJECTED.equals(reason)) {
            permitted = permitSource(source == null ? "" : source, now);
        } else {
            permitted = true;
        }
        if (!permitted) {
            meters.counter(METRIC, "component", COMPONENT, "reason", reason).increment();
        }
        return permitted;
    }

    private boolean permitSource(String source, long now) {
        Long last = sourceSeen.get(source);
        if (last != null && now - last < sourceIntervalNanos) {
            return false;
        }
        if (sourceSeen.size() >= MAX_SOURCES) {
            for (Iterator<Long> it = sourceSeen.values().iterator(); it.hasNext();) {
                if (now - it.next() >= sourceIntervalNanos) {
                    it.remove();
                }
            }
            if (sourceSeen.size() >= MAX_SOURCES) {
                // A scan from thousands of addresses: one shared slot, so the map cannot grow without bound.
                source = "";
                Long shared = sourceSeen.get(source);
                if (shared != null && now - shared < sourceIntervalNanos) {
                    return false;
                }
            }
        }
        sourceSeen.put(source, now);
        return true;
    }
}
