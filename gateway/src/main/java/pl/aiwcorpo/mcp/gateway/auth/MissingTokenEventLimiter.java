package pl.aiwcorpo.mcp.gateway.auth;

import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;

/**
 * Per-process cap on {@code missing_token} authentication events: a request without credentials costs the caller
 * nothing, so without a cap anyone could fill the audit stream. Events over the cap are only counted
 * ({@code gateway_audit_authentication_suppressed_total}), never written to C8.
 */
public final class MissingTokenEventLimiter {

    public static final int DEFAULT_PER_SECOND = 20;
    private static final long SECOND_NANOS = 1_000_000_000L;

    private final int perSecond;
    private final LongSupplier nanoClock;
    private final Counter suppressed;
    private final AtomicLong windowStart;
    private final AtomicLong inWindow = new AtomicLong();

    public MissingTokenEventLimiter(int perSecond, LongSupplier nanoClock, MeterRegistry meters) {
        this.perSecond = perSecond;
        this.nanoClock = nanoClock;
        this.suppressed = Counter.builder("gateway_audit_authentication_suppressed_total")
                .description("missing_token authentication events not written to the audit log (rate cap)").register(meters);
        this.windowStart = new AtomicLong(nanoClock.getAsLong());
    }

    public boolean tryAcquire() {
        long now = nanoClock.getAsLong();
        long start = windowStart.get();
        if (now - start >= SECOND_NANOS && windowStart.compareAndSet(start, now)) {
            inWindow.set(0);
        }
        if (inWindow.incrementAndGet() > perSecond) {
            suppressed.increment();
            return false;
        }
        return true;
    }
}
