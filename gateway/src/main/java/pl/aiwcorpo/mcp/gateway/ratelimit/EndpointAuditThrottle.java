package pl.aiwcorpo.mcp.gateway.ratelimit;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.MeterRegistry;
import pl.aiwcorpo.mcp.gateway.audit.AuditEvent;
import pl.aiwcorpo.mcp.gateway.audit.AuditLog;
import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.jwt.UuidV7;
import pl.aiwcorpo.mcp.gateway.redis.KeyHash;

/**
 * Keeps the audit from being flooded by a client that repeats refusals (CC-190, CC-191): {@code invalid_filter}, {@code filter_mismatch},
 * {@code invalid_cursor} and a {@code tools/call} answered {@code not_found_or_denied} for {@code not_granted} or {@code filter_scope}.
 * One event per user, reason and target in an interval; the rest only in {@code mcp_audit_endpoint_suppressed_total{reason}}. A timer
 * closes the window of a user and reason, whether or not more requests come, and writes one summary event with {@code suppressedCount};
 * a controlled shutdown writes the summaries of the open windows. State is in the memory of the instance: with two instances the windows
 * are separate, so a client that alternates between them gets up to one event per instance and interval.
 */
public final class EndpointAuditThrottle implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(EndpointAuditThrottle.class);

    private final AuditThrottleCore<GatewayUser> core;
    private final LongSupplier millis;
    private final MeterRegistry meters;
    private final AuditLog audit;
    private final String componentId;
    private final Supplier<String> policyRevision;
    private final DistributionSummary summaryTargets;
    private final ScheduledExecutorService timer;

    public EndpointAuditThrottle(Duration interval, int maxTargetsPerUserAndReason, LongSupplier millis, MeterRegistry meters, AuditLog audit,
                                 String componentId, Supplier<String> policyRevision) {
        this.core = new AuditThrottleCore<>(interval.toMillis(), maxTargetsPerUserAndReason);
        this.millis = millis;
        this.meters = meters;
        this.audit = audit;
        this.componentId = componentId;
        this.policyRevision = policyRevision;
        this.summaryTargets = DistributionSummary.builder("mcp_audit_endpoint_summary_targets")
                .description("Different targets among the refusals left out of one window (saturates at 1000)").register(meters);
        this.timer = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "audit-throttle-windows");
            thread.setDaemon(true);
            return thread;
        });
        long tick = Math.max(50, Math.min(1000, interval.toMillis() / 2));
        timer.scheduleWithFixedDelay(this::closeDueWindows, tick, tick, TimeUnit.MILLISECONDS);
    }

    /**
     * @param target the tool name for a refused call, else a value that tells one repeated request from another (the raw query, the
     *               canonical filter or the cursor); only its hash is kept
     * @return true when the event is due now, false when it is left out and counted
     */
    public boolean admit(GatewayUser user, String reason, String target) {
        boolean due;
        List<AuditThrottleCore.Summary<GatewayUser>> closed;
        synchronized (core) {
            closed = core.closeDue(millis.getAsLong());
            due = core.admit(millis.getAsLong(), user.sub(), reason, KeyHash.of(target == null ? "" : target), user);
        }
        write(closed);
        if (!due) {
            meters.counter("mcp_audit_endpoint_suppressed_total", "reason", reason).increment();
        }
        return due;
    }

    private void closeDueWindows() {
        try {
            List<AuditThrottleCore.Summary<GatewayUser>> closed;
            synchronized (core) {
                closed = core.closeDue(millis.getAsLong());
            }
            write(closed);
        } catch (RuntimeException e) {
            log.error("audit throttle windows could not be closed: {}", e.getClass().getName());
        }
    }

    @Override
    public void close() {
        timer.shutdownNow();
        List<AuditThrottleCore.Summary<GatewayUser>> closed;
        synchronized (core) {
            closed = core.flush(millis.getAsLong());
        }
        write(closed);
    }

    private void write(List<AuditThrottleCore.Summary<GatewayUser>> summaries) {
        for (AuditThrottleCore.Summary<GatewayUser> summary : summaries) {
            AuditEvent event = AuditEvent.of("policy_decision", UuidV7.next(), componentId).user(summary.user())
                    .decision("deny", summary.reason()).policyRevision(policyRevision.get());
            switch (summary.reason()) {
                case "invalid_filter", "invalid_cursor" -> event.outcome("error");
                case "filter_mismatch" -> event.outcome("denied");
                default -> event.outcome("denied", "not_found_or_denied");
            }
            audit.emit(event.suppressedCount(summary.suppressedCount()));
            summaryTargets.record(summary.suppressedTargets());
        }
    }
}
