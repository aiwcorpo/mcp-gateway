package pl.aiwcorpo.mcp.gateway.activity;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.micrometer.core.instrument.MeterRegistry;
import pl.aiwcorpo.mcp.gateway.audit.AuditEvent;

/**
 * Keeps the audit events of a user's calls for the activity views. Events with no {@code sub} (authentication of an unknown
 * caller, changes by the system) and the allow of a policy decision (the call's own event follows) are not kept.
 * A failed write is counted and logged; the audit line is the record, so the call is never failed for it.
 */
public final class ActivityRecorder {

    private static final Logger log = LoggerFactory.getLogger(ActivityRecorder.class);
    private static final Set<String> KEPT = Set.of("tool_call", "policy_decision", "confirmation");

    private final ActivityStore store;
    private final MeterRegistry meters;

    public ActivityRecorder(ActivityStore store, MeterRegistry meters) {
        this.store = store;
        this.meters = meters;
    }

    public void record(AuditEvent event) {
        Map<String, Object> fields = event.view();
        Object kind = fields.get("event");
        Object sub = fields.get("sub");
        if (!(kind instanceof String name) || !KEPT.contains(name) || !(sub instanceof String subject)) {
            return;
        }
        if ("policy_decision".equals(name) && "allow".equals(fields.get("decision"))) {
            return;
        }
        String requestId = (String) fields.get("requestId");
        String callKey = event.callKey() != null ? event.callKey() : requestId;
        try {
            store.insert(subject, callKey, Instant.parse((String) fields.get("ts")), requestId, fields);
        } catch (RuntimeException e) {
            meters.counter("gateway_activity_write_failures_total").increment();
            log.error("activity event not stored: {}", e.getClass().getName());
        }
    }
}
