package pl.aiwcorpo.mcp.gateway.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import tools.jackson.core.json.JsonWriteFeature;
import tools.jackson.databind.json.JsonMapper;

/**
 * C8 events, one JSON object per line on the dedicated {@code AUDIT} logger (stdout without a prefix, see
 * logback-spring.xml), so {@code make audit RID=} and a SIEM shipper can read them. Non-ASCII is escaped, so no
 * value can break the line or smuggle U+2028/U+2029.
 */
public final class AuditLog {

    private static final Logger AUDIT = LoggerFactory.getLogger("AUDIT");
    private static final Logger AUDIT_FAILURES = LoggerFactory.getLogger(AuditLog.class);
    private final JsonMapper json = JsonMapper.builder().enable(JsonWriteFeature.ESCAPE_NON_ASCII).build();

    private final java.util.List<java.util.function.Consumer<AuditEvent>> listeners = new java.util.concurrent.CopyOnWriteArrayList<>();

    /** Gets every event after it is logged (the activity store records the events of a user's calls). */
    public void listen(java.util.function.Consumer<AuditEvent> listener) {
        listeners.add(listener);
    }

    public void emit(AuditEvent event) {
        AUDIT.info(json.writeValueAsString(event.fields()));
        for (java.util.function.Consumer<AuditEvent> listener : listeners) {
            try {
                listener.accept(event);
            } catch (RuntimeException e) {
                // The log line is the record of the event; a listener must not break the call.
                AUDIT_FAILURES.warn("audit listener failed: {}", e.getClass().getName());
            }
        }
    }
}
