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
    private final JsonMapper json = JsonMapper.builder().enable(JsonWriteFeature.ESCAPE_NON_ASCII).build();

    public void emit(AuditEvent event) {
        AUDIT.info(json.writeValueAsString(event.fields()));
    }
}
