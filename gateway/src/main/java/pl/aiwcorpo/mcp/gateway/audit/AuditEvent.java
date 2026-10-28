package pl.aiwcorpo.mcp.gateway.audit;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;

/**
 * Builder of one C8 event (audit-event.schema.json). Only fields of the schema can be set; there is no way to
 * add argument values, results or secrets.
 */
public final class AuditEvent {

    private static final Pattern CLIENT_REQUEST_ID = Pattern.compile("^[A-Za-z0-9._:-]{1,128}$");
    private static final Pattern TOOL_NAME = Pattern.compile("^[a-z][a-z0-9]*(_[a-z0-9]+)*$");

    private final Map<String, Object> fields = new LinkedHashMap<>();
    private String callKey;

    private AuditEvent(String event, String requestId, String componentId) {
        fields.put("ts", Instant.now().truncatedTo(ChronoUnit.MILLIS).toString());
        fields.put("requestId", requestId);
        fields.put("component", "gateway");
        fields.put("componentId", componentId);
        fields.put("event", event);
    }

    public static AuditEvent of(String event, String requestId, String componentId) {
        return new AuditEvent(event, requestId, componentId);
    }

    public AuditEvent user(GatewayUser user) {
        put("sub", user.sub());
        put("username", user.username());
        put("client", user.client());
        return this;
    }

    /** The actor of an administrative call: the sub and the name, not the client of the BFF token. */
    public AuditEvent userWithoutClient(GatewayUser user) {
        put("sub", user.sub());
        put("username", user.username());
        return this;
    }

    public AuditEvent client(String client) {
        return put("client", client);
    }

    /** Main resource of the call (C8 {@code resource}); ignored when the identifier is not log-safe. */
    public AuditEvent resource(pl.aiwcorpo.mcp.gateway.confirm.PendingCall.Resource resource) {
        if (resource != null) {
            Map<String, Object> value = new LinkedHashMap<>();
            value.put("type", resource.type());
            value.put("id", resource.id());
            if (resource.parent() != null) {
                value.put("parent", resource.parent());
            }
            fields.put("resource", value);
        }
        return this;
    }

    /**
     * Internal link between the events of one call (the confirmation id of a pending call, else the request id). It is
     * not a C8 field: it goes to the activity store only and never to the log line.
     */
    public AuditEvent callKey(String key) {
        this.callKey = key;
        return this;
    }

    public String callKey() {
        return callKey;
    }

    /** A copy of the C8 fields (the call key is not among them). */
    public Map<String, Object> view() {
        return new LinkedHashMap<>(fields);
    }

    /** Client-supplied X-Request-Id; dropped when outside the log-safe alphabet (CC-031). */
    public AuditEvent clientRequestId(String value) {
        if (value != null && CLIENT_REQUEST_ID.matcher(value).matches()) {
            fields.put("clientRequestId", value);
        }
        return this;
    }

    public AuditEvent server(String serverId) {
        return put("server", serverId);
    }

    /** Slug of the link the call came through; the caller only passes slugs that matched the C5 pattern. */
    public AuditEvent virtualServer(String slug) {
        return put("virtualServer", slug);
    }

    public AuditEvent tool(String name) {
        if (name != null && name.length() <= 64 && TOOL_NAME.matcher(name).matches()) {
            fields.put("tool", name);
        }
        return this;
    }

    public AuditEvent risk(String risk) {
        return put("risk", risk);
    }

    public AuditEvent decision(String decision, String reason) {
        put("decision", decision);
        return put("reason", reason);
    }

    public AuditEvent policyRevision(String revision) {
        return put("policyRevision", revision);
    }

    public AuditEvent credentialType(String type) {
        return put("credentialType", type);
    }

    public AuditEvent outcome(String outcome, String errorCode) {
        put("outcome", outcome);
        fields.put("errorCode", errorCode);
        return this;
    }

    public AuditEvent latencyMs(long value) {
        fields.put("latencyMs", Math.max(0, value));
        return this;
    }

    public AuditEvent argsLength(int value) {
        fields.put("argsLength", Math.max(0, value));
        return this;
    }

    Map<String, Object> fields() {
        return fields;
    }

    private AuditEvent put(String name, String value) {
        if (value != null && !value.isEmpty()) {
            fields.put(name, value);
        }
        return this;
    }
}
