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

    /** The actor of an event the system itself raises about a user (offboarding): the sub of the user concerned. */
    public AuditEvent sub(String sub) {
        return put("sub", sub);
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

    /** Canonical endpoint filter of the request (CC-174); null or empty when the request had none or it did not parse. */
    public AuditEvent filter(String canonicalFilter) {
        return put("filter", canonicalFilter);
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

    /** Reason alone, for events that have no allow or deny decision (admin_change, credential_resolve). */
    public AuditEvent reason(String reason) {
        return put("reason", reason);
    }

    /** Hash of the definition an admin_change concerns (CC-133). */
    public AuditEvent definitionHash(String hash) {
        return put("definitionHash", hash);
    }

    /** Revision of the policy data the decision was made with (C7); 0 is not recorded: it names no data. */
    public AuditEvent policyRevision(long revision) {
        if (revision > 0) {
            fields.put("policyRevision", revision);
        }
        return this;
    }

    public AuditEvent credentialType(String type) {
        return put("credentialType", type);
    }

    public AuditEvent outcome(String outcome) {
        return put("outcome", outcome);
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

    /** On the summary event of an audit throttle window: how many refusals of the reason were left out (CC-191). */
    public AuditEvent suppressedCount(int value) {
        fields.put("suppressedCount", Math.max(1, value));
        return this;
    }

    /** On the same summary: how many different targets those refusals had (CC-195). */
    public AuditEvent suppressedTargets(int value) {
        fields.put("suppressedTargets", Math.max(1, value));
        return this;
    }

    /** Cedar action of a classification of an adapter tool, on the admin_change that approves it (CC-193, CC-206). */
    public AuditEvent action(String action) {
        return put("action", action);
    }

    /** Group (C9) of a scope mapping entry; the scope itself goes to {@code resource} (type, and the part after the slash as id). */
    public AuditEvent group(String group) {
        return put("group", group);
    }

    /** The override an admin_change concerns (7.0.0): its id, its target and the hash of its text, never the text. */
    public AuditEvent override(String id, String target, String text, String textBefore) {
        put("overrideId", id);
        put("overrideTarget", target);
        if (text != null) {
            put("textSha256", sha256(text));
        }
        if (textBefore != null) {
            put("textSha256Before", sha256(textBefore));
        }
        return this;
    }

    /** Names of the fields a PATCH of a server changed, never their values. */
    public AuditEvent changedFields(java.util.List<String> names) {
        if (!names.isEmpty()) {
            fields.put("changedFields", java.util.List.copyOf(names));
        }
        return this;
    }

    /** {@code sha256:<hex>} of the UTF-8 text. */
    public static String sha256(String text) {
        try {
            return "sha256:" + java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
                    .digest(text.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
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
