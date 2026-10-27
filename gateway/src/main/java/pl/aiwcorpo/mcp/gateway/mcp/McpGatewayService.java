package pl.aiwcorpo.mcp.gateway.mcp;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import pl.aiwcorpo.mcp.gateway.audit.AuditEvent;
import pl.aiwcorpo.mcp.gateway.audit.AuditLog;
import pl.aiwcorpo.mcp.gateway.authz.ToolAuthorizer;
import pl.aiwcorpo.mcp.gateway.authz.ToolDecision;
import pl.aiwcorpo.mcp.gateway.broker.Credential;
import pl.aiwcorpo.mcp.gateway.broker.CredentialService;
import pl.aiwcorpo.mcp.gateway.broker.Resolution;
import pl.aiwcorpo.mcp.gateway.jwt.UuidV7;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.server.ToolDefinition;
import pl.aiwcorpo.mcp.gateway.upstream.UpstreamException;
import pl.aiwcorpo.mcp.gateway.upstream.UpstreamSessions;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * tools/list and tools/call through the gateway: names {@code <system>__<tool>} towards the client (C5), the
 * static tool list and the authorizer as the filter, the broker credential, then the server. Every tools/call
 * leaves one {@code policy_decision} and one {@code tool_call} event (C8).
 */
public class McpGatewayService {

    private static final Logger log = LoggerFactory.getLogger(McpGatewayService.class);
    private static final int MAX_LIST_PAGES = 20;

    private final UpstreamSessions upstream;
    private final CredentialService credentials;
    private final ToolAuthorizer authorizer;
    private final AuditLog audit;
    private final ToolErrors errors;
    private final JsonMapper json;
    private final MeterRegistry meters;
    private final String componentId;

    public McpGatewayService(UpstreamSessions upstream, CredentialService credentials, ToolAuthorizer authorizer,
                             AuditLog audit, ToolErrors errors, JsonMapper json, MeterRegistry meters, String componentId) {
        this.upstream = upstream;
        this.credentials = credentials;
        this.authorizer = authorizer;
        this.audit = audit;
        this.errors = errors;
        this.json = json;
        this.meters = meters;
        this.componentId = componentId;
    }

    public ObjectNode listTools(CallContext ctx) throws RpcFailure {
        McpServer server = ctx.server();
        boolean anyAllowed = server.tools().values().stream()
                .anyMatch(t -> authorizer.decide(ctx.user(), server, t).allowed());
        ObjectNode result = json.createObjectNode();
        ArrayNode out = result.putArray("tools");
        if (!anyAllowed) {
            return result;
        }
        String cursor = null;
        for (int page = 0; page < MAX_LIST_PAGES; page++) {
            ObjectNode request = request("tools/list");
            if (cursor != null) {
                request.putObject("params").put("cursor", cursor);
            }
            JsonNode response = callUpstream(ctx, request, null, null);
            if (response.has("error")) {
                throw new RpcFailure(-32603, "The MCP server could not list its tools.", 502);
            }
            for (JsonNode tool : response.path("result").path("tools")) {
                if (!tool.isObject()) {
                    continue;
                }
                String name = tool.path("name").asString(null);
                Optional<ToolDefinition> definition = name == null ? Optional.empty() : server.tool(name);
                if (definition.isEmpty() || !authorizer.decide(ctx.user(), server, definition.get()).allowed()) {
                    continue;
                }
                ObjectNode copy = (ObjectNode) tool.deepCopy();
                copy.put("name", server.toolPrefix() + name);
                out.add(copy);
            }
            cursor = response.path("result").path("nextCursor").asString(null);
            if (cursor == null || cursor.isEmpty()) {
                return result;
            }
        }
        log.warn("{} returned more than {} pages of tools; list truncated", server.serverId(), MAX_LIST_PAGES);
        return result;
    }

    public ObjectNode callTool(CallContext ctx, JsonNode params) throws RpcFailure {
        long started = System.nanoTime();
        String clientName = params.path("name").asString(null);
        JsonNode arguments = params.has("arguments") ? params.get("arguments") : json.createObjectNode();
        if (clientName == null || !arguments.isObject()) {
            throw new RpcFailure(-32602, "tools/call needs a string name and object arguments.", 400);
        }
        int argsLength = json.writeValueAsString(arguments).getBytes(StandardCharsets.UTF_8).length;
        McpServer server = ctx.server();
        Optional<ToolDefinition> definition = clientName.startsWith(server.toolPrefix())
                ? server.tool(clientName.substring(server.toolPrefix().length()))
                : Optional.empty();
        if (definition.isEmpty()) {
            decisionEvent(ctx, null, null, "deny", "tool_disabled");
            return finish(ctx, null, null, started, argsLength, "deny", "tool_disabled", null,
                    errors.error("tool_disabled", "This tool is not available."));
        }
        ToolDefinition tool = definition.get();
        ToolDecision decision = authorizer.decide(ctx.user(), server, tool);
        if (!decision.allowed()) {
            decisionEvent(ctx, tool, server, "deny", decision.reason());
            ObjectNode error = "tool_disabled".equals(decision.reason())
                    ? errors.error("tool_disabled", "This tool is not available.")
                    : errors.error("access_denied", "You are not allowed to use this tool.",
                            Map.of("requiredEntitlements", decision.requiredEntitlements()));
            return finish(ctx, tool, null, started, argsLength, "deny", decision.reason(), null, error);
        }
        decisionEvent(ctx, tool, server, "allow", null);

        Credential credential = null;
        if (server.credential().required()) {
            Resolution resolution = credentials.resolve(ctx.user(), server.system(), server.credential(), tool.name(),
                    ctx.requestId());
            switch (resolution) {
                case Resolution.Granted granted -> credential = granted.credential();
                case Resolution.Required required -> {
                    return finish(ctx, tool, null, started, argsLength, "allow", "credential_required", null,
                            errors.error("credential_required", "Connect your " + server.system() + " account in the portal.",
                                    Map.of("system", required.system(), "connectUrl", required.connectUrl())));
                }
                case Resolution.Unavailable unavailable -> {
                    return finish(ctx, tool, null, started, argsLength, "allow", null, null,
                            errors.error("upstream_unavailable", "The credential service is unavailable. Try again later."));
                }
                case Resolution.Failed failed -> {
                    log.error("credential for rid={} failed: {}", ctx.requestId(), failed.reason());
                    return finish(ctx, tool, null, started, argsLength, "allow", null, null,
                            errors.error("internal_error", "The call could not be completed."));
                }
            }
        }

        ObjectNode request = request("tools/call");
        ObjectNode upstreamParams = request.putObject("params");
        upstreamParams.put("name", tool.name());
        upstreamParams.set("arguments", arguments);
        JsonNode response;
        try {
            response = upstream.call(server, ctx.conversationKey(), ctx.user(), ctx.requestId(), request, tool.name(), credential);
        } catch (UpstreamException e) {
            log.warn("tools/call rid={} to {} failed: {} {}", ctx.requestId(), server.serverId(), e.kind(), e.getMessage());
            String code = e.kind() == UpstreamException.Kind.UNAVAILABLE ? "upstream_unavailable" : "internal_error";
            String message = e.kind() == UpstreamException.Kind.UNAVAILABLE
                    ? "The MCP server is unavailable. Try again later." : "The call could not be completed.";
            return finish(ctx, tool, credential, started, argsLength, "allow", null, null, errors.error(code, message));
        }
        if (response.has("error")) {
            JsonNode error = response.get("error");
            finish(ctx, tool, credential, started, argsLength, "allow", null, "internal_error", null);
            int code = error.path("code").isInt() ? error.path("code").asInt() : -32603;
            String message = error.path("message").asString("The MCP server returned an error.");
            throw new RpcFailure(code, message.length() > 500 ? message.substring(0, 500) : message, 200);
        }
        JsonNode result = response.path("result");
        if (!result.isObject()) {
            return finish(ctx, tool, credential, started, argsLength, "allow", null, null,
                    errors.error("internal_error", "The call could not be completed."));
        }
        return finish(ctx, tool, credential, started, argsLength, "allow", null, null, (ObjectNode) result);
    }

    private JsonNode callUpstream(CallContext ctx, ObjectNode request, String tool, Credential credential) throws RpcFailure {
        try {
            return upstream.call(ctx.server(), ctx.conversationKey(), ctx.user(), ctx.requestId(), request, tool, credential);
        } catch (UpstreamException e) {
            log.warn("{} rid={} to {} failed: {} {}", request.path("method").asString(), ctx.requestId(),
                    ctx.server().serverId(), e.kind(), e.getMessage());
            throw new RpcFailure(-32603, e.kind() == UpstreamException.Kind.UNAVAILABLE
                    ? "upstream_unavailable: the MCP server is unavailable." : "internal_error", 502);
        }
    }

    private ObjectNode request(String method) {
        ObjectNode request = json.createObjectNode();
        request.put("jsonrpc", "2.0");
        request.put("id", "gw-" + UuidV7.next());
        request.put("method", method);
        return request;
    }

    private void decisionEvent(CallContext ctx, ToolDefinition tool, McpServer server, String decision, String reason) {
        audit.emit(base(ctx, "policy_decision", tool).risk(tool == null ? null : tool.risk().name())
                .decision(decision, reason).policyRevision(authorizer.policyRevision()));
    }

    /**
     * Audits and counts the call. {@code result} null means a JSON-RPC error follows ({@code forcedErrorCode}).
     */
    private ObjectNode finish(CallContext ctx, ToolDefinition tool, Credential credential, long startedNanos, int argsLength,
                              String decision, String reason, String forcedErrorCode, ObjectNode result) {
        long latencyNanos = System.nanoTime() - startedNanos;
        String errorCode = result != null ? errors.codeOf(result) : forcedErrorCode;
        String outcome = "deny".equals(decision) ? "denied" : errorCode == null ? "ok" : "error";
        audit.emit(base(ctx, "tool_call", tool)
                .risk(tool == null ? null : tool.risk().name())
                .decision(decision, reason)
                .policyRevision(authorizer.policyRevision())
                .credentialType(credential == null ? null : credential.type())
                .outcome(outcome, errorCode)
                .latencyMs(latencyNanos / 1_000_000)
                .argsLength(argsLength));
        String toolTag = tool == null ? "unknown" : tool.name();
        meters.counter("mcp.gateway.tool.calls", List.of(
                io.micrometer.core.instrument.Tag.of("server", ctx.server().serverId()),
                io.micrometer.core.instrument.Tag.of("tool", toolTag),
                io.micrometer.core.instrument.Tag.of("outcome", outcome),
                io.micrometer.core.instrument.Tag.of("error", errorCode == null ? "none" : errorCode))).increment();
        Timer.builder("mcp.gateway.tool.call.duration").tag("server", ctx.server().serverId()).tag("tool", toolTag)
                .register(meters).record(java.time.Duration.ofNanos(latencyNanos));
        return result;
    }

    private AuditEvent base(CallContext ctx, String event, ToolDefinition tool) {
        return AuditEvent.of(event, ctx.requestId(), componentId)
                .clientRequestId(ctx.clientRequestId())
                .user(ctx.user())
                .server(ctx.server().serverId())
                .tool(tool == null ? null : tool.name());
    }
}
