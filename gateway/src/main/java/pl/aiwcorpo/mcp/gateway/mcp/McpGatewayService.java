package pl.aiwcorpo.mcp.gateway.mcp;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import pl.aiwcorpo.mcp.gateway.audit.AuditEvent;
import pl.aiwcorpo.mcp.gateway.audit.AuditLog;
import pl.aiwcorpo.mcp.gateway.auth.PublicUrls;
import pl.aiwcorpo.mcp.gateway.authz.ToolAuthorizer;
import pl.aiwcorpo.mcp.gateway.authz.ToolDecision;
import pl.aiwcorpo.mcp.gateway.broker.Credential;
import pl.aiwcorpo.mcp.gateway.broker.CredentialService;
import pl.aiwcorpo.mcp.gateway.broker.Resolution;
import pl.aiwcorpo.mcp.gateway.jwt.UuidV7;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.server.ServerRegistry;
import pl.aiwcorpo.mcp.gateway.server.ToolDefinition;
import pl.aiwcorpo.mcp.gateway.upstream.UpstreamException;
import pl.aiwcorpo.mcp.gateway.upstream.UpstreamSessions;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * tools/list and tools/call through the gateway: names {@code <system>__<tool>} towards the client (C5), the
 * static tool list, the link (when the client came through one) and the authorizer as the filter, the broker
 * credential, then the server. A link only narrows: a tool is visible and callable only when the link names it
 * and the authorizer allows it for the caller. Every tools/call leaves one {@code policy_decision} and one
 * {@code tool_call} event (C8).
 */
public class McpGatewayService {

    private static final Logger log = LoggerFactory.getLogger(McpGatewayService.class);
    private static final int MAX_LIST_PAGES = 20;

    private final ServerRegistry registry;
    private final PublicUrls urls;
    private final UpstreamSessions upstream;
    private final CredentialService credentials;
    private final ToolAuthorizer authorizer;
    private final AuditLog audit;
    private final ToolErrors errors;
    private final JsonMapper json;
    private final MeterRegistry meters;
    private final String componentId;

    public McpGatewayService(ServerRegistry registry, PublicUrls urls, UpstreamSessions upstream,
                             CredentialService credentials, ToolAuthorizer authorizer, AuditLog audit, ToolErrors errors,
                             JsonMapper json, MeterRegistry meters, String componentId) {
        this.registry = registry;
        this.urls = urls;
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
        List<McpServer> servers = serversOf(ctx);
        ObjectNode result = json.createObjectNode();
        ArrayNode out = result.putArray("tools");
        int failed = 0;
        RpcFailure lastFailure = null;
        for (McpServer server : servers) {
            try {
                listFrom(ctx, server, out);
            } catch (RpcFailure failure) {
                failed++;
                lastFailure = failure;
                log.warn("tools/list rid={}: {} left out of the list", ctx.requestId(), server.serverId());
            }
        }
        // One failing server of a link must not hide the tools of the others, but a list that is empty only
        // because everything failed is an error, not an empty list.
        if (failed > 0 && failed == servers.size()) {
            throw lastFailure;
        }
        return result;
    }

    private void listFrom(CallContext ctx, McpServer server, ArrayNode out) throws RpcFailure {
        boolean anyVisible = server.tools().values().stream().anyMatch(t -> visible(ctx, server, t));
        if (!anyVisible) {
            return;
        }
        String cursor = null;
        for (int page = 0; page < MAX_LIST_PAGES; page++) {
            ObjectNode request = request("tools/list");
            if (cursor != null) {
                request.putObject("params").put("cursor", cursor);
            }
            JsonNode response = callUpstream(ctx, server, request, null, null);
            if (response.has("error")) {
                throw new RpcFailure(-32603, "The MCP server could not list its tools.", 502);
            }
            for (JsonNode tool : response.path("result").path("tools")) {
                if (!tool.isObject()) {
                    continue;
                }
                String name = tool.path("name").asString(null);
                Optional<ToolDefinition> definition = name == null ? Optional.empty() : server.tool(name);
                if (definition.isEmpty() || !visible(ctx, server, definition.get())) {
                    continue;
                }
                ObjectNode copy = (ObjectNode) tool.deepCopy();
                copy.put("name", server.qualifiedName(definition.get()));
                out.add(copy);
            }
            cursor = response.path("result").path("nextCursor").asString(null);
            if (cursor == null || cursor.isEmpty()) {
                return;
            }
        }
        log.warn("{} returned more than {} pages of tools; list truncated", server.serverId(), MAX_LIST_PAGES);
    }

    /** The servers behind the endpoint: the one addressed, or those that own the tools of the link. */
    private List<McpServer> serversOf(CallContext ctx) {
        Target target = ctx.target();
        if (target.link() == null) {
            return List.of(target.server());
        }
        Map<String, McpServer> servers = new LinkedHashMap<>();
        for (String name : target.link().tools()) {
            registry.resolve(name).ifPresent(resolved -> servers.putIfAbsent(resolved.server().serverId(), resolved.server()));
        }
        return new ArrayList<>(servers.values());
    }

    /** In scope of the endpoint (the link names the tool) and allowed for the caller now. */
    private boolean visible(CallContext ctx, McpServer server, ToolDefinition tool) {
        return inScope(ctx, server, tool) && authorizer.decide(ctx.user(), server, tool).allowed();
    }

    private static boolean inScope(CallContext ctx, McpServer server, ToolDefinition tool) {
        Target target = ctx.target();
        return target.link() == null ? server.serverId().equals(target.server().serverId())
                : target.link().allows(server.qualifiedName(tool));
    }

    public ObjectNode callTool(CallContext ctx, JsonNode params) throws RpcFailure {
        long started = System.nanoTime();
        String clientName = params.path("name").asString(null);
        JsonNode arguments = params.has("arguments") ? params.get("arguments") : json.createObjectNode();
        if (clientName == null || !arguments.isObject()) {
            finish(ctx, ctx.target().server(), null, null, started, 0, "allow", null, "invalid_argument", null);
            throw new RpcFailure(-32602, "tools/call needs a string name and object arguments.", 400);
        }
        int argsLength = json.writeValueAsString(arguments).getBytes(StandardCharsets.UTF_8).length;
        Optional<ServerRegistry.Resolved> resolved = registry.resolve(clientName)
                .filter(r -> inScope(ctx, r.server(), r.tool()));
        if (resolved.isEmpty()) {
            // Outside the configuration or outside the link: the same answer, the link hides what it does not name
            // (C10: tool_disabled is only for a tool an administrator switched off).
            McpServer addressed = ctx.target().server();
            decisionEvent(ctx, addressed, null, "deny", "not_found_or_denied");
            return finish(ctx, addressed, null, null, started, argsLength, "deny", "not_found_or_denied", null,
                    errors.error("not_found_or_denied", "This tool was not found or is not available to you."));
        }
        McpServer server = resolved.get().server();
        ToolDefinition tool = resolved.get().tool();
        ToolDecision decision = authorizer.decide(ctx.user(), server, tool);
        if (!decision.allowed()) {
            decisionEvent(ctx, server, tool, "deny", decision.reason());
            ObjectNode error = "tool_disabled".equals(decision.reason())
                    ? errors.error("tool_disabled", "This tool is not available.")
                    : errors.error("access_denied", "You are not allowed to use this tool.",
                            Map.of("requiredEntitlements", decision.requiredEntitlements()));
            return finish(ctx, server, tool, null, started, argsLength, "deny", decision.reason(), null, error);
        }
        decisionEvent(ctx, server, tool, "allow", null);

        Credential credential = null;
        if (server.credential().required()) {
            Resolution resolution = credentials.resolve(ctx.user(), server.system(), server.credential(), tool.name(),
                    ctx.requestId());
            switch (resolution) {
                case Resolution.Granted granted -> credential = granted.credential();
                case Resolution.Required required -> {
                    return finish(ctx, server, tool, null, started, argsLength, "allow", "credential_required", null,
                            errors.error("credential_required", "Connect your " + server.system() + " account in the portal.",
                                    Map.of("system", required.system(), "connectUrl", urls.connectUrl(required.system()))));
                }
                case Resolution.Unavailable unavailable -> {
                    return finish(ctx, server, tool, null, started, argsLength, "allow", null, null,
                            errors.error("upstream_unavailable", "The credential service is unavailable. Try again later."));
                }
                case Resolution.Failed failed -> {
                    log.error("credential for rid={} failed: {}", ctx.requestId(), failed.reason());
                    return finish(ctx, server, tool, null, started, argsLength, "allow", null, null,
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
            response = upstream.call(server, ctx.conversationKey(), ctx.user(), ctx.requestId(), request, tool.name(), credential,
                    ctx.target().virtualSlug());
        } catch (UpstreamException e) {
            log.warn("tools/call rid={} to {} failed: {} {}", ctx.requestId(), server.serverId(), e.kind(), e.getMessage());
            String code = e.kind() == UpstreamException.Kind.UNAVAILABLE ? "upstream_unavailable" : "internal_error";
            String message = e.kind() == UpstreamException.Kind.UNAVAILABLE
                    ? "The MCP server is unavailable. Try again later." : "The call could not be completed.";
            return finish(ctx, server, tool, credential, started, argsLength, "allow", null, null, errors.error(code, message));
        } catch (RuntimeException e) {
            // Only the class: JDK messages can quote header values, i.e. the credential.
            log.error("tools/call rid={} to {} failed: {}", ctx.requestId(), server.serverId(), e.getClass().getName());
            return finish(ctx, server, tool, credential, started, argsLength, "allow", null, null,
                    errors.error("internal_error", "The call could not be completed."));
        }
        if (response.has("error")) {
            JsonNode error = response.get("error");
            finish(ctx, server, tool, credential, started, argsLength, "allow", null, "internal_error", null);
            int code = error.path("code").isInt() ? error.path("code").asInt() : -32603;
            throw new RpcFailure(code, safeMessage(code), 200);
        }
        JsonNode result = response.path("result");
        if (!result.isObject()) {
            return finish(ctx, server, tool, credential, started, argsLength, "allow", null, null,
                    errors.error("internal_error", "The call could not be completed."));
        }
        return finish(ctx, server, tool, credential, started, argsLength, "allow", null, null, (ObjectNode) result);
    }

    private JsonNode callUpstream(CallContext ctx, McpServer server, ObjectNode request, String tool, Credential credential)
            throws RpcFailure {
        try {
            return upstream.call(server, ctx.conversationKey(), ctx.user(), ctx.requestId(), request, tool, credential,
                    ctx.target().virtualSlug());
        } catch (UpstreamException e) {
            log.warn("{} rid={} to {} failed: {} {}", request.path("method").asString(), ctx.requestId(),
                    server.serverId(), e.kind(), e.getMessage());
            throw new RpcFailure(-32603, e.kind() == UpstreamException.Kind.UNAVAILABLE
                    ? "upstream_unavailable: the MCP server is unavailable." : "internal_error", 502);
        } catch (RuntimeException e) {
            log.error("{} rid={} to {} failed: {}", request.path("method").asString(), ctx.requestId(),
                    server.serverId(), e.getClass().getName());
            throw new RpcFailure(-32603, "internal_error", 502);
        }
    }

    /** Fixed texts: the server's own message may carry backend content, and C10 forbids passing it on. */
    private static String safeMessage(int code) {
        return switch (code) {
            case -32700 -> "Parse error.";
            case -32600 -> "Invalid request.";
            case -32601 -> "Method not found.";
            case -32602 -> "Invalid params.";
            default -> "The MCP server returned an error.";
        };
    }

    private ObjectNode request(String method) {
        ObjectNode request = json.createObjectNode();
        request.put("jsonrpc", "2.0");
        request.put("id", "gw-" + UuidV7.next());
        request.put("method", method);
        return request;
    }

    private void decisionEvent(CallContext ctx, McpServer server, ToolDefinition tool, String decision, String reason) {
        audit.emit(base(ctx, server, "policy_decision", tool).risk(tool == null ? null : tool.risk().name())
                .decision(decision, reason).policyRevision(authorizer.policyRevision()));
    }

    /**
     * Audits and counts the call. {@code result} null means a JSON-RPC error follows ({@code forcedErrorCode}).
     * {@code server} is null only for a tool outside the configuration called through a link.
     */
    private ObjectNode finish(CallContext ctx, McpServer server, ToolDefinition tool, Credential credential,
                              long startedNanos, int argsLength, String decision, String reason, String forcedErrorCode,
                              ObjectNode result) {
        long latencyNanos = System.nanoTime() - startedNanos;
        String errorCode = result != null ? errors.codeOf(result) : forcedErrorCode;
        String outcome = "deny".equals(decision) ? "denied" : errorCode == null ? "ok" : "error";
        audit.emit(base(ctx, server, "tool_call", tool)
                .risk(tool == null ? null : tool.risk().name())
                .decision(decision, reason)
                .policyRevision(authorizer.policyRevision())
                .credentialType(credential == null ? null : credential.type())
                .outcome(outcome, errorCode)
                .latencyMs(latencyNanos / 1_000_000)
                .argsLength(argsLength));
        String toolTag = tool == null ? "unknown" : tool.name();
        String serverTag = server == null ? "virtual" : server.serverId();
        meters.counter("mcp.gateway.tool.calls", List.of(
                io.micrometer.core.instrument.Tag.of("server", serverTag),
                io.micrometer.core.instrument.Tag.of("tool", toolTag),
                io.micrometer.core.instrument.Tag.of("outcome", outcome),
                io.micrometer.core.instrument.Tag.of("error", errorCode == null ? "none" : errorCode))).increment();
        Timer.builder("mcp.gateway.tool.call.duration").tag("server", serverTag).tag("tool", toolTag)
                .register(meters).record(java.time.Duration.ofNanos(latencyNanos));
        return result;
    }

    private AuditEvent base(CallContext ctx, McpServer server, String event, ToolDefinition tool) {
        return AuditEvent.of(event, ctx.requestId(), componentId)
                .clientRequestId(ctx.clientRequestId())
                .user(ctx.user())
                .virtualServer(ctx.target().virtualSlug())
                .server(server == null ? null : server.serverId())
                .tool(tool == null ? null : tool.name());
    }
}
