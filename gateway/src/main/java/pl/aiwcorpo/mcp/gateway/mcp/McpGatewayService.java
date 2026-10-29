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
import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.auth.PublicUrls;
import pl.aiwcorpo.mcp.gateway.authz.ToolAuthorizer;
import pl.aiwcorpo.mcp.gateway.authz.ToolDecision;
import pl.aiwcorpo.mcp.gateway.broker.Credential;
import pl.aiwcorpo.mcp.gateway.broker.CredentialService;
import pl.aiwcorpo.mcp.gateway.broker.Resolution;
import pl.aiwcorpo.mcp.gateway.confirm.ConfirmationRules;
import pl.aiwcorpo.mcp.gateway.confirm.ConfirmationService;
import pl.aiwcorpo.mcp.gateway.confirm.OperationDescription;
import pl.aiwcorpo.mcp.gateway.confirm.PendingCall;
import pl.aiwcorpo.mcp.gateway.jwt.UuidV7;
import pl.aiwcorpo.mcp.gateway.ratelimit.RateLimitAuditThrottle;
import pl.aiwcorpo.mcp.gateway.ratelimit.RateLimiter;
import pl.aiwcorpo.mcp.gateway.registry.DefinitionGuard;
import pl.aiwcorpo.mcp.gateway.registry.DefinitionGuard.Verdict;
import pl.aiwcorpo.mcp.gateway.registry.RegistryService;
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
    private final ConfirmationService confirmations;
    private final RegistryService registryService;
    private final DefinitionGuard definitionGuard;
    private final RateLimiter rateLimiter;
    private final RateLimitAuditThrottle rateLimitAudit;

    public McpGatewayService(ServerRegistry registry, PublicUrls urls, UpstreamSessions upstream,
                             CredentialService credentials, ToolAuthorizer authorizer, AuditLog audit, ToolErrors errors,
                             JsonMapper json, MeterRegistry meters, String componentId, ConfirmationService confirmations,
                             RegistryService registryService, DefinitionGuard definitionGuard, RateLimiter rateLimiter,
                             RateLimitAuditThrottle rateLimitAudit) {
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
        this.confirmations = confirmations;
        this.registryService = registryService;
        this.definitionGuard = definitionGuard;
        this.rateLimiter = rateLimiter;
        this.rateLimitAudit = rateLimitAudit;
    }

    /**
     * The limits of the user and of the user's client for a request that is not a tool call (initialize, tools/list, ...). Empty means
     * go on; a refusal is audited as a policy decision (at most one event per user and reason in an interval) and becomes HTTP 429.
     */
    public Optional<RateLimiter.Limited> limitRequest(GatewayUser user, Target target, String requestId, String clientRequestId) {
        Optional<RateLimiter.Limited> limited = rateLimiter.check(user.sub(), user.client(), null, null);
        limited.ifPresent(l -> {
            meters.counter("mcp.gateway.requests.limited").increment();
            if (rateLimitAudit.due(user.sub(), l.reason())) {
                audit.emit(AuditEvent.of("policy_decision", requestId, componentId).clientRequestId(clientRequestId).user(user)
                        .virtualServer(target.virtualSlug()).decision("deny", l.reason()).policyRevision(authorizer.policyRevision())
                        .outcome(l.unavailable() ? "error" : "denied", l.unavailable() ? "upstream_unavailable" : "rate_limited"));
            }
        });
        return limited;
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
        if (!server.approvalRequired()) {
            for (JsonNode tool : readTools(ctx, server)) {
                String name = tool.path("name").asString(null);
                Optional<ToolDefinition> definition = name == null ? Optional.empty() : server.tool(name);
                if (definition.isPresent() && visible(ctx, server, definition.get())) {
                    out.add(listed(server, definition.get(), tool));
                }
            }
            return;
        }
        // The list the client sees is built from the approved definitions; the server's own list only decides which of them
        // may be shown now (CC-133).
        DefinitionGuard.Reading reading = definitions(ctx, server, false);
        server.tools().values().stream().sorted(java.util.Comparator.comparing(ToolDefinition::name)).forEach(definition -> {
            if (visible(ctx, server, definition)
                    && reading.verdicts().getOrDefault(definition.name(), Verdict.NOT_SERVED) == Verdict.INTACT) {
                out.add(listed(server, definition, definition.definition()));
            }
        });
    }

    private ObjectNode listed(McpServer server, ToolDefinition definition, JsonNode source) {
        ObjectNode copy = (ObjectNode) source.deepCopy();
        copy.put("name", server.qualifiedName(definition));
        if (definition.requiresConfirmation()) {
            addConfirmationCode(copy);
        }
        return copy;
    }

    /** Every tool the server lists now, all pages. */
    private List<JsonNode> readTools(CallContext ctx, McpServer server) throws RpcFailure {
        List<JsonNode> tools = new ArrayList<>();
        String cursor = null;
        boolean complete = false;
        for (int page = 0; page < MAX_LIST_PAGES; page++) {
            ObjectNode request = request("tools/list");
            if (cursor != null) {
                request.putObject("params").put("cursor", cursor);
            }
            JsonNode response = callUpstream(ctx, server, request, null, null);
            if (response.has("error")) {
                throw new RpcFailure(-32603, "The MCP server could not list its tools.", 502);
            }
            response.path("result").path("tools").forEach(tool -> {
                if (tool.isObject()) {
                    tools.add(tool);
                }
            });
            cursor = response.path("result").path("nextCursor").asString(null);
            if (cursor == null || cursor.isEmpty()) {
                complete = true;
                break;
            }
        }
        if (!complete) {
            log.warn("{} returned more than {} pages of tools; list truncated", server.serverId(), MAX_LIST_PAGES);
        }
        return tools;
    }

    /**
     * The tool list of the server as of the last read that is not older than the TTL, or a new read. A read that fails is no proof
     * of a change or of a missing tool: for the list the last reading, whatever its age, still decides; a call ({@code needFresh})
     * is refused instead, so that nothing reaches a server whose definitions cannot be checked.
     */
    private DefinitionGuard.Reading definitions(CallContext ctx, McpServer server, boolean needFresh) throws RpcFailure {
        Optional<DefinitionGuard.Reading> fresh = definitionGuard.fresh(server.serverId());
        if (fresh.isPresent()) {
            return fresh.get();
        }
        // A reading judged against approvals that changed meanwhile is dropped and made again; a server whose approvals keep
        // changing under the read is refused (fail-closed) rather than served from a stale verdict.
        for (int attempt = 0; attempt < 3; attempt++) {
            long generation = definitionGuard.generation(server.serverId());
            List<JsonNode> tools;
            try {
                tools = readTools(ctx, server);
            } catch (RpcFailure failure) {
                Optional<DefinitionGuard.Reading> last = definitionGuard.last(server.serverId());
                if (!needFresh && last.isPresent()) {
                    return last.get();
                }
                throw failure;
            }
            Map<String, JsonNode> live = new LinkedHashMap<>();
            for (JsonNode tool : tools) {
                String name = tool.path("name").asString(null);
                if (name != null) {
                    live.putIfAbsent(name, tool);
                }
            }
            McpServer current = registry.find(server.serverId()).orElse(server);
            Map<String, Verdict> verdicts = registryService.observe(current, live, upstream.serverVersion(server.serverId()));
            Optional<DefinitionGuard.Reading> kept = definitionGuard.record(server.serverId(), generation, live,
                    upstream.serverVersion(server.serverId()), verdicts);
            if (kept.isPresent()) {
                verdicts.forEach((name, verdict) -> {
                    if (verdict != Verdict.INTACT) {
                        meters.counter("mcp.gateway.definition.mismatch", "server", server.serverId(), "reason", verdict.reason()).increment();
                        log.warn("{}: the tool {} is blocked ({}): {}", server.serverId(), name, verdict.reason(),
                                verdict == Verdict.CHANGED ? "the definition differs from the approved one" : "the server does not list it");
                    }
                });
                return kept.get();
            }
        }
        throw new RpcFailure(-32603, "upstream_unavailable: the definitions of the server keep changing.", 502);
    }

    /** Why an approved tool of an approved-manifest server may not be used now, from a reading not older than the TTL. */
    private Optional<Verdict> blocked(CallContext ctx, McpServer server, ToolDefinition tool) throws RpcFailure {
        if (!server.approvalRequired()) {
            return Optional.empty();
        }
        Verdict verdict = definitions(ctx, server, true).verdicts().getOrDefault(tool.name(), Verdict.NOT_SERVED);
        return verdict == Verdict.INTACT ? Optional.empty() : Optional.of(verdict);
    }

    /** The code field is added to the schema the client sees; it is not part of the tool's own schema or its hash (C11). */
    private void addConfirmationCode(ObjectNode tool) {
        withConfirmationCode(tool);
    }

    /** Adds the {@code confirmation_code} property, creating {@code properties} for a tool that takes no arguments. */
    static void withConfirmationCode(ObjectNode tool) {
        if (!(tool.get("inputSchema") instanceof ObjectNode inputSchema)) {
            return;
        }
        ObjectNode properties = inputSchema.get("properties") instanceof ObjectNode existing ? existing : inputSchema.putObject("properties");
        ObjectNode code = properties.putObject("confirmation_code");
        code.put("type", "string");
        code.put("pattern", "^[0-9]{6}$");
        code.put("minLength", 6);
        code.put("maxLength", 6);
        code.put("description", "Current 6-digit code of the MCP Platform account in the authenticator app. Ask the user for "
                + "it only after the call answered confirmation_required, then repeat the call with the same arguments.");
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
        Optional<RateLimiter.Limited> limited = rateLimiter.check(ctx.user().sub(), ctx.user().client(),
                resolved.map(r -> r.server().qualifiedName(r.tool())).orElse(null), resolved.map(r -> r.tool().risk()).orElse(null));
        if (limited.isPresent()) {
            return rateLimitedCall(ctx, resolved, limited.get(), started, argsLength);
        }
        if (resolved.isEmpty()) {
            // Outside the configuration or outside the link: the same answer, the link hides what it does not name
            // (C10: tool_disabled is only for a tool an administrator switched off).
            McpServer addressed = ctx.target().server();
            Optional<ServerRegistry.Resolved> known = registry.resolve(clientName);
            if (known.isPresent()) {
                // A real tool the link does not name: the activity shows it as outside the link.
                decisionEvent(ctx, known.get().server(), known.get().tool(), "deny", "link_scope", "not_found_or_denied");
            } else {
                decisionEvent(ctx, addressed, null, "deny", "not_found_or_denied", "not_found_or_denied");
            }
            return finish(ctx, addressed, null, null, started, argsLength, "deny", "not_found_or_denied", null,
                    errors.error("not_found_or_denied", ToolErrors.NOT_FOUND_OR_DENIED_MESSAGE));
        }
        McpServer server = resolved.get().server();
        ToolDefinition tool = resolved.get().tool();
        ToolDecision decision = authorizer.decide(ctx.user(), server, tool, arguments, ctx.target().virtualSlug());
        if (!decision.allowed()) {
            String code = switch (decision.reason()) {
                case "tool_disabled" -> "tool_disabled";
                case "invalid_argument" -> "invalid_argument";
                case "policy_unavailable" -> "upstream_unavailable";
                case "policy_error" -> "internal_error";
                default -> "access_denied";
            };
            decisionEvent(ctx, server, tool, "deny", decision.reason(), code);
            ObjectNode error = switch (code) {
                case "tool_disabled" -> errors.error("tool_disabled", "This tool is not available.");
                case "invalid_argument" -> errors.error("invalid_argument", "An argument does not fit the resource it names.");
                case "upstream_unavailable" -> errors.error("upstream_unavailable", "The policy service is unavailable. Try again later.");
                case "internal_error" -> errors.error("internal_error", "The call could not be completed.");
                default -> decision.requiredEntitlements().isEmpty()
                        ? errors.error("access_denied", "You are not allowed to use this tool.")
                        : errors.error("access_denied", "You are not allowed to use this tool.",
                                Map.of("requiredEntitlements", decision.requiredEntitlements()));
            };
            return finish(ctx, server, tool, null, started, argsLength, "deny", decision.reason(), null, error);
        }
        try {
            Optional<Verdict> blocked = blocked(ctx, server, tool);
            if (blocked.isPresent()) {
                String reason = blocked.get().reason();
                decisionEvent(ctx, server, tool, "deny", reason, "tool_disabled");
                return finish(ctx, server, tool, null, started, argsLength, "deny", reason, null,
                        errors.error("tool_disabled", "This tool is not available."));
            }
        } catch (RpcFailure failure) {
            // The definitions could not be checked: the call is refused before the server, and the decision says so (invariant 10).
            decisionEvent(ctx, server, tool, "deny", "upstream_unavailable", "upstream_unavailable");
            return finish(ctx, server, tool, null, started, argsLength, "deny", "upstream_unavailable", null,
                    errors.error("upstream_unavailable", "The MCP server is unavailable. Try again later."));
        }
        decisionEvent(ctx, server, tool, "allow", null, null);

        String callKey = null;
        if (tool.requiresConfirmation()) {
            Confirmed confirmed = confirm(ctx, server, tool, arguments, started, argsLength);
            if (confirmed.refusal() != null) {
                return confirmed.refusal();
            }
            callKey = confirmed.confirmationId();
            arguments = confirmed.arguments();
        }

        Credential credential = null;
        if (server.credential().required()) {
            Resolution resolution = credentials.resolve(ctx.user(), server.system(), server.credential(), tool.name(),
                    ctx.requestId());
            switch (resolution) {
                case Resolution.Granted granted -> credential = granted.credential();
                case Resolution.Required required -> {
                    return finish(callKey, ctx, server, tool, null, started, argsLength, "allow", "credential_required", null,
                            errors.error("credential_required", "Connect your " + server.system() + " account in the portal.",
                                    Map.of("system", required.system(), "connectUrl", urls.connectUrl(required.system()))));
                }
                case Resolution.Unavailable unavailable -> {
                    return finish(callKey, ctx, server, tool, null, started, argsLength, "allow", null, null,
                            errors.error("upstream_unavailable", "The credential service is unavailable. Try again later."));
                }
                case Resolution.Denied denied -> {
                    // The IdP refused the exchange: the user may not use this system. The answer names no group (CC-157).
                    resolveEvent(ctx, server, tool, denied.reason(), "denied", "access_denied");
                    return finish(callKey, ctx, server, tool, null, started, argsLength, "deny", denied.reason(), null,
                            errors.error("access_denied", "You are not allowed to use this tool."));
                }
                case Resolution.Failed failed -> {
                    log.error("credential for rid={} failed: {}", ctx.requestId(), failed.reason());
                    if ("system_not_configured".equals(failed.reason())) {
                        // A defect of the installation, not of the request: the client sees internal_error, the audit says why (CC-158).
                        resolveEvent(ctx, server, tool, "system_not_configured", "error", "internal_error");
                    }
                    return finish(callKey, ctx, server, tool, null, started, argsLength, "allow", null, null,
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
            return finish(callKey, ctx, server, tool, credential, started, argsLength, "allow", null, null, errors.error(code, message));
        } catch (RuntimeException e) {
            // Only the class: JDK messages can quote header values, i.e. the credential.
            log.error("tools/call rid={} to {} failed: {}", ctx.requestId(), server.serverId(), e.getClass().getName());
            return finish(callKey, ctx, server, tool, credential, started, argsLength, "allow", null, null,
                    errors.error("internal_error", "The call could not be completed."));
        }
        if (response.has("error")) {
            JsonNode error = response.get("error");
            finish(callKey, ctx, server, tool, credential, started, argsLength, "allow", null, "internal_error", null);
            int code = error.path("code").isInt() ? error.path("code").asInt() : -32603;
            throw new RpcFailure(code, safeMessage(code), 200);
        }
        JsonNode result = response.path("result");
        if (!result.isObject()) {
            return finish(callKey, ctx, server, tool, credential, started, argsLength, "allow", null, null,
                    errors.error("internal_error", "The call could not be completed."));
        }
        return finish(callKey, ctx, server, tool, credential, started, argsLength, "allow", null, null, (ObjectNode) result);
    }

    /** The call is refused before anything else happens: no policy, no broker, no server (CC-156). */
    private ObjectNode rateLimitedCall(CallContext ctx, Optional<ServerRegistry.Resolved> resolved, RateLimiter.Limited limited,
                                       long started, int argsLength) {
        McpServer server = resolved.map(ServerRegistry.Resolved::server).orElse(ctx.target().server());
        ToolDefinition tool = resolved.map(ServerRegistry.Resolved::tool).orElse(null);
        String code = limited.unavailable() ? "upstream_unavailable" : "rate_limited";
        ObjectNode result = limited.unavailable()
                ? errors.error("upstream_unavailable", "The service is unavailable. Try again later.")
                : errors.error("rate_limited", "Too many calls. Try again later.", Map.of("retryAfterSeconds", limited.retryAfterSeconds()));
        long latencyNanos = System.nanoTime() - started;
        if (rateLimitAudit.due(ctx.user().sub(), limited.reason())) {
            audit.emit(base(ctx, server, "tool_call", tool).risk(tool == null ? null : tool.risk().name())
                    .decision("deny", limited.reason()).policyRevision(authorizer.policyRevision())
                    .outcome(limited.unavailable() ? "error" : "denied", code).latencyMs(latencyNanos / 1_000_000).argsLength(argsLength));
        }
        count(server, tool, limited.unavailable() ? "error" : "denied", code, latencyNanos);
        return result;
    }

    private record Confirmed(ObjectNode refusal, String confirmationId, JsonNode arguments) {
    }

    private static final java.util.regex.Pattern CODE = java.util.regex.Pattern.compile("^[0-9]{6}$");

    /**
     * The confirmation gate of a DESTRUCTIVE tool (C11): without a code a pending call is created and the call stops;
     * with a code the broker judges it and the call goes on only when it was right. The code never reaches the server.
     */
    private Confirmed confirm(CallContext ctx, McpServer server, ToolDefinition tool, JsonNode arguments, long started,
                              int argsLength) {
        ServerAndTool at = new ServerAndTool(server, tool);
        ObjectNode withoutCode = ((ObjectNode) arguments).deepCopy();
        JsonNode codeNode = withoutCode.remove("confirmation_code");
        String code = null;
        if (codeNode != null) {
            if (!codeNode.isString() || !CODE.matcher(codeNode.asString()).matches()) {
                return new Confirmed(finish(ctx, server, tool, null, started, argsLength, "allow", null, "invalid_argument",
                        errors.error("invalid_argument", "confirmation_code must be the 6 digits shown in the authenticator app.")),
                        null, null);
            }
            code = codeNode.asString();
        }
        ConfirmationRules.Operation operation = new ConfirmationRules.Operation(server.serverId(), tool.name(),
                tool.risk().name(), OperationDescription.argumentsHash(withoutCode));
        PendingCall.Display display = OperationDescription.of(json, server.qualifiedName(tool), server.system(), withoutCode,
                tool.resourceRefs());
        ConfirmationService.CallInfo info = new ConfirmationService.CallInfo(ctx.user(), ctx.requestId(), ctx.clientRequestId(),
                ctx.target().virtualSlug(), server.serverId(), tool.name(), operation, display);
        if (code == null) {
            return new Confirmed(firstCall(at, started, info), null, null);
        }
        ConfirmationService.RetryResult result = confirmations.retry(info, code);
        if (result instanceof ConfirmationService.RetryResult.Execute execute) {
            return new Confirmed(null, execute.confirmationId(), withoutCode);
        }
        return new Confirmed(refuse(at, started, retryError(result)), null, null);
    }

    private ObjectNode firstCall(ServerAndTool at, long started, ConfirmationService.CallInfo info) {
        ConfirmationService.FirstCallResult result = confirmations.firstCall(info);
        return switch (result) {
            case ConfirmationService.FirstCallResult.Pending pending -> {
                PendingCall call = pending.call();
                java.time.Instant expires = java.time.Instant.ofEpochMilli(call.expiresAt(ConfirmationRules.TTL_MILLIS))
                        .truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
                Map<String, Object> extra = new LinkedHashMap<>();
                extra.put("confirmationId", call.confirmationId());
                extra.put("description", call.display().description());
                extra.put("previewUrl", urls.confirmationPreviewUrl(call.confirmationId()));
                extra.put("expiresAt", expires.toString());
                yield refuse(at, started, errors.error("confirmation_required", CODE_REQUIRED, extra));
            }
            case ConfirmationService.FirstCallResult.Register register -> refuse(at, started, registerError());
            case ConfirmationService.FirstCallResult.Blocked blocked -> refuse(at, started,
                    errors.error("confirmation_blocked", BLOCKED, Map.of("retryAfterSeconds", blocked.retryAfterSeconds())));
            case ConfirmationService.FirstCallResult.RateLimited limited -> refuse(at, started,
                    errors.error("rate_limited", "Too many operations wait for confirmation. Try again later.",
                            Map.of("retryAfterSeconds", limited.retryAfterSeconds())));
            case ConfirmationService.FirstCallResult.Unavailable unavailable -> refuse(at, started, unavailableError());
        };
    }

    private ObjectNode retryError(ConfirmationService.RetryResult result) {
        return switch (result) {
            case ConfirmationService.RetryResult.Superseded s -> errors.error("confirmation_superseded",
                    "This operation was replaced by a newer one. Start it again if you still want it.");
            case ConfirmationService.RetryResult.Cancelled c -> errors.error("confirmation_cancelled",
                    "The user cancelled this operation. Start it again if it is still wanted.");
            case ConfirmationService.RetryResult.RateLimited r -> errors.error("rate_limited",
                    "Too many wrong codes. Try again later.", Map.of("retryAfterSeconds", r.retryAfterSeconds()));
            case ConfirmationService.RetryResult.Register r -> registerError();
            case ConfirmationService.RetryResult.Unavailable u -> unavailableError();
            default -> errors.error("confirmation_failed", "Confirmation failed.");
        };
    }

    private ObjectNode registerError() {
        return errors.error("confirmation_required", "Register the authenticator in the portal first, then repeat the call.",
                Map.of("registerUrl", urls.authenticatorUrl()));
    }

    private ObjectNode unavailableError() {
        return errors.error("upstream_unavailable", "The confirmation service is unavailable. Try again later.");
    }

    private ObjectNode refuse(ServerAndTool at, long started, ObjectNode error) {
        return refuse(at, started, errors.codeOf(error), error);
    }

    private static final String CODE_REQUIRED = "Type the current 6-digit code of the MCP Platform account from your "
            + "authenticator app and retry the call with confirmation_code.";
    private static final String BLOCKED = "Another destructive operation of this user is waiting for confirmation. Do not ask "
            + "the user for a code for this call; tell them that another operation awaits confirmation and try again later.";

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

    /** The gateway's own record of a credential resolution that did not give a credential for a reason the contract names. */
    private void resolveEvent(CallContext ctx, McpServer server, ToolDefinition tool, String reason, String outcome, String errorCode) {
        audit.emit(base(ctx, server, "credential_resolve", tool).reason(reason).outcome(outcome, errorCode));
    }

    private void decisionEvent(CallContext ctx, McpServer server, ToolDefinition tool, String decision, String reason,
                               String errorCode) {
        AuditEvent event = base(ctx, server, "policy_decision", tool).risk(tool == null ? null : tool.risk().name())
                .decision(decision, reason).policyRevision(authorizer.policyRevision());
        if ("deny".equals(decision)) {
            event.outcome("denied", errorCode);
        }
        audit.emit(event);
    }

    /**
     * Audits and counts the call. {@code result} null means a JSON-RPC error follows ({@code forcedErrorCode}).
     * {@code server} is null only for a tool outside the configuration called through a link.
     */
    private ObjectNode finish(CallContext ctx, McpServer server, ToolDefinition tool, Credential credential,
                              long startedNanos, int argsLength, String decision, String reason, String forcedErrorCode,
                              ObjectNode result) {
        return finish(null, ctx, server, tool, credential, startedNanos, argsLength, decision, reason, forcedErrorCode, result);
    }

    /** {@code callKey}: the confirmation the call was confirmed by, so that its events form one row of the activity. */
    private ObjectNode finish(String callKey, CallContext ctx, McpServer server, ToolDefinition tool, Credential credential,
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
                .argsLength(argsLength)
                .callKey(callKey));
        count(server, tool, outcome, errorCode, latencyNanos);
        return result;
    }

    /** A refusal of the confirmation gate: the confirmation event already says what happened, there is no tool_call. */
    private ObjectNode refuse(ServerAndTool at, long startedNanos, String errorCode, ObjectNode result) {
        count(at.server(), at.tool(), "denied".equals(errorCode) ? "denied" : "error", errorCode, System.nanoTime() - startedNanos);
        return result;
    }

    private record ServerAndTool(McpServer server, ToolDefinition tool) {
    }

    private void count(McpServer server, ToolDefinition tool, String outcome, String errorCode, long latencyNanos) {
        String toolTag = tool == null ? "unknown" : tool.name();
        String serverTag = server == null ? "virtual" : server.serverId();
        meters.counter("mcp.gateway.tool.calls", List.of(
                io.micrometer.core.instrument.Tag.of("server", serverTag),
                io.micrometer.core.instrument.Tag.of("tool", toolTag),
                io.micrometer.core.instrument.Tag.of("outcome", outcome),
                io.micrometer.core.instrument.Tag.of("error", errorCode == null ? "none" : errorCode))).increment();
        Timer.builder("mcp.gateway.tool.call.duration").tag("server", serverTag).tag("tool", toolTag)
                .register(meters).record(java.time.Duration.ofNanos(latencyNanos));
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
