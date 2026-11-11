package pl.aiwcorpo.mcp.gateway.mcp;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import pl.aiwcorpo.mcp.gateway.audit.AuditEvent;
import pl.aiwcorpo.mcp.gateway.audit.AuditLog;
import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.auth.PublicUrls;
import pl.aiwcorpo.mcp.gateway.authz.ToolAccess;
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
import pl.aiwcorpo.mcp.gateway.killswitch.KillSwitches;
import pl.aiwcorpo.mcp.gateway.ratelimit.EndpointAuditThrottle;
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
import pl.aiwcorpo.mcp.manifest.EndpointFilter;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * tools/list and tools/call through the gateway: names {@code <system>__<tool>} towards the client (C5), the approved
 * tools of the servers, the endpoint (route and filter of its query) and the authorizer as the filter, the broker
 * credential, then the server. The filter only narrows: a tool is visible and callable only when the endpoint leaves it
 * and the authorizer allows it for the caller. Every tools/call leaves one {@code policy_decision} and one
 * {@code tool_call} event (C8).
 */
public class McpGatewayService {

    private static final Logger log = LoggerFactory.getLogger(McpGatewayService.class);
    private static final int MAX_LIST_PAGES = 20;
    private static final Duration DEFAULT_READ_WAIT_LIMIT = Duration.ofSeconds(60);

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
    private final EndpointAuditThrottle endpointAudit;
    private final ToolsListCursor listCursor;
    private final KillSwitches killSwitches;
    private final ToolAccess access;
    private final Duration toolsListTimeout;
    private final Duration readWaitLimit;
    private final Clock clock;
    private final Map<String, CompletableFuture<DefinitionGuard.Reading>> readsInFlight = new ConcurrentHashMap<>();
    private final ExecutorService listReaders = Executors.newVirtualThreadPerTaskExecutor();

    public McpGatewayService(ServerRegistry registry, PublicUrls urls, UpstreamSessions upstream,
                             CredentialService credentials, ToolAuthorizer authorizer, AuditLog audit, ToolErrors errors,
                             JsonMapper json, MeterRegistry meters, String componentId, ConfirmationService confirmations,
                             RegistryService registryService, DefinitionGuard definitionGuard, RateLimiter rateLimiter,
                             RateLimitAuditThrottle rateLimitAudit, EndpointAuditThrottle endpointAudit, ToolsListCursor listCursor,
                             KillSwitches killSwitches, ToolAccess access, Duration toolsListTimeout, Clock clock) {
        this(registry, urls, upstream, credentials, authorizer, audit, errors, json, meters, componentId, confirmations, registryService,
                definitionGuard, rateLimiter, rateLimitAudit, endpointAudit, listCursor, killSwitches, access, toolsListTimeout, clock,
                DEFAULT_READ_WAIT_LIMIT);
    }

    /** @param readWaitLimit the longest a call waits for the definitions read that another call has in flight */
    public McpGatewayService(ServerRegistry registry, PublicUrls urls, UpstreamSessions upstream,
                             CredentialService credentials, ToolAuthorizer authorizer, AuditLog audit, ToolErrors errors,
                             JsonMapper json, MeterRegistry meters, String componentId, ConfirmationService confirmations,
                             RegistryService registryService, DefinitionGuard definitionGuard, RateLimiter rateLimiter,
                             RateLimitAuditThrottle rateLimitAudit, EndpointAuditThrottle endpointAudit, ToolsListCursor listCursor,
                             KillSwitches killSwitches, ToolAccess access, Duration toolsListTimeout, Clock clock, Duration readWaitLimit) {
        this.readWaitLimit = readWaitLimit;
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
        this.endpointAudit = endpointAudit;
        this.listCursor = listCursor;
        this.killSwitches = killSwitches;
        this.access = access;
        this.toolsListTimeout = toolsListTimeout;
        this.clock = clock;
    }

    /**
     * The limits of the user and of the user's client for a request that is not a tool call (initialize, tools/list, ...). Empty means
     * go on; a refusal is audited as a policy decision (at most one event per user and reason in an interval) and becomes HTTP 429.
     */
    public Optional<RateLimiter.Limited> limitRequest(GatewayUser user, EndpointFilter filter, String requestId, String clientRequestId) {
        Optional<RateLimiter.Limited> limited = rateLimiter.check(user.sub(), user.client(), null, null);
        limited.ifPresent(l -> {
            meters.counter("mcp.gateway.requests.limited").increment();
            if (rateLimitAudit.due(user.sub(), l.reason())) {
                audit.emit(AuditEvent.of("policy_decision", requestId, componentId).clientRequestId(clientRequestId).user(user)
                        .filter(filter.isEmpty() ? null : filter.canonical()).decision("deny", l.reason()).policyRevision(authorizer.policyRevision())
                        .outcome(l.unavailable() ? "error" : "denied", l.unavailable() ? "upstream_unavailable" : "rate_limited"));
            }
        });
        return limited;
    }

    /**
     * A request the endpoint refused before it reached a method: a filter that does not parse ({@code invalid_filter}, no filter field
     * because nothing could be normalized), a session used on another route or with another filter ({@code filter_mismatch}) or a cursor
     * that is not ours ({@code invalid_cursor}). One policy_decision (C8); the client learns the reason from the HTTP answer only.
     */
    public void auditRefusedRequest(GatewayUser user, String requestId, String clientRequestId, String reason, String outcome,
                                    String canonicalFilter, String target) {
        // An authenticated client can repeat a refused request as fast as it likes: one event per user, reason and target in an interval
        // for the refusals it can repeat at will (CC-190, CC-191); the failure of the session store keeps the older limit by reason.
        boolean repeatable = !"upstream_unavailable".equals(reason);
        if (repeatable ? !endpointAudit.admit(user, reason, target) : !rateLimitAudit.due(user.sub(), reason)) {
            return;
        }
        audit.emit(AuditEvent.of("policy_decision", requestId, componentId).clientRequestId(clientRequestId).user(user)
                .filter(canonicalFilter).decision("deny", reason).policyRevision(authorizer.policyRevision()).outcome(outcome));
    }

    /**
     * The tools the user may call now through the endpoint, one page (CC-169, CC-181). The servers are read in parallel, each within
     * {@code toolsListTimeout}; a server that does not answer in time or cannot be read is left out of this list and nothing else is
     * concluded about it (CC-180).
     */
    public ObjectNode listTools(CallContext ctx, JsonNode cursorParam) throws RpcFailure {
        String after = null;
        if (cursorParam != null && !cursorParam.isMissingNode()) {
            Optional<String> opened = cursorParam.isString()
                    ? listCursor.open(ctx.user().sub(), ctx.filter().canonical(), cursorParam.asString(), clock.instant().getEpochSecond())
                    : Optional.empty();
            if (opened.isEmpty()) {
                auditRefusedRequest(ctx.user(), ctx.requestId(), ctx.clientRequestId(), "invalid_cursor", "error", ctx.auditFilter(),
                        cursorParam.isString() ? cursorParam.asString() : cursorParam.toString());
                throw new RpcFailure(-32602, "Invalid cursor", 400);
            }
            after = opened.get();
        }
        List<ToolsPage.Entry<ObjectNode>> entries = new ArrayList<>();
        Map<McpServer, Future<List<ToolsPage.Entry<ObjectNode>>>> reads = new LinkedHashMap<>();
        for (McpServer server : serversOf(ctx)) {
            if (touches(ctx.filter(), server)) {
                reads.put(server, listReaders.submit(() -> listFrom(ctx, server)));
            }
        }
        long deadline = System.nanoTime() + toolsListTimeout.toNanos();
        for (Map.Entry<McpServer, Future<List<ToolsPage.Entry<ObjectNode>>>> read : reads.entrySet()) {
            long started = System.nanoTime();
            try {
                entries.addAll(read.getValue().get(Math.max(0, deadline - started), TimeUnit.NANOSECONDS));
            } catch (TimeoutException e) {
                read.getValue().cancel(true);
                skipped(ctx, read.getKey(), "timeout");
            } catch (ExecutionException e) {
                skipped(ctx, read.getKey(), e.getCause() instanceof RpcFailure ? "unreadable" : "error");
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                read.getValue().cancel(true);
                throw new RpcFailure(-32603, "The request was interrupted.", 502);
            }
        }
        ToolsPage.Page<ObjectNode> page = ToolsPage.of(entries, after, ToolsPage.SIZE);
        ObjectNode result = json.createObjectNode();
        ArrayNode out = result.putArray("tools");
        page.entries().forEach(entry -> out.add(entry.value()));
        page.nextAfter().ifPresent(name -> result.put("nextCursor",
                listCursor.issue(ctx.user().sub(), ctx.filter().canonical(), name, clock.instant().getEpochSecond())));
        return result;
    }

    private void skipped(CallContext ctx, McpServer server, String reason) {
        meters.counter("mcp.gateway.tools.list.skipped", "server", server.serverId(), "reason", reason).increment();
        log.warn("tools/list rid={}: {} left out of the list ({})", ctx.requestId(), server.serverId(), reason);
    }

    /** Whether the filter can leave anything of this server; a server it excludes as a whole is not read. */
    private static boolean touches(EndpointFilter filter, McpServer server) {
        return filter.systems().map(systems -> systems.contains(server.system())).orElse(true)
                && !filter.exclude().map(excluded -> excluded.contains(server.system())).orElse(false);
    }

    private List<ToolsPage.Entry<ObjectNode>> listFrom(CallContext ctx, McpServer server) throws RpcFailure {
        List<ToolsPage.Entry<ObjectNode>> out = new ArrayList<>();
        List<ToolDefinition> inScope = server.tools().values().stream().filter(t -> throughEndpoint(ctx, server, t)).toList();
        // Cedar is asked once per tool that is switched on at all, all of them side by side: this is what a long list costs most.
        List<ToolDefinition> switchedOn = inScope.stream().filter(t -> enabled(server, t)).toList();
        List<Boolean> decisions = access.mayCall(ctx.user(), server, switchedOn);
        Map<String, Boolean> allowed = new LinkedHashMap<>();
        for (int i = 0; i < switchedOn.size(); i++) {
            allowed.put(switchedOn.get(i).name(), decisions.get(i));
        }
        // A server none of whose tools the user may list is not read at all.
        if (!allowed.containsValue(true)) {
            return out;
        }
        // The list the client sees is built from the approved definitions; the server's own list only decides which of them
        // may be shown now (CC-133).
        DefinitionGuard.Reading reading = definitions(ctx, server);
        for (ToolDefinition definition : inScope) {
            Verdict verdict = reading.verdicts().getOrDefault(definition.name(), Verdict.NOT_SERVED);
            if (ListedTools.listed(candidate(server, definition, verdict != Verdict.NOT_SERVED, verdict == Verdict.INTACT, allowed))) {
                out.add(new ToolsPage.Entry<>(server.qualifiedName(definition), listed(server, definition, definition.definition())));
            }
        }
        return out;
    }

    /** Neither the server, the tool nor an emergency switch turns the tool off; an unreadable store of the switches turns everything off (CC-194). */
    private boolean enabled(McpServer server, ToolDefinition tool) {
        return server.enabled() && !tool.disabled() && killSwitches.status(server.serverId(), tool.name()) == KillSwitches.Status.OFF;
    }

    private ListedTools.Candidate candidate(McpServer server, ToolDefinition tool, boolean served, boolean definitionMatches,
                                            Map<String, Boolean> allowed) {
        return new ListedTools.Candidate(server.qualifiedName(tool), tool.risk().name(), true, enabled(server, tool), served, definitionMatches,
                allowed.getOrDefault(tool.name(), false));
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
     * The tool list of the server as of the last read that is not older than the TTL, or a new read. A read that fails is no proof of
     * a change or of a missing tool, and it is no list either: the caller leaves the server out of a list and refuses a call, so that
     * nothing is shown or reaches a server whose definitions cannot be checked (CC-180).
     */
    private DefinitionGuard.Reading definitions(CallContext ctx, McpServer server) throws RpcFailure {
        Optional<DefinitionGuard.Reading> fresh = definitionGuard.fresh(server.serverId());
        if (fresh.isPresent()) {
            return fresh.get();
        }
        // One read per server is in flight at a time: N admitted calls that find the reading expired would otherwise send N
        // tools/list to the very server that is already under load. A failed flight fails its waiters and is not kept.
        CompletableFuture<DefinitionGuard.Reading> mine = new CompletableFuture<>();
        CompletableFuture<DefinitionGuard.Reading> running = readsInFlight.putIfAbsent(server.serverId(), mine);
        if (running != null) {
            return awaitRead(server, running);
        }
        try {
            Optional<DefinitionGuard.Reading> recorded = definitionGuard.fresh(server.serverId());
            DefinitionGuard.Reading reading = recorded.isPresent() ? recorded.get() : readDefinitionsNow(ctx, server);
            readsInFlight.remove(server.serverId(), mine);
            mine.complete(reading);
            return reading;
        } catch (RpcFailure | RuntimeException e) {
            log.warn("{}: the definitions could not be read: {}", server.serverId(), e.getClass().getSimpleName());
            readsInFlight.remove(server.serverId(), mine);
            mine.completeExceptionally(e);
            throw e instanceof RpcFailure failure ? failure : new RpcFailure(-32603, "upstream_unavailable: the MCP server is unavailable.", 502);
        } finally {
            readsInFlight.remove(server.serverId(), mine);
            mine.completeExceptionally(new IllegalStateException("the read ended without a result"));
        }
    }

    /**
     * Waits for the read in flight. The read ends by itself (every request of it is bound by the timeout of the upstream client, the body
     * included) and always completes the future, so a waiter normally fails exactly when the read fails and a shorter wait would refuse calls
     * the read is about to serve. {@code readWaitLimit} is only a backstop for a read that does not end: the waiter is refused, and the
     * stuck read is dropped so that the next call starts a new one instead of waiting behind it.
     */
    private DefinitionGuard.Reading awaitRead(McpServer server, CompletableFuture<DefinitionGuard.Reading> running) throws RpcFailure {
        try {
            return running.get(readWaitLimit.toMillis(), TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            readsInFlight.remove(server.serverId(), running);
            log.warn("{}: the definitions read in flight did not end in {} ms", server.serverId(), readWaitLimit.toMillis());
            throw new RpcFailure(-32603, "upstream_unavailable: the MCP server is unavailable.", 502);
        } catch (ExecutionException e) {
            if (e.getCause() instanceof RpcFailure failure) {
                throw failure;
            }
            throw new RpcFailure(-32603, "upstream_unavailable: the MCP server is unavailable.", 502);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("{}: the wait for the definitions was interrupted", server.serverId());
            throw new RpcFailure(-32603, "upstream_unavailable: the MCP server is unavailable.", 502);
        }
    }

    private DefinitionGuard.Reading readDefinitionsNow(CallContext ctx, McpServer server) throws RpcFailure {
        // A reading judged against approvals that changed meanwhile is dropped and made again; a server whose approvals keep
        // changing under the read is refused (fail-closed) rather than served from a stale verdict.
        for (int attempt = 0; attempt < 3; attempt++) {
            long generation = definitionGuard.generation(server.serverId());
            List<JsonNode> tools = readTools(ctx, server);
            Map<String, JsonNode> live = new LinkedHashMap<>();
            for (JsonNode tool : tools) {
                String name = tool.path("name").asString(null);
                if (name != null) {
                    live.putIfAbsent(name, tool);
                }
            }
            McpServer current = registry.find(server.serverId()).orElse(server);
            Map<String, Verdict> observed = registryService.observe(current, live, upstream.serverVersion(server.serverId()));
            // The policies a server evaluates with are part of what was approved: a server that presents others is blocked as a whole.
            Map<String, Verdict> verdicts = observed;
            RegistryService.PoliciesVerdict onPolicies = registryService.observePolicies(current);
            if (onPolicies == RegistryService.PoliciesVerdict.CHANGED || onPolicies == RegistryService.PoliciesVerdict.UNVERIFIED) {
                verdicts = new LinkedHashMap<>();
                for (String name : current.tools().keySet()) {
                    verdicts.put(name, onPolicies == RegistryService.PoliciesVerdict.CHANGED ? Verdict.POLICIES_CHANGED : Verdict.POLICIES_UNVERIFIED);
                }
            }
            Map<String, Verdict> judged = verdicts;
            Optional<DefinitionGuard.Reading> kept = definitionGuard.record(server.serverId(), generation, live,
                    upstream.serverVersion(server.serverId()), judged);
            if (kept.isPresent()) {
                judged.forEach((name, verdict) -> {
                    if (verdict != Verdict.INTACT) {
                        meters.counter("mcp.gateway.definition.mismatch", "server", server.serverId(), "reason", verdict.reason()).increment();
                        log.warn("{}: the tool {} is blocked ({}): {}", server.serverId(), name, verdict.reason(),
                                verdict == Verdict.CHANGED ? "the definition differs from the approved one"
                                        : verdict == Verdict.POLICIES_CHANGED ? "the policies of the server differ from the approved ones"
                                        : verdict == Verdict.POLICIES_UNVERIFIED ? "the policies of the server could not be verified"
                                        : "the server does not list it");
                    }
                });
                return kept.get();
            }
        }
        throw new RpcFailure(-32603, "upstream_unavailable: the definitions of the server keep changing.", 502);
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

    /** The servers behind the endpoint: all of them in the order of the list (by ServerId), or the one addressed. */
    private List<McpServer> serversOf(CallContext ctx) {
        Target target = ctx.target();
        if (!target.aggregateEndpoint()) {
            return List.of(target.server());
        }
        return registry.all().stream().sorted(java.util.Comparator.comparing(McpServer::serverId)).toList();
    }

    /** Neither the route nor the filter of the request leaves the tool out. */
    private static boolean throughEndpoint(CallContext ctx, McpServer server, ToolDefinition tool) {
        Target target = ctx.target();
        return (target.aggregateEndpoint() || server.serverId().equals(target.server().serverId()))
                && ctx.filter().allows(server.qualifiedName(tool), tool.risk().name());
    }

    /** What the checks of the call learned on the way, kept for the events. */
    private static final class CallState {
        boolean keepCredential = true;
        /** The refusal at the level of the tool came from a forbid, not from a missing grant: the audit says so (CC-198). */
        boolean forbidden;
        Verdict definition;
        Resolution resolution;
    }

    /**
     * The call, in the order of CC-178: the tool is known and Cedar allows it at the level of the tool (mayCall), the endpoint leaves
     * it visible, it is enabled, its server answers and presents the approved definition, the account is connected; only then the
     * decision of Cedar with the arguments, the confirmation gate and the server. What the endpoint cuts says nothing of the state of
     * the tool, of its server or of the account.
     */
    public ObjectNode callTool(CallContext ctx, JsonNode params) throws RpcFailure {
        long started = System.nanoTime();
        String clientName = params.path("name").asString(null);
        JsonNode arguments = params.has("arguments") ? params.get("arguments") : json.createObjectNode();
        if (clientName == null || !arguments.isObject()) {
            if (rateLimitAudit.due(ctx.user().sub(), "invalid_call")) {
                finish(ctx, ctx.target().server(), null, null, started, 0, "allow", null, "invalid_argument", null);
            }
            throw new RpcFailure(-32602, "tools/call needs a string name and object arguments.", 400);
        }
        int argsLength = json.writeValueAsString(arguments).getBytes(StandardCharsets.UTF_8).length;
        Optional<ServerRegistry.Resolved> resolved = registry.resolveForCall(clientName);
        McpServer addressed = ctx.target().server();
        // What the user may not call is decided before anything is counted for the tool: a limit of the tool that answers differently for
        // a tool that exists and one that does not would tell the user which is which (invariant 8).
        ToolDecision toolLevel = resolved.isEmpty() ? null
                : authorizer.toolLevel(ctx.user(), resolved.get().server(), resolved.get().tool());
        boolean mayCall = toolLevel != null && toolLevel.allowed();
        Optional<RateLimiter.Limited> limited = rateLimiter.check(ctx.user().sub(), ctx.user().client(),
                mayCall ? resolved.get().server().qualifiedName(resolved.get().tool()) : null,
                mayCall ? resolved.get().tool().risk() : null);
        if (limited.isPresent()) {
            return rateLimitedCall(ctx, mayCall ? resolved : Optional.empty(), limited.get(), started, argsLength);
        }
        if (resolved.isEmpty()) {
            if (!endpointAudit.admit(ctx.user(), "not_granted", clientName)) {
                count(addressed, null, "denied", "not_found_or_denied", System.nanoTime() - started);
                return errors.error("not_found_or_denied", ToolErrors.NOT_FOUND_OR_DENIED_MESSAGE);
            }
            decisionEvent(ctx, addressed, null, "deny", "not_granted", "not_found_or_denied");
            return finish(ctx, addressed, null, null, started, argsLength, "deny", "not_granted", null,
                    errors.error("not_found_or_denied", ToolErrors.NOT_FOUND_OR_DENIED_MESSAGE));
        }
        McpServer server = resolved.get().server();
        ToolDefinition tool = resolved.get().tool();
        if (!mayCall && ("policy_unavailable".equals(toolLevel.reason()) || "policy_error".equals(toolLevel.reason()))) {
            // Undecided is not denied: the client is told the service failed, and the audit says why.
            boolean unavailable = "policy_unavailable".equals(toolLevel.reason());
            String code = unavailable ? "upstream_unavailable" : "internal_error";
            decisionEvent(ctx, server, tool, "deny", toolLevel.reason(), code);
            return finish(ctx, server, tool, null, started, argsLength, "deny", toolLevel.reason(), null,
                    unavailable ? errors.error("upstream_unavailable", "The policy service is unavailable. Try again later.")
                            : errors.error("internal_error", "The call could not be completed."));
        }
        CallState state = new CallState();
        state.keepCredential = !tool.requiresConfirmation() || arguments.has("confirmation_code");
        state.forbidden = !mayCall && "policy_forbid".equals(toolLevel.reason());
        CallOrder.Verdict verdict = CallOrder.decide(mayCall, throughEndpoint(ctx, server, tool),
                () -> killSwitches.status(server.serverId(), tool.name()),
                () -> server.enabled() && !tool.disabled(),
                () -> readDefinitions(ctx, server, tool, state),
                () -> state.definition == null || state.definition == Verdict.INTACT,
                () -> resolveCredential(ctx, server, tool, state));
        if (!verdict.passes()) {
            return refuse(ctx, server, tool, verdict, state, started, argsLength);
        }
        if (state.resolution != null) {
            ObjectNode failure = credentialFailure(ctx, server, tool, state.resolution, started, argsLength);
            if (failure != null) {
                return failure;
            }
        }
        Credential credential = state.resolution instanceof Resolution.Granted granted ? granted.credential() : null;
        ToolDecision decision = authorizer.decide(ctx.user(), server, tool, arguments);
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

        ObjectNode request = request("tools/call");
        ObjectNode upstreamParams = request.putObject("params");
        upstreamParams.put("name", tool.name());
        upstreamParams.set("arguments", arguments);
        JsonNode response;
        try {
            response = upstream.call(server, ctx.conversationKey(), ctx.user(), ctx.requestId(), request, tool.name(), credential,
                    tool.risk() == pl.aiwcorpo.mcp.gateway.server.Risk.READ_ONLY, tool.risk().name(), tool.action());
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

    /** Reads the definitions of a server that has an approved manifest; false when they cannot be read (the server is not available). */
    private boolean readDefinitions(CallContext ctx, McpServer server, ToolDefinition tool, CallState state) {
        try {
            state.definition = definitions(ctx, server).verdicts().getOrDefault(tool.name(), Verdict.NOT_SERVED);
            return true;
        } catch (RpcFailure failure) {
            return false;
        }
    }

    /**
     * Asks the broker for the credential the tool needs; false only when the account has no connection to the system. Any other
     * answer is kept in {@code state} and judged by {@link #credentialFailure}: it is no state of the account.
     */
    private boolean resolveCredential(CallContext ctx, McpServer server, ToolDefinition tool, CallState state) {
        if (!server.credential().required()) {
            return true;
        }
        state.resolution = credentials.resolve(ctx.user(), server.system(), server.credential(), tool.name(), ctx.requestId(),
                state.keepCredential);
        return !(state.resolution instanceof Resolution.Required);
    }

    /** The answer for a call that stopped before the decision with arguments, with the events it leaves. */
    private ObjectNode refuse(CallContext ctx, McpServer server, ToolDefinition tool, CallOrder.Verdict verdict, CallState state,
                              long started, int argsLength) {
        String reason = verdict.auditReason();
        if ("tool_disabled".equals(reason) && state.definition != null && state.definition != Verdict.INTACT) {
            reason = state.definition.reason();
        }
        if ("not_granted".equals(reason) && state.forbidden) {
            reason = "policy_forbid";
        }
        if (("not_granted".equals(reason) || "policy_forbid".equals(reason) || "filter_scope".equals(reason))
                && !endpointAudit.admit(ctx.user(), reason, server.qualifiedName(tool))) {
            count(server, tool, "denied", "not_found_or_denied", System.nanoTime() - started);
            return errors.error("not_found_or_denied", ToolErrors.NOT_FOUND_OR_DENIED_MESSAGE);
        }
        if ("credential_required".equals(reason)) {
            decisionEvent(ctx, server, tool, "allow", null, null);
            Resolution.Required required = (Resolution.Required) state.resolution;
            return finish(null, ctx, server, tool, null, started, argsLength, "allow", "credential_required", null,
                    errors.error("credential_required", "Connect your " + server.system() + " account in the portal.",
                            Map.of("system", required.system(), "connectUrl", urls.connectUrl(required.system()))));
        }
        ObjectNode error = switch (verdict.errorCode()) {
            case "tool_disabled" -> errors.error("tool_disabled", "This tool is not available.");
            case "upstream_unavailable" -> errors.error("upstream_unavailable", "The MCP server is unavailable. Try again later.");
            default -> errors.error("not_found_or_denied", ToolErrors.NOT_FOUND_OR_DENIED_MESSAGE);
        };
        decisionEvent(ctx, server, tool, "deny", reason, verdict.errorCode());
        return finish(ctx, server, tool, null, started, argsLength, "deny", reason, null, error);
    }

    /**
     * What the broker answered other than a credential or a missing connection: null when it gave a credential. These calls were let
     * through at the level of the tool, so the decision event says allow and the tool_call event carries the outcome.
     */
    private ObjectNode credentialFailure(CallContext ctx, McpServer server, ToolDefinition tool, Resolution resolution, long started,
                                         int argsLength) {
        switch (resolution) {
            case Resolution.Granted granted -> {
                return null;
            }
            case Resolution.Required required -> {
                return null;
            }
            case Resolution.Unavailable unavailable -> {
                decisionEvent(ctx, server, tool, "allow", null, null);
                return finish(null, ctx, server, tool, null, started, argsLength, "allow", null, null,
                        errors.error("upstream_unavailable", "The credential service is unavailable. Try again later."));
            }
            case Resolution.Denied denied -> {
                // The IdP refused the exchange: the user may not use this system. The answer names no group (CC-157). The gateway
                // let the call through, the IdP refused: tool_call allow with outcome denied (CC-165).
                decisionEvent(ctx, server, tool, "allow", null, null);
                resolveEvent(ctx, server, tool, denied.reason(), "denied", "access_denied", null);
                return finishDenied(null, ctx, server, tool, started, argsLength, denied.reason(),
                        errors.error("access_denied", "You are not allowed to use this tool."));
            }
            case Resolution.TypeMismatch mismatch -> {
                log.error("credential for rid={}: the broker returned the type {} which the configuration of {} does not allow",
                        ctx.requestId(), mismatch.returnedType(), server.system());
                decisionEvent(ctx, server, tool, "allow", null, null);
                resolveEvent(ctx, server, tool, "credential_type_mismatch", "error", "internal_error", mismatch.returnedType());
                return finish(null, ctx, server, tool, null, started, argsLength, "allow", null, null,
                        errors.error("internal_error", "The call could not be completed."));
            }
            case Resolution.Failed failed -> {
                log.error("credential for rid={} failed: {}", ctx.requestId(), failed.reason());
                decisionEvent(ctx, server, tool, "allow", null, null);
                if ("system_not_configured".equals(failed.reason())) {
                    // A defect of the installation, not of the request: the client sees internal_error, the audit says why (CC-158).
                    resolveEvent(ctx, server, tool, "system_not_configured", "error", "internal_error", null);
                }
                return finish(null, ctx, server, tool, null, started, argsLength, "allow", null, null,
                        errors.error("internal_error", "The call could not be completed."));
            }
        }
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
        if (!OperationDescription.listsEveryArgument(withoutCode)) {
            return new Confirmed(finish(ctx, server, tool, null, started, argsLength, "allow", null, "invalid_argument",
                    errors.error("invalid_argument", "A destructive call takes at most " + OperationDescription.MAX_ARGUMENTS
                            + " arguments, so that the confirmation can show all of them.")), null, null);
        }
        if (!OperationDescription.hashedExactly(withoutCode)) {
            return new Confirmed(finish(ctx, server, tool, null, started, argsLength, "allow", null, "invalid_argument",
                    errors.error("invalid_argument", "An integer in the arguments of a destructive call must lie between "
                            + "-9007199254740991 and 9007199254740991.")), null, null);
        }
        ConfirmationRules.Operation operation = new ConfirmationRules.Operation(server.serverId(), tool.name(),
                tool.risk().name(), OperationDescription.argumentsHash(withoutCode));
        PendingCall.Display display = OperationDescription.of(json, server.qualifiedName(tool), server.system(), withoutCode,
                tool.resourceRefs());
        ConfirmationService.CallInfo info = new ConfirmationService.CallInfo(ctx.user(), ctx.requestId(), ctx.clientRequestId(),
                ctx.auditFilter(), server.serverId(), tool.name(), operation, display);
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
            return upstream.call(server, ctx.conversationKey(), ctx.user(), ctx.requestId(), request, tool, credential, true);
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
    private void resolveEvent(CallContext ctx, McpServer server, ToolDefinition tool, String reason, String outcome, String errorCode,
                              String credentialType) {
        audit.emit(base(ctx, server, "credential_resolve", tool).reason(reason).credentialType(credentialType).outcome(outcome, errorCode));
    }

    /** The call was allowed and the system refused it: decision allow, outcome denied (CC-165). */
    private ObjectNode finishDenied(String callKey, CallContext ctx, McpServer server, ToolDefinition tool, long startedNanos,
                                    int argsLength, String reason, ObjectNode result) {
        long latencyNanos = System.nanoTime() - startedNanos;
        audit.emit(base(ctx, server, "tool_call", tool).risk(tool.risk().name()).decision("allow", reason)
                .policyRevision(authorizer.policyRevision()).outcome("denied", errors.codeOf(result))
                .latencyMs(latencyNanos / 1_000_000).argsLength(argsLength).callKey(callKey));
        count(server, tool, "denied", errors.codeOf(result), latencyNanos);
        return result;
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
     * {@code server} is null only for a tool outside the configuration called on {@code /mcp}.
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
        String serverTag = server == null ? "none" : server.serverId();
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
                .filter(ctx.auditFilter())
                .server(server == null ? null : server.serverId())
                .tool(tool == null ? null : tool.name());
    }
}
