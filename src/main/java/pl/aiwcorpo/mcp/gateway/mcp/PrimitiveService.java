package pl.aiwcorpo.mcp.gateway.mcp;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
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
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.micrometer.core.instrument.MeterRegistry;
import pl.aiwcorpo.mcp.cedar.entities.ResourceTypeDeclaration;
import pl.aiwcorpo.mcp.cedar.entities.ResourceTypes;
import pl.aiwcorpo.mcp.gateway.audit.AuditEvent;
import pl.aiwcorpo.mcp.gateway.audit.AuditLog;
import pl.aiwcorpo.mcp.gateway.auth.PublicUrls;
import pl.aiwcorpo.mcp.gateway.authz.ToolAuthorizer;
import pl.aiwcorpo.mcp.gateway.authz.ToolDecision;
import pl.aiwcorpo.mcp.gateway.broker.Credential;
import pl.aiwcorpo.mcp.gateway.broker.CredentialService;
import pl.aiwcorpo.mcp.gateway.broker.Resolution;
import pl.aiwcorpo.mcp.gateway.confirm.PendingCall;
import pl.aiwcorpo.mcp.gateway.jwt.UuidV7;
import pl.aiwcorpo.mcp.gateway.killswitch.KillSwitches;
import pl.aiwcorpo.mcp.gateway.primitive.ContractsVersion;
import pl.aiwcorpo.mcp.gateway.primitive.PrimitiveLists;
import pl.aiwcorpo.mcp.gateway.primitive.PromptGetOrder;
import pl.aiwcorpo.mcp.gateway.primitive.PromptRenderer;
import pl.aiwcorpo.mcp.gateway.primitive.ResourceContents;
import pl.aiwcorpo.mcp.gateway.primitive.ResourceReadOrder;
import pl.aiwcorpo.mcp.gateway.primitive.ResourceUris;
import pl.aiwcorpo.mcp.gateway.ratelimit.EndpointAuditThrottle;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.server.PromptDefinition;
import pl.aiwcorpo.mcp.gateway.server.ResourceDefinition;
import pl.aiwcorpo.mcp.gateway.server.ServerRegistry;
import pl.aiwcorpo.mcp.gateway.server.ToolRoute;
import pl.aiwcorpo.mcp.gateway.upstream.UpstreamException;
import pl.aiwcorpo.mcp.gateway.upstream.UpstreamSessions;
import pl.aiwcorpo.mcp.manifest.DefinitionHash;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * {@code resources/list}, {@code resources/templates/list}, {@code resources/read}, {@code prompts/list} and {@code prompts/get} (CC-259). The
 * lists are built from the approved entries of the registry and never from what a server lists; a server's own lists of resources are read
 * only to compare each entry with its approved definition, as {@code tools/list} is read for the tools. A prompt is composed here from the
 * approved messages of its manifest entry and no server is asked. A refusal of a resource at any step from the match of the URI to the
 * state of the entry is the same answer, -32602 {@code Resource not found} with the requested URI (D5), so the client cannot tell a missing
 * resource from a forbidden one; the audit says which it was. The content of a resource is data of the system and is passed on as the
 * server gave it once its shape is checked, never rewritten.
 */
public final class PrimitiveService {

    private static final Logger log = LoggerFactory.getLogger(PrimitiveService.class);
    private static final int MAX_LIST_PAGES = 20;
    private static final int MAX_READINGS = 10_000;
    private static final String UNAVAILABLE_MESSAGE = "Internal error";

    private final ServerRegistry registry;
    private final ToolAuthorizer authorizer;
    private final KillSwitches killSwitches;
    private final McpGatewayService service;
    private final AuditLog audit;
    private final EndpointAuditThrottle endpointAudit;
    private final UpstreamSessions upstream;
    private final CredentialService credentials;
    private final PublicUrls urls;
    private final ToolsListCursor cursors;
    private final JsonMapper json;
    private final MeterRegistry meters;
    private final Clock clock;
    private final String componentId;
    private final Duration listTimeout;
    private final Duration readingTtl;
    private final long resourceMaxBytes;
    private final Duration readWaitLimit;
    private final String brokerContractsVersion;
    private final Map<String, Reading> readings = new ConcurrentHashMap<>();
    private final Map<String, CompletableFuture<Reading>> readsInFlight = new ConcurrentHashMap<>();
    private final Map<String, Reading> lastOfServer = new ConcurrentHashMap<>();
    private volatile Runnable onReadingChange = () -> { };
    private final ExecutorService listReaders = Executors.newVirtualThreadPerTaskExecutor();

    /**
     * @param listTimeout the time one server has to answer the reading of its resource lists for a client's list (the one of tools/list)
     * @param readingTtl how long what a server listed is trusted (the one of the definitions of tools)
     * @param brokerContractsVersion the version of the broker the operator confirmed, null or empty when none
     */
    public PrimitiveService(ServerRegistry registry, ToolAuthorizer authorizer, KillSwitches killSwitches, McpGatewayService service, AuditLog audit,
                            EndpointAuditThrottle endpointAudit, UpstreamSessions upstream, CredentialService credentials, PublicUrls urls,
                            ToolsListCursor cursors, JsonMapper json, MeterRegistry meters, Clock clock, String componentId, Duration listTimeout,
                            Duration readingTtl, long resourceMaxBytes, String brokerContractsVersion) {
        this(registry, authorizer, killSwitches, service, audit, endpointAudit, upstream, credentials, urls, cursors, json, meters, clock, componentId,
                listTimeout, readingTtl, resourceMaxBytes, brokerContractsVersion, Duration.ofSeconds(60));
    }

    /** @param readWaitLimit the longest a list waits for the reading another has in flight */
    public PrimitiveService(ServerRegistry registry, ToolAuthorizer authorizer, KillSwitches killSwitches, McpGatewayService service, AuditLog audit,
                            EndpointAuditThrottle endpointAudit, UpstreamSessions upstream, CredentialService credentials, PublicUrls urls,
                            ToolsListCursor cursors, JsonMapper json, MeterRegistry meters, Clock clock, String componentId, Duration listTimeout,
                            Duration readingTtl, long resourceMaxBytes, String brokerContractsVersion, Duration readWaitLimit) {
        this.readWaitLimit = readWaitLimit;
        this.registry = registry;
        this.authorizer = authorizer;
        this.killSwitches = killSwitches;
        this.service = service;
        this.audit = audit;
        this.endpointAudit = endpointAudit;
        this.upstream = upstream;
        this.credentials = credentials;
        this.urls = urls;
        this.cursors = cursors;
        this.json = json;
        this.meters = meters;
        this.clock = clock;
        this.componentId = componentId;
        this.listTimeout = listTimeout;
        this.readingTtl = readingTtl;
        this.resourceMaxBytes = resourceMaxBytes;
        this.brokerContractsVersion = brokerContractsVersion;
    }

    /** A result larger than the response the upstream client reads could never be seen whole, so the limit of a resource may not exceed it. */
    public static void checkLimits(long resourceMaxBytes, long upstreamMaxResponseBytes) {
        if (resourceMaxBytes > upstreamMaxResponseBytes) {
            throw new IllegalStateException("gateway.mcp.resource-max-bytes (MCP_RESOURCE_MAX_BYTES) must not exceed gateway.upstream.max-response-bytes");
        }
    }

    // ---------------------------------------------------------------------------------------------------------------- lists

    public ObjectNode listResources(CallContext ctx, JsonNode cursor) throws RpcFailure {
        return list(ctx, cursor, PrimitiveLists.Kind.RESOURCES, ToolsListCursor.RESOURCES, "resources");
    }

    public ObjectNode listTemplates(CallContext ctx, JsonNode cursor) throws RpcFailure {
        return list(ctx, cursor, PrimitiveLists.Kind.TEMPLATES, ToolsListCursor.TEMPLATES, "resourceTemplates");
    }

    public ObjectNode listPrompts(CallContext ctx, JsonNode cursor) throws RpcFailure {
        return list(ctx, cursor, PrimitiveLists.Kind.PROMPTS, ToolsListCursor.PROMPTS, "prompts");
    }

    private ObjectNode list(CallContext ctx, JsonNode cursorParam, PrimitiveLists.Kind kind, String cursorKind, String field) throws RpcFailure {
        String after = null;
        if (cursorParam != null && !cursorParam.isMissingNode()) {
            Optional<String> opened = cursorParam.isString()
                    ? cursors.open(cursorKind, ctx.user().sub(), ctx.filter().canonical(), cursorParam.asString(), clock.instant().getEpochSecond())
                    : Optional.empty();
            if (opened.isEmpty()) {
                service.auditRefusedRequest(ctx.user(), ctx.requestId(), ctx.clientRequestId(), "invalid_cursor", "error", ctx.auditFilter(),
                        cursorParam.isString() ? cursorParam.asString() : cursorParam.toString());
                throw new RpcFailure(-32602, "Invalid cursor", 400);
            }
            after = opened.get();
        }
        List<ToolsPage.Entry<ObjectNode>> entries = new ArrayList<>();
        Map<McpServer, Future<List<ToolsPage.Entry<ObjectNode>>>> reads = new LinkedHashMap<>();
        for (McpServer server : serversOf(ctx)) {
            if (PrimitiveLists.throughFilter(ctx.filter(), server.system())) {
                reads.put(server, listReaders.submit(() -> listFrom(ctx, server, kind)));
            }
        }
        long deadline = System.nanoTime() + listTimeout.toNanos();
        for (Map.Entry<McpServer, Future<List<ToolsPage.Entry<ObjectNode>>>> read : reads.entrySet()) {
            try {
                entries.addAll(read.getValue().get(Math.max(0, deadline - System.nanoTime()), TimeUnit.NANOSECONDS));
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
        ArrayNode out = result.putArray(field);
        page.entries().forEach(entry -> out.add(entry.value()));
        page.nextAfter().ifPresent(name -> result.put("nextCursor",
                cursors.issue(cursorKind, ctx.user().sub(), ctx.filter().canonical(), name, clock.instant().getEpochSecond())));
        count(field, "ok");
        return result;
    }

    private void skipped(CallContext ctx, McpServer server, String reason) {
        meters.counter("mcp.gateway.primitives.list.skipped", "server", server.serverId(), "reason", reason).increment();
        log.warn("primitives list rid={}: {} left out of the list ({})", ctx.requestId(), server.serverId(), reason);
    }

    private List<ToolsPage.Entry<ObjectNode>> listFrom(CallContext ctx, McpServer server, PrimitiveLists.Kind kind) throws RpcFailure {
        boolean served = server.primitivesServed();
        List<PrimitiveLists.Entry> entries = new ArrayList<>();
        Map<String, ObjectNode> shown = new LinkedHashMap<>();
        List<Object> candidates = new ArrayList<>();
        if (kind == PrimitiveLists.Kind.PROMPTS) {
            candidates.addAll(server.primitives().prompts().values());
        } else {
            server.primitives().resources().values().stream().filter(r -> r.template() == (kind == PrimitiveLists.Kind.TEMPLATES)).forEach(candidates::add);
        }
        if (!served || candidates.isEmpty()) {
            return List.of();
        }
        Map<String, Boolean> allowed = new LinkedHashMap<>();
        for (Object candidate : candidates) {
            if (candidate instanceof PromptDefinition prompt) {
                allowed.put(prompt.name(), authorizer.mayGet(ctx.user(), server, prompt).allowed());
            } else if (candidate instanceof ResourceDefinition resource) {
                allowed.put(resource.name(), authorizer.mayRead(ctx.user(), server, resource, Map.of()).allowed());
            }
        }
        // A server none of whose entries the user may list is not read at all.
        if (!allowed.containsValue(true)) {
            return List.of();
        }
        boolean available = true;
        Reading reading = null;
        if (kind != PrimitiveLists.Kind.PROMPTS) {
            if (!ContractsVersion.supportsNewClaims(server.primitives().contractsVersion())) {
                available = false;
            } else {
                try {
                    reading = reading(ctx, server);
                } catch (RpcFailure failure) {
                    available = false;
                }
            }
        }
        for (Object candidate : candidates) {
            if (candidate instanceof PromptDefinition prompt) {
                boolean on = killSwitches.statusOfPrompt(server.serverId(), prompt.name()) == KillSwitches.Status.OFF && !prompt.changedSinceApproval();
                entries.add(new PrimitiveLists.Entry(prompt.name(), true, on, true, allowed.get(prompt.name())));
                shown.put(prompt.name(), promptListing(server, prompt));
            } else if (candidate instanceof ResourceDefinition resource) {
                boolean on = killSwitches.statusOfResource(server.serverId(), resource.name()) == KillSwitches.Status.OFF;
                boolean matches = reading != null && reading.matches(json, server, resource);
                entries.add(new PrimitiveLists.Entry(resource.name(), true, on, matches, allowed.get(resource.name())));
                shown.put(resource.name(), (ObjectNode) resource.definition().deepCopy());
            }
        }
        List<ToolsPage.Entry<ObjectNode>> out = new ArrayList<>();
        PrimitiveLists.visible(kind, List.of(new PrimitiveLists.ServerEntries(server.serverId(), server.system(), served, available, entries)))
                .forEach(listed -> out.add(new ToolsPage.Entry<>(listed.qualifiedName(), shown.get(listed.name()))));
        return out;
    }

    private ObjectNode promptListing(McpServer server, PromptDefinition prompt) {
        ObjectNode copy = (ObjectNode) prompt.definition().deepCopy();
        copy.put("name", server.qualifiedName(prompt));
        return copy;
    }

    /**
     * For the streams that announce a change: false when the server is too old to be read, or its last reading, of whatever age, found this
     * resource other than approved. A server never read counts as intact (no proof), and nothing is asked of it here.
     */
    public boolean lastKnownIntact(McpServer server, ResourceDefinition resource) {
        if (!ContractsVersion.supportsNewClaims(server.primitives().contractsVersion())) {
            return false;
        }
        Reading last = lastOfServer.get(server.serverId());
        return last == null || last.matches(json, server, resource);
    }

    /** The servers behind the endpoint: all of them in the order of the list (by ServerId), or the one addressed. */
    private List<McpServer> serversOf(CallContext ctx) {
        Target target = ctx.target();
        if (!target.aggregateEndpoint()) {
            return List.of(target.server());
        }
        return registry.all().stream().sorted(java.util.Comparator.comparing(McpServer::serverId)).toList();
    }

    // -------------------------------------------------------------------------------------------- what a server presents

    /** What a server listed as its resources and templates, by name, when. */
    private record Reading(Instant at, Map<String, JsonNode> resources, Map<String, JsonNode> templates, Map<String, Boolean> verdicts) {

        boolean matches(JsonMapper json, McpServer server, ResourceDefinition approved) {
            JsonNode live = (approved.template() ? templates : resources).get(approved.name());
            if (live == null || !live.isObject()) {
                return false;
            }
            try {
                return DefinitionHash.computePrimitive(approved.template() ? "resourceTemplate" : "resource", json.writeValueAsString(live),
                        json.writeValueAsString(approved.entry()), server.system(), approved.credentialJson()).equals(approved.definitionHash());
            } catch (RuntimeException e) {
                return false;
            }
        }
    }

    /**
     * The resource lists of the server as of a reading not older than the TTL, or a new one. One reading per server is in flight at a time and a
     * failed one fails its waiters at once, so that the lists of many clients neither send the server one request each nor queue behind a read that
     * hangs (the pattern of the definitions of tools). It is made with the token of the user who asked and kept for that user only: the service variant
     * of the token cannot be used inside a session (CC-070), and a server may list by who asks, so one user's view must not hide entries from another.
     * A server that cannot be read is no proof of a change: the caller skips it and concludes nothing else.
     */
    private Reading reading(CallContext ctx, McpServer server) throws RpcFailure {
        String key = server.serverId() + "|" + ctx.user().sub();
        Reading fresh = readings.get(key);
        if (fresh != null && Duration.between(fresh.at(), clock.instant()).compareTo(readingTtl) <= 0) {
            return fresh;
        }
        CompletableFuture<Reading> mine = new CompletableFuture<>();
        CompletableFuture<Reading> running = readsInFlight.putIfAbsent(key, mine);
        if (running != null) {
            return awaitReading(key, running);
        }
        try {
            Reading again = readings.get(key);
            Reading made = again != null && Duration.between(again.at(), clock.instant()).compareTo(readingTtl) <= 0 ? again : readNow(ctx, server, key);
            readsInFlight.remove(key, mine);
            mine.complete(made);
            return made;
        } catch (RpcFailure | RuntimeException e) {
            readsInFlight.remove(key, mine);
            mine.completeExceptionally(e);
            throw e instanceof RpcFailure failure ? failure : new RpcFailure(-32603, "upstream_unavailable: the MCP server is unavailable.", 502);
        } finally {
            readsInFlight.remove(key, mine);
            mine.completeExceptionally(new IllegalStateException("the read ended without a result"));
        }
    }

    private Reading readNow(CallContext ctx, McpServer server, String key) throws RpcFailure {
        Map<String, JsonNode> resources = readAll(ctx, server, "resources/list", "resources");
        Map<String, JsonNode> templates = readAll(ctx, server, "resources/templates/list", "resourceTemplates");
        Map<String, Boolean> verdicts = new LinkedHashMap<>();
        Reading probe = new Reading(clock.instant(), resources, templates, Map.of());
        server.primitives().resources().forEach((name, definition) -> verdicts.put(name, probe.matches(json, server, definition)));
        Reading made = new Reading(probe.at(), resources, templates, Map.copyOf(verdicts));
        readings.put(key, made);
        Reading before = lastOfServer.put(server.serverId(), made);
        // A reading that finds an entry in another state than the one before it (or in a bad state on the first) changes a list: streams are told.
        boolean differs = before == null ? verdicts.containsValue(false) : !before.verdicts().equals(made.verdicts());
        // A server that left the registry takes its readings with it, and the readings of users are kept for the most recent ones only.
        readings.keySet().removeIf(each -> registry.find(each.substring(0, each.indexOf('|'))).isEmpty());
        lastOfServer.keySet().removeIf(serverId -> registry.find(serverId).isEmpty());
        if (readings.size() > MAX_READINGS) {
            readings.entrySet().removeIf(each -> Duration.between(each.getValue().at(), clock.instant()).compareTo(readingTtl) > 0);
        }
        if (differs) {
            onReadingChange.run();
        }
        return made;
    }

    /** Waits for the reading in flight; it ends by itself (every request of it is bound by the upstream timeout), the limit is a backstop. */
    private Reading awaitReading(String key, CompletableFuture<Reading> running) throws RpcFailure {
        try {
            return running.get(readWaitLimit.toMillis(), TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            readsInFlight.remove(key, running);
            throw new RpcFailure(-32603, "upstream_unavailable: the MCP server is unavailable.", 502);
        } catch (ExecutionException e) {
            throw e.getCause() instanceof RpcFailure failure ? failure : new RpcFailure(-32603, "upstream_unavailable: the MCP server is unavailable.", 502);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RpcFailure(-32603, "upstream_unavailable: the MCP server is unavailable.", 502);
        }
    }

    /** Told when a reading of a server's resource lists changed what an entry is judged as. */
    public void onChange(Runnable listener) {
        this.onReadingChange = listener;
    }

    private Map<String, JsonNode> readAll(CallContext ctx, McpServer server, String method, String field) throws RpcFailure {
        Map<String, JsonNode> byName = new LinkedHashMap<>();
        String cursor = null;
        boolean complete = false;
        for (int page = 0; page < MAX_LIST_PAGES; page++) {
            ObjectNode request = request(method);
            if (cursor != null) {
                request.putObject("params").put("cursor", cursor);
            }
            JsonNode response = callUpstream(ctx, server, request);
            if (response.has("error")) {
                throw new RpcFailure(-32603, "The MCP server could not list its " + field + ".", 502);
            }
            response.path("result").path(field).forEach(item -> {
                if (item.isObject() && item.path("name").isString()) {
                    byName.putIfAbsent(item.path("name").asString(), item);
                }
            });
            cursor = response.path("result").path("nextCursor").asString(null);
            if (cursor == null || cursor.isEmpty()) {
                complete = true;
                break;
            }
        }
        if (!complete) {
            log.warn("{} returned more than {} pages of {}; list truncated", server.serverId(), MAX_LIST_PAGES, field);
        }
        return byName;
    }

    private JsonNode callUpstream(CallContext ctx, McpServer server, ObjectNode request) throws RpcFailure {
        try {
            return upstream.call(server, ctx.conversationKey(), ctx.user(), ctx.requestId(), request, null, null, true);
        } catch (UpstreamException e) {
            log.warn("{} rid={} to {} failed: {} {}", request.path("method").asString(), ctx.requestId(), server.serverId(), e.kind(), e.getMessage());
            throw new RpcFailure(-32603, "upstream_unavailable: the MCP server is unavailable.", 502);
        } catch (RuntimeException e) {
            log.error("{} rid={} to {} failed: {}", request.path("method").asString(), ctx.requestId(), server.serverId(), e.getClass().getName());
            throw new RpcFailure(-32603, "internal_error", 502);
        }
    }

    private ObjectNode request(String method) {
        ObjectNode request = json.createObjectNode();
        request.put("jsonrpc", "2.0");
        request.put("id", "gw-" + UuidV7.next());
        request.put("method", method);
        return request;
    }

    // ------------------------------------------------------------------------------------------------------ resources/read

    /** What a requested URI refers to among the approved entries: the entry, its server and the decoded variables, or why nothing. */
    private record Matched(McpServer server, ResourceDefinition resource, Map<String, String> variables, String missReason) {

        static Matched none(String reason) {
            return new Matched(null, null, Map.of(), reason);
        }

        boolean found() {
            return resource != null;
        }
    }

    /** What the checks of a read learned on the way and the steps after them need. */
    private static final class ReadState {
        Reading reading;
        boolean unreadable;
        Resolution resolution;
    }

    public ObjectNode readResource(CallContext ctx, JsonNode params) throws RpcFailure {
        long started = System.nanoTime();
        String uri = params.path("uri").asString(null);
        if (uri == null) {
            throw new RpcFailure(-32602, "resources/read needs a string uri.", 400);
        }
        Matched target = match(ctx, uri);
        if (!target.found()) {
            throw notFound(ctx, target.server(), null, Map.of(), uri, target.missReason(), started);
        }
        McpServer server = target.server();
        ResourceDefinition resource = target.resource();
        Map<String, String> variables = target.variables();
        ToolDecision decision = authorizer.mayRead(ctx.user(), server, resource, variables);
        String denial = decision.allowed() ? null : decision.reason();
        if ("policy_unavailable".equals(denial) || "policy_error".equals(denial)) {
            // Undecided is not denied: the client is told the service failed, the audit says why.
            throw failed(ctx, server, resource, variables, "deny", denial, "upstream_unavailable", started);
        }
        if ("invalid_argument".equals(denial)) {
            throw notFound(ctx, server, resource, variables, uri, "variable_invalid", started);
        }
        boolean needsCredential = resource.template() && server.credential().required();
        ReadState state = new ReadState();
        ResourceReadOrder.Verdict verdict = ResourceReadOrder.decide(decision.allowed(), "policy_forbid".equals(denial),
                PrimitiveLists.throughFilter(ctx.filter(), server.system()),
                () -> killSwitches.statusOfResource(server.serverId(), resource.name()),
                server::primitivesServed,
                () -> true,
                () -> definitionMatches(ctx, server, resource, state),
                () -> !state.unreadable,
                () -> ContractsVersion.supportsNewClaims(server.primitives().contractsVersion())
                        && (!needsCredential || ContractsVersion.supportsNewClaims(brokerContractsVersion)),
                () -> !ctx.user().isAgent() || !needsCredential,
                () -> connected(ctx, server, uri, needsCredential, state));
        if (!verdict.passes()) {
            String reason = denial != null && denial.startsWith("agent_") ? denial : verdict.reason();
            switch (verdict.answer()) {
                case NOT_FOUND -> throw notFound(ctx, server, resource, variables, uri, reason, started);
                case UPSTREAM_UNAVAILABLE -> throw failed(ctx, server, resource, variables,
                        "contracts_version_unsupported".equals(reason) ? "deny" : "allow", reason, "upstream_unavailable", started);
                case CREDENTIAL_REQUIRED -> throw credentialRequired(ctx, server, resource, variables, started, (Resolution.Required) state.resolution);
                case PASSES -> throw new IllegalStateException("a passing verdict is not a refusal");
            }
        }
        if (state.resolution != null && !(state.resolution instanceof Resolution.Granted)) {
            throw credentialProblem(ctx, server, resource, variables, uri, state.resolution, started);
        }
        Credential credential = state.resolution instanceof Resolution.Granted granted ? granted.credential() : null;
        ObjectNode request = request("resources/read");
        request.putObject("params").put("uri", uri);
        JsonNode response;
        try {
            response = upstream.call(server, ctx.conversationKey(), ctx.user(), ctx.requestId(), request, null, uri, credential, true, null, null,
                    () -> stillReadable(server, resource));
        } catch (UpstreamException e) {
            log.warn("resources/read rid={} to {} failed: {} {}", ctx.requestId(), server.serverId(), e.kind(), e.getMessage());
            throw failed(ctx, server, resource, variables, "allow", "upstream_unavailable", "upstream_unavailable", started);
        } catch (RuntimeException e) {
            // Only the class: JDK messages can quote header values, i.e. the credential.
            log.error("resources/read rid={} to {} failed: {}", ctx.requestId(), server.serverId(), e.getClass().getName());
            throw failed(ctx, server, resource, variables, "allow", "upstream_unavailable", "internal_error", started);
        }
        if (response.has("error") || !response.path("result").isObject()) {
            throw failed(ctx, server, resource, variables, "allow", "upstream_unavailable", "upstream_unavailable", started);
        }
        JsonNode result = response.path("result");
        if (result.has("resultType") && !"complete".equals(result.path("resultType").asString())) {
            // An InputRequiredResult is out of scope (CC-259): the server asked the client for something this gateway cannot carry.
            throw failed(ctx, server, resource, variables, "allow", "result_invalid", "upstream_unavailable", started);
        }
        JsonNode contents = result.path("contents");
        long bytes = ResourceContents.measure(contents);
        ResourceContents.Check check = ResourceContents.check(contents, uri, bytes, resourceMaxBytes);
        if (!check.passes()) {
            throw failed(ctx, server, resource, variables, "allow", check.reason(), "upstream_unavailable", started);
        }
        // Only what the contract names: an item's own _meta, annotations or any field a server adds are not passed on.
        ObjectNode item = json.createObjectNode();
        item.put("uri", uri);
        if (contents.get(0).path("mimeType").isString()) {
            item.put("mimeType", contents.get(0).path("mimeType").asString());
        }
        item.put("text", contents.get(0).path("text").asString());
        ObjectNode out = json.createObjectNode();
        out.putArray("contents").add(item);
        audit.emit(readEvent(ctx, server, resource, variables).decision("allow", null).policyRevision(authorizer.policyRevision())
                .outcome("ok", null).latencyMs(millis(started)).content(bytes, AuditEvent.sha256(contents.get(0).path("text").asString())));
        count("resources/read", "ok");
        return out;
    }

    /** The URI against the approved entries of the servers the endpoint reaches; static resources first, then the templates (CC-259). */
    private Matched match(CallContext ctx, String uri) {
        String scheme = schemeOf(uri);
        if (scheme == null) {
            return Matched.none("uri_no_match");
        }
        ResourceTypes types = authorizer.resourceTypes();
        McpServer owner = null;
        boolean undeclared = false;
        for (McpServer server : serversOf(ctx)) {
            if (!schemeBelongs(server, scheme)) {
                continue;
            }
            owner = server;
            List<ResourceUris.StaticEntry> statics = new ArrayList<>();
            List<ResourceUris.TemplateEntry> templates = new ArrayList<>();
            for (ResourceDefinition resource : server.primitives().resources().values()) {
                if (!resource.template()) {
                    statics.add(new ResourceUris.StaticEntry(resource.name(), resource.locator()));
                    continue;
                }
                Optional<List<ResourceUris.Variable>> variables = variablesOf(resource, types);
                if (variables.isEmpty()) {
                    undeclared = true;
                } else {
                    templates.add(new ResourceUris.TemplateEntry(resource.name(), resource.locator(), variables.get()));
                }
            }
            ResourceUris.Resolved resolved = ResourceUris.resolve(statics, templates, uri);
            if (resolved.found()) {
                return new Matched(server, server.primitives().resources().get(resolved.name()), resolved.variables(), null);
            }
            undeclared = undeclared || "variable_invalid".equals(resolved.reason());
        }
        // An entry nobody approved yet is known to the registry: the refusal is the same, the audit says it is a question of approval (CC-259, step 6).
        for (McpServer server : serversOf(ctx)) {
            if (schemeBelongs(server, scheme) && ResourceUris.resolve(staticsOf(server.primitives().waiting()),
                    templatesOf(server.primitives().waiting(), types), uri).found()) {
                return new Matched(server, null, Map.of(), "not_granted");
            }
        }
        return new Matched(owner, null, Map.of(), undeclared ? "variable_invalid" : "uri_no_match");
    }

    private static List<ResourceUris.StaticEntry> staticsOf(Map<String, ResourceDefinition> entries) {
        return entries.values().stream().filter(r -> !r.template()).map(r -> new ResourceUris.StaticEntry(r.name(), r.locator())).toList();
    }

    private List<ResourceUris.TemplateEntry> templatesOf(Map<String, ResourceDefinition> entries, ResourceTypes types) {
        List<ResourceUris.TemplateEntry> out = new ArrayList<>();
        for (ResourceDefinition resource : entries.values()) {
            if (resource.template()) {
                variablesOf(resource, types).ifPresent(variables -> out.add(new ResourceUris.TemplateEntry(resource.name(), resource.locator(), variables)));
            }
        }
        return out;
    }

    private static boolean schemeBelongs(McpServer server, String scheme) {
        return server.adapter() ? scheme.startsWith(server.system() + "+") : scheme.equals(server.system());
    }

    private static final Pattern SCHEME = Pattern.compile("^([a-z][a-z0-9]*(?:\\+[a-z][a-z0-9.+-]*)?)://");

    private static String schemeOf(String uri) {
        java.util.regex.Matcher found = SCHEME.matcher(uri);
        return found.find() ? found.group(1) : null;
    }

    /** The variables of a template with the pattern of their type; empty when a type is not declared by the policies in force (nothing can match). */
    private Optional<List<ResourceUris.Variable>> variablesOf(ResourceDefinition resource, ResourceTypes types) {
        List<ResourceUris.Variable> out = new ArrayList<>();
        for (ResourceDefinition.UriVariable variable : resource.variables()) {
            try {
                if (variable.type() == null) {
                    out.add(ResourceUris.Variable.of(variable.name(), variable.pattern(), variable.maxLength()));
                } else {
                    Optional<ResourceTypeDeclaration> declared = types.declaration(variable.type());
                    if (declared.isEmpty()) {
                        return Optional.empty();
                    }
                    out.add(ResourceUris.Variable.of(variable.name(), declared.get().idPattern(), ResourceTypes.MAX_ID_LENGTH));
                }
            } catch (java.util.regex.PatternSyntaxException e) {
                return Optional.empty();
            }
        }
        return Optional.of(out);
    }

    /**
     * Whether the server presents the approved definition of the entry. A server that cannot be read is not a mismatch but an unavailable server,
     * which the next step judges; one that is too old to take the claim of the read is not read at all, that refusal comes first.
     */
    private boolean definitionMatches(CallContext ctx, McpServer server, ResourceDefinition resource, ReadState state) {
        if (!ContractsVersion.supportsNewClaims(server.primitives().contractsVersion())) {
            return true;
        }
        try {
            state.reading = reading(ctx, server);
        } catch (RpcFailure failure) {
            state.unreadable = true;
            return true;
        }
        return state.reading.matches(json, server, resource);
    }

    private boolean connected(CallContext ctx, McpServer server, String uri, boolean needsCredential, ReadState state) {
        if (!needsCredential) {
            return true;
        }
        state.resolution = credentials.resolve(ctx.user(), server.system(), server.credential(), null, uri, ctx.requestId(), true);
        return !(state.resolution instanceof Resolution.Required);
    }

    private boolean stillReadable(McpServer server, ResourceDefinition resource) {
        return killSwitches.statusOfResource(server.serverId(), resource.name()) == KillSwitches.Status.OFF
                && registry.find(server.serverId()).filter(McpServer::primitivesServed)
                        .map(current -> current.primitives().resources().containsKey(resource.name())).orElse(false);
    }

    /** The one answer of D5: -32602 with the requested URI; the audit says which of the refusals it was. */
    private RpcFailure notFound(CallContext ctx, McpServer server, ResourceDefinition resource, Map<String, String> variables, String uri,
                                String reason, long started) {
        if (!repeatable(reason) || endpointAudit.admit(ctx.user(), reason, uri)) {
            audit.emit(readEvent(ctx, server, resource, variables).decision("deny", reason).policyRevision(authorizer.policyRevision())
                    .outcome("denied", "not_found_or_denied").latencyMs(millis(started)));
        }
        count("resources/read", "denied");
        ObjectNode data = json.createObjectNode();
        data.put("uri", uri);
        return new RpcFailure(-32602, "Resource not found", 200, data);
    }

    /** -32603 {@code upstream_unavailable} for whatever went wrong after the user was allowed to read; the audit keeps the real reason. */
    private RpcFailure failed(CallContext ctx, McpServer server, ResourceDefinition resource, Map<String, String> variables, String decision,
                              String reason, String errorCode, long started) {
        audit.emit(readEvent(ctx, server, resource, variables).decision(decision, reason).policyRevision(authorizer.policyRevision())
                .outcome("error", errorCode).latencyMs(millis(started)));
        count("resources/read", "error");
        ObjectNode data = json.createObjectNode();
        data.put("error", "upstream_unavailable");
        return new RpcFailure(-32603, UNAVAILABLE_MESSAGE, 200, data);
    }

    private RpcFailure credentialRequired(CallContext ctx, McpServer server, ResourceDefinition resource, Map<String, String> variables,
                                          long started, Resolution.Required required) {
        audit.emit(readEvent(ctx, server, resource, variables).decision("allow", "credential_required").policyRevision(authorizer.policyRevision())
                .outcome("error", "credential_required").latencyMs(millis(started)));
        count("resources/read", "error");
        ObjectNode data = json.createObjectNode();
        data.put("error", "credential_required");
        data.put("system", required.system());
        data.put("connectUrl", urls.connectUrl(required.system()));
        return new RpcFailure(-32603, UNAVAILABLE_MESSAGE, 200, data);
    }

    /** What the broker answered other than a credential or a missing connection: the IdP refused, which is a refusal of access; the rest is a failure. */
    private RpcFailure credentialProblem(CallContext ctx, McpServer server, ResourceDefinition resource, Map<String, String> variables, String uri,
                                         Resolution resolution, long started) {
        if (resolution instanceof Resolution.Denied) {
            return notFound(ctx, server, resource, variables, uri, "exchange_denied", started);
        }
        boolean unavailable = resolution instanceof Resolution.Unavailable;
        return failed(ctx, server, resource, variables, "allow", "upstream_unavailable", unavailable ? "upstream_unavailable" : "internal_error", started);
    }

    private AuditEvent readEvent(CallContext ctx, McpServer server, ResourceDefinition resource, Map<String, String> variables) {
        AuditEvent event = AuditEvent.of("resource_read", ctx.requestId(), componentId).clientRequestId(ctx.clientRequestId()).user(ctx.user())
                .filter(ctx.auditFilter()).server(server == null ? ctx.target().aggregateEndpoint() ? null : ctx.target().server().serverId()
                        : server.serverId());
        if (resource != null) {
            event.resourceTemplate(resource.name());
            ResourceTypes types = authorizer.resourceTypes();
            for (ResourceDefinition.UriVariable variable : resource.variables()) {
                if (variable.type() != null && !types.isValueOnly(variable.type()) && variables.containsKey(variable.name())) {
                    event.resource(new PendingCall.Resource(variable.type(), variables.get(variable.name()), null));
                    break;
                }
            }
        }
        return event;
    }

    /** Called by the endpoint when the modern header {@code Mcp-Name} is not the URI of the request (CC-259, step 2). */
    public void auditHeaderMismatch(CallContext ctx, String uri) {
        Matched target = uri == null ? Matched.none("uri_no_match") : match(ctx, uri);
        AuditEvent event = readEvent(ctx, target.server(), target.resource(), target.variables()).decision("deny", "header_mismatch")
                .policyRevision(authorizer.policyRevision()).outcome("error", "internal_error");
        if (endpointAudit.admit(ctx.user(), "header_mismatch", uri == null ? "" : uri)) {
            audit.emit(event);
        }
        count("resources/read", "error");
    }

    // -------------------------------------------------------------------------------------------------------- prompts/get

    public ObjectNode getPrompt(CallContext ctx, JsonNode params) throws RpcFailure {
        long started = System.nanoTime();
        String name = params.path("name").asString(null);
        JsonNode arguments = params.get("arguments");
        if (name == null) {
            throw new RpcFailure(-32602, "prompts/get needs a string name.", 400);
        }
        int argsLength = arguments == null ? 0 : json.writeValueAsString(arguments).getBytes(StandardCharsets.UTF_8).length;
        Optional<ToolRoute> route = ToolRoute.of(name, registry.all().stream().map(McpServer::system).toList());
        Optional<McpServer> found = route.flatMap(r -> registry.find(r.serverId()))
                .filter(server -> ctx.target().aggregateEndpoint() || server.serverId().equals(ctx.target().server().serverId()));
        Optional<PromptDefinition> prompt = found.flatMap(server -> Optional.ofNullable(server.primitives().prompts().get(route.get().tool())));
        if (prompt.isEmpty()) {
            throw promptDenied(ctx, found.orElse(null), null, name, "not_granted", started, argsLength);
        }
        McpServer server = found.get();
        PromptDefinition definition = prompt.get();
        ToolDecision decision = authorizer.mayGet(ctx.user(), server, definition);
        String denial = decision.allowed() ? null : decision.reason();
        if ("policy_unavailable".equals(denial) || "policy_error".equals(denial)) {
            throw promptFailed(ctx, server, definition, denial, started, argsLength);
        }
        PromptGetOrder.Verdict verdict = PromptGetOrder.decide(true, decision.allowed(), "policy_forbid".equals(denial),
                PrimitiveLists.throughFilter(ctx.filter(), server.system()),
                () -> killSwitches.statusOfPrompt(server.serverId(), definition.name()), server.primitivesServed(), definition.changedSinceApproval());
        if (!verdict.passes()) {
            if (verdict.answer() == PromptGetOrder.Answer.UPSTREAM_UNAVAILABLE) {
                throw promptFailed(ctx, server, definition, verdict.reason(), started, argsLength);
            }
            throw promptDenied(ctx, server, definition, name, denial != null && denial.startsWith("agent_") ? denial : verdict.reason(), started, argsLength);
        }
        ResourceTypes types = authorizer.resourceTypes();
        PromptRenderer.Outcome outcome = PromptRenderer.render(json, definition.entry(),
                type -> types.declaration(type).map(ResourceTypeDeclaration::idPattern), arguments);
        if (outcome instanceof PromptRenderer.Refused refused) {
            log.debug("prompts/get rid={}: {}", ctx.requestId(), refused.problem());
            audit.emit(promptEvent(ctx, server, definition).decision("deny", PromptRenderer.ARGUMENT_INVALID)
                    .policyRevision(authorizer.policyRevision()).outcome("error", "invalid_argument").latencyMs(millis(started))
                    .argsLength(argsLength).definitionHash(definition.definitionHash()));
            count("prompts/get", "error");
            throw promptNotFound(name);
        }
        PromptRenderer.Rendered rendered = (PromptRenderer.Rendered) outcome;
        ObjectNode result = json.createObjectNode();
        result.put("description", rendered.description());
        result.set("messages", rendered.messages());
        audit.emit(promptEvent(ctx, server, definition).decision("allow", null).policyRevision(authorizer.policyRevision()).outcome("ok", null)
                .latencyMs(millis(started)).argsLength(argsLength).definitionHash(definition.definitionHash()));
        count("prompts/get", "ok");
        return result;
    }

    private RpcFailure promptDenied(CallContext ctx, McpServer server, PromptDefinition prompt, String name, String reason, long started,
                                    int argsLength) {
        if (!repeatable(reason) || endpointAudit.admit(ctx.user(), reason, name)) {
            AuditEvent event = promptEvent(ctx, server, prompt).decision("deny", reason).policyRevision(authorizer.policyRevision())
                    .outcome("denied", "not_found_or_denied").latencyMs(millis(started)).argsLength(argsLength);
            if (prompt != null) {
                event.definitionHash(prompt.definitionHash());
            }
            audit.emit(event);
        }
        count("prompts/get", "denied");
        return promptNotFound(name);
    }

    private RpcFailure promptFailed(CallContext ctx, McpServer server, PromptDefinition prompt, String reason, long started, int argsLength) {
        audit.emit(promptEvent(ctx, server, prompt).decision("deny", reason).policyRevision(authorizer.policyRevision())
                .outcome("error", "upstream_unavailable").latencyMs(millis(started)).argsLength(argsLength));
        count("prompts/get", "error");
        ObjectNode data = json.createObjectNode();
        data.put("error", "upstream_unavailable");
        return new RpcFailure(-32603, UNAVAILABLE_MESSAGE, 200, data);
    }

    private RpcFailure promptNotFound(String name) {
        ObjectNode data = json.createObjectNode();
        data.put("name", name);
        return new RpcFailure(-32602, "Prompt not found", 200, data);
    }

    private AuditEvent promptEvent(CallContext ctx, McpServer server, PromptDefinition prompt) {
        AuditEvent event = AuditEvent.of("prompt_get", ctx.requestId(), componentId).clientRequestId(ctx.clientRequestId()).user(ctx.user())
                .filter(ctx.auditFilter()).server(server == null ? ctx.target().aggregateEndpoint() ? null : ctx.target().server().serverId()
                        : server.serverId());
        return prompt == null ? event : event.prompt(prompt.name());
    }

    // --------------------------------------------------------------------------------------------------------------- common

    private static boolean repeatable(String reason) {
        return switch (reason) {
            case "uri_no_match", "variable_invalid", "not_granted", "policy_forbid", "filter_scope", "agent_suspended", "agent_not_registered",
                    "principal_not_eligible" -> true;
            default -> false;
        };
    }

    private static long millis(long startedNanos) {
        return (System.nanoTime() - startedNanos) / 1_000_000;
    }

    private void count(String method, String outcome) {
        meters.counter("mcp.gateway.primitive.requests", "method", method, "outcome", outcome).increment();
    }
}
