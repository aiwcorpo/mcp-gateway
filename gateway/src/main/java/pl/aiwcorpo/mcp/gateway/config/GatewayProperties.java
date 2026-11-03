package pl.aiwcorpo.mcp.gateway.config;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

/** All gateway settings; environment variable names are in application.yml and README. */
@Validated
@ConfigurationProperties(prefix = "gateway")
public record GatewayProperties(
        @DefaultValue("mcp-gateway") @NotBlank String componentId,
        @DefaultValue("0.1.0") String version,
        /*
         * Public base URL as clients see it (publicBaseUrl of C5, CC-089): RFC 9728 resource, WWW-Authenticate,
         * MCP endpoint and portal addresses. Always configuration, never the Host of a request.
         */
        @NotNull URI publicUrl,
        @Valid @NotNull Oidc oidc,
        @Valid @NotNull InternalJwt internalJwt,
        @Valid @NotNull InternalEndpoint internalEndpoint,
        @Valid @NotNull Tls tls,
        @Valid @NotNull Broker broker,
        @Valid @NotNull Redis redis,
        @Valid @NotNull Sessions sessions,
        @Valid @NotNull Upstream upstream,
        @Valid @NotNull Admin admin,
        @DefaultValue @Valid Mcp mcp,
        @Valid @NotNull Metrics metrics,
        @DefaultValue @Valid Audit audit,
        @DefaultValue @Valid Confirmations confirmations,
        @DefaultValue @Valid Activity activity,
        @DefaultValue @Valid RateLimit rateLimit,
        @DefaultValue @Valid Registry registry,
        @Valid @NotNull Policy policy,
        /* Dev only: allows http for the IdP token endpoint (token exchange); never for the broker or servers. */
        @DefaultValue("false") boolean allowPlainHttp,
        @DefaultValue List<String> allowedOrigins,
        @Valid @NotEmpty Map<String, Server> servers) {

    public record Oidc(
            @NotBlank String issuer,
            @NotNull URI jwksUri,
            @DefaultValue("mcp-gateway") @NotBlank String audience,
            /* Authorization server advertised in RFC 9728 metadata; defaults to the issuer. */
            String authorizationServer,
            URI tokenUri,
            String clientId,
            String clientSecret,
            @DefaultValue("mcp-credential-broker") String exchangeAudience,
            @DefaultValue("mcp-credential-broker-audience") String exchangeScope,
            /* Longest accepted C1 token lifetime (exp - iat); C1 says at most 60 min. */
            @DefaultValue("60m") Duration maxTokenLifetime,
            /*
             * IdP key set (CC-124): at most one fetch per retry interval (also the Retry-After of the 503, 1..60 s);
             * a copy is current for freshFor and still used for usableFor when the IdP cannot be reached.
             */
            @DefaultValue("10s") Duration jwksRetryInterval,
            @DefaultValue("5m") Duration jwksFreshFor,
            @DefaultValue("1h") Duration jwksUsableFor,
            /*
             * Clients (azp) whose tokens belong to the admin API only. On /s/ and /v/ such a token is refused whatever its
             * audience, so that allowing the portal's calls in the policy never allows tool calls with the portal's token.
             */
            @DefaultValue("mcp-portal-bff") List<String> c5OnlyClients) {

        public String advertisedAuthorizationServer() {
            return authorizationServer == null || authorizationServer.isBlank() ? issuer : authorizationServer;
        }
    }

    public record InternalJwt(
            @DefaultValue("https://mcp-gateway.internal") @NotBlank String issuer,
            @DefaultValue("30s") Duration lifetime,
            /* JWKS file with the private signing keys; empty = two ephemeral keys generated at start. */
            String keysFile,
            /* kid of the signing key in keysFile; the other keys are only published. */
            String activeKid,
            @DefaultValue("false") boolean allowTestKeys) {
    }

    public record InternalEndpoint(
            @DefaultValue("8443") @Min(0) @Max(65535) int port) {
    }

    public record Tls(
            @NotBlank String keystore,
            @NotBlank String truststore,
            @NotBlank String storePassword) {
    }

    public record Broker(
            @NotNull URI url,
            @NotBlank String tlsName,
            @DefaultValue("5s") Duration timeout,
            @DefaultValue("60s") Duration maxCacheTtl,
            @DefaultValue("true") boolean checkSystemsAtStartup) {
    }

    public record Redis(
            @NotBlank String host,
            @DefaultValue("6379") int port,
            String username,
            String password,
            @DefaultValue("gw:") String keyPrefix,
            @DefaultValue("credential.invalidated") String invalidationChannel,
            /* PING interval on the invalidation subscription (half-open connection detection). */
            @DefaultValue("5s") Duration healthInterval,
            /*
             * Replicas that must have acknowledged a change of the confirmation state (WAIT) before the gateway goes on: a burned code or
             * a pending operation lost in a failover would let a code be used twice. 0 = no wait (one Redis, development). With more than
             * 0 a change that is not acknowledged within wait-timeout is answered as a store failure (fail-closed).
             */
            @DefaultValue("0") @Min(0) int waitReplicas,
            @DefaultValue("200ms") Duration waitTimeout) {
    }

    public record Sessions(
            @DefaultValue("1h") Duration clientIdleTimeout,
            @DefaultValue("30m") Duration upstreamIdleTimeout) {
    }

    public record Upstream(
            /* Total time for one request, headers and body (SSE included). */
            @DefaultValue("30s") Duration timeout,
            @DefaultValue("4194304") int maxResponseBytes) {
    }

    /** Admin API of C5 on the internal TLS port: mTLS client names and the audience of the BFF's user token. */
    public record Admin(
            @DefaultValue("mcp-gateway-admin") @NotBlank String audience,
            /* Client of the user token (azp): the BFF that exchanged it, nobody else. */
            @DefaultValue("mcp-portal-bff") @NotBlank String authorizedParty,
            /* Certificate names of the operations the contract gives to the BFF (x-allowed-client-cn). */
            @DefaultValue("mcp-portal-bff") @NotEmpty List<String> allowedClientCns,
            /* Certificate names of the offboarding call (x-allowed-client-cn of purgeUser). */
            @DefaultValue("mcp-offboarding") @NotEmpty List<String> offboardingClientCns) {
    }

    /** The client side of the aggregate endpoint (CC-180, CC-181). */
    public record Mcp(
            /* How long one server has to answer the read of its tools/list for a client's list; a server that does not is skipped. */
            @DefaultValue("3000ms") Duration toolsListTimeout,
            /* Key of the HMAC on the cursor of tools/list, at least 16 bytes; every instance must have the same one (HA). */
            String listCursorKey,
            /* The most MCP requests served at the same time; more are refused with 503 and Retry-After. Sized to the pools behind it (database, Redis). */
            @DefaultValue("128") int maxConcurrentRequests,
            /* How long a request waits for a place before it is refused. */
            @DefaultValue("100ms") Duration queueWait,
            @DefaultValue("2") int shedRetryAfterSeconds,
            /* Retry-After of the 503 given when the store of the MCP sessions does not answer (CC-199). */
            @DefaultValue("10") int sessionStoreRetryAfterSeconds,
            /* Comment line (: keepalive) on every open SSE stream, so that an intermediary does not close an idle one (CC-207). */
            @DefaultValue("15s") Duration sseHeartbeatInterval,
            /* How often every instance looks for changes made by another one: of the registry and of the emergency switches (CC-192, CC-194). */
            @DefaultValue("1s") Duration changePollInterval,
            /* The longest an instance trusts what it read of the emergency switches (CC-194, at most 5 s). */
            @DefaultValue("5s") Duration killSwitchCacheTtl,
            /* The most SSE streams open on one instance, both kinds together (decision of 2026-11-03); more are refused with 503 and Retry-After. No limit per user. */
            @DefaultValue("2000") int maxOpenStreams,
            /* How many streams compute their list at the same time after a change; the rest wait their turn, so a change does not stop the instance. */
            @DefaultValue("4") int streamRecomputeParallelism) {

        public Mcp {
            if (maxConcurrentRequests < 1 || shedRetryAfterSeconds < 1 || sessionStoreRetryAfterSeconds < 1 || queueWait == null || queueWait.isNegative()) {
                throw new IllegalArgumentException("gateway.mcp.max-concurrent-requests and shed-retry-after-seconds must be at least 1, queue-wait not negative");
            }
            if (maxOpenStreams < 1 || streamRecomputeParallelism < 1) {
                throw new IllegalArgumentException("gateway.mcp.max-open-streams (MCP_MAX_OPEN_STREAMS) and stream-recompute-parallelism must be at least 1");
            }
            if (sseHeartbeatInterval == null || sseHeartbeatInterval.compareTo(Duration.ofSeconds(1)) < 0
                    || sseHeartbeatInterval.compareTo(Duration.ofSeconds(60)) > 0) {
                throw new IllegalArgumentException("gateway.mcp.sse-heartbeat-interval (MCP_SSE_HEARTBEAT_INTERVAL) must be between 1 s and 60 s");
            }
            if (changePollInterval == null || changePollInterval.compareTo(Duration.ofMillis(100)) < 0
                    || changePollInterval.compareTo(Duration.ofSeconds(4)) > 0) {
                throw new IllegalArgumentException("gateway.mcp.change-poll-interval (MCP_CHANGE_POLL_INTERVAL) must be between 100 ms and 4 s: a change has to reach every instance within 5 s");
            }
            if (killSwitchCacheTtl == null || killSwitchCacheTtl.isNegative() || killSwitchCacheTtl.isZero()
                    || killSwitchCacheTtl.compareTo(Duration.ofSeconds(5)) > 0) {
                throw new IllegalArgumentException("gateway.mcp.kill-switch-cache-ttl (MCP_KILL_SWITCH_CACHE_TTL) must be between 1 ms and 5 s (CC-194)");
            }
            if (toolsListTimeout == null || toolsListTimeout.isNegative() || toolsListTimeout.isZero()) {
                throw new IllegalArgumentException("gateway.mcp.tools-list-timeout (MCP_TOOLS_LIST_TIMEOUT, milliseconds) must be positive");
            }
        }
    }

    /** Confirmations of DESTRUCTIVE calls (C11); TTL, attempts and the validity of a code are fixed by the contract. */
    public record Confirmations(
            /* Pending confirmations of a risk other than DESTRUCTIVE (required by policy) per user. */
            @DefaultValue("3") @Min(1) int pendingLimit) {
    }

    /**
     * Where the signed policy bundles come from (C7). The gateway does not start without a main bundle (CC-068). Keys are PEM
     * files of the Ed25519 public keys; identifiers starting with {@code test-} need {@code allowTestKeys} (CC-044).
     */
    public record Policy(
            @NotNull URI mainUrl,
            URI overridesUrl,
            @NotBlank String mainKeyId,
            @NotBlank String mainKeyFile,
            String overridesKeyId,
            String overridesKeyFile,
            @DefaultValue("false") boolean allowTestKeys,
            /* Directory of the rollback protection state (CC-066), one per instance; empty = in memory only. */
            String stateDir,
            /* Lowest revision ever accepted per channel (raised after an incident); empty = none. */
            String minimumMainRevision,
            String minimumOverridesRevision,
            @DefaultValue("30s") Duration mainInterval,
            @DefaultValue("5s") Duration overridesInterval,
            /* How long the start waits for the main bundle before the gateway gives up. */
            @DefaultValue("2m") Duration startupTimeout,
            /* After a restart with an overrides bundle active: how long to wait for it before an alarm and serving anyway. */
            @DefaultValue("1m") Duration overridesGrace) {
    }

    /** Approved definitions of the servers (C6). */
    public record Registry(
            /* required: a server serves only tools of an approved manifest; static: the tools of this configuration. */
            @DefaultValue("required") String mode,
            /*
             * A required server with no stored approval gets, once, the manifest it serves itself at /mcp-manifest (trust on
             * first use: the server then declares the risk of its own new tools). Development only; production registers
             * through CI.
             */
            @DefaultValue("false") boolean bootstrapFromServer,
            @DefaultValue("10s") Duration bootstrapRetry,
            /* How long the last check of the live definitions of a server counts before a call checks them again. */
            @DefaultValue("30s") Duration definitionCheckTtl) {
    }

    /** The activity views (C5 /activity/calls). */
    public record Activity(
            /* Key of the HMAC on the cursor, at least 16 bytes; empty = random per process (cursors do not survive a restart). */
            String cursorKey,
            /* How long the activity table keeps events (CC-134); a user who left keeps theirs until then. */
            @DefaultValue("30d") Duration retention) {
    }

    /**
     * Request limits (CC-135): per user, per (user, AI client) and per (user, tool), requests per window; a DESTRUCTIVE tool has its
     * own, lower limit and {@code tools} sets a limit for single tools by their name as the client sees it ({@code jira__delete_issue}).
     */
    public record RateLimit(
            @DefaultValue("true") boolean enabled,
            @DefaultValue("1m") Duration window,
            @DefaultValue("600") @Min(1) int perUser,
            @DefaultValue("300") @Min(1) int perClient,
            @DefaultValue("120") @Min(1) int perTool,
            @DefaultValue("10") @Min(1) int destructivePerTool,
            @DefaultValue Map<String, Integer> tools,
            /* One audit event per user and reason in this time; the rest is only counted. */
            @DefaultValue("10s") Duration auditInterval) {

        public RateLimit {
            if (window == null || window.compareTo(Duration.ofSeconds(1)) < 0 || window.compareTo(Duration.ofHours(1)) > 0) {
                throw new IllegalArgumentException("gateway.rate-limit.window must be between 1 s and 1 h");
            }
            if (destructivePerTool > perTool) {
                throw new IllegalArgumentException("gateway.rate-limit.destructive-per-tool must not exceed per-tool: a DESTRUCTIVE tool has the lower limit");
            }
            for (Map.Entry<String, Integer> own : tools.entrySet()) {
                if (own.getValue() == null || own.getValue() < 1) {
                    throw new IllegalArgumentException("gateway.rate-limit.tools." + own.getKey() + " must be at least 1");
                }
            }
        }
    }

    /** Caps on authentication events that cost the sender nothing (CC-120, CC-125). */
    public record Audit(
            /* Per second and per reason, for missing_token and malformed. */
            @DefaultValue("20") @Min(1) int unauthenticatedPerSecond,
            /* One client_certificate_rejected event per source address in this time on the admin port. */
            @DefaultValue("1m") Duration certificateRejectionInterval,
            /* Live keys (user, reason, target) of the audit of repeatable refusals per user and reason; further targets share one key (CC-191). */
            @DefaultValue("50") @Min(1) int throttleMaxTargetsPerUser) {
    }

    /** Prometheus endpoint on the internal port: only client certificates with these names (empty = nobody). */
    public record Metrics(
            @DefaultValue List<String> allowedClientCns) {
    }

    /** Static configuration of one MCP server (stand-in for the registry, C5). */
    public record Server(
            @NotBlank String system,
            @NotNull URI internalUrl,
            @DefaultValue("0.1.0") @NotBlank String version,
            @DefaultValue("true") boolean enabled,
            /* required or static; empty = gateway.registry.mode. */
            String manifest,
            @Valid @NotNull Credential credential,
            @Valid @NotNull Map<String, Tool> tools,
            /*
             * The server is a foreign MCP server behind an adapter (CC-193, CC-206): its manifest comes from the adapter on its own channel
             * (submitAdapterManifest), never from the pipeline, and an administrator classifies its tools. Needs manifest "required".
             * The tools listed here are only minimum risks for tools of the same name; a server built on the starter lists them all.
             */
            @DefaultValue("false") boolean adapter) {
    }

    public record Credential(
            @DefaultValue("true") boolean required,
            @DefaultValue List<String> acceptedTypes,
            @DefaultValue List<String> scopes,
            /* token-exchange systems need the user's token exchanged for the broker (C4 subjectToken). */
            @DefaultValue("false") boolean tokenExchange,
            /*
             * The credential type of the system for context.credentialType (CC-136), one of accepted-types. Optional when only
             * one type is accepted (or token-exchange is on); required when a user may hold several.
             */
            String type) {
    }

    /** {@code action} defaults from the risk (read, update, delete); {@code title} is optional (CC-082). */
    public record Tool(
            @NotBlank String risk,
            @NotBlank String description,
            String title,
            String action,
            @DefaultValue("false") boolean disabled,
            /* Resource identifiers among the arguments (C6 resourceRefs); the manifest replaces this from M3 K3 on. */
            @DefaultValue List<ResourceRefConfig> resourceRefs) {
    }

    public record ResourceRefConfig(@NotBlank String argument, @NotBlank String type) {
    }
}
