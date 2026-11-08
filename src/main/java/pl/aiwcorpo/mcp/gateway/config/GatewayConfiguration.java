package pl.aiwcorpo.mcp.gateway.config;

import java.nio.file.Path;
import java.time.Clock;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.core.Ordered;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.transaction.PlatformTransactionManager;

import io.lettuce.core.RedisURI;
import jakarta.servlet.DispatcherType;
import io.micrometer.core.instrument.MeterRegistry;
import pl.aiwcorpo.mcp.gateway.admin.AdminController;
import pl.aiwcorpo.mcp.gateway.admin.ClientCertificateVerifier;
import pl.aiwcorpo.mcp.gateway.activity.ActivityAggregator;
import pl.aiwcorpo.mcp.gateway.activity.ActivityCursor;
import pl.aiwcorpo.mcp.gateway.activity.ActivityRecorder;
import pl.aiwcorpo.mcp.gateway.activity.ActivityRetention;
import pl.aiwcorpo.mcp.gateway.activity.ActivityService;
import pl.aiwcorpo.mcp.gateway.activity.ActivityStore;
import pl.aiwcorpo.mcp.gateway.admin.ActivityController;
import pl.aiwcorpo.mcp.gateway.audit.AuditLog;
import pl.aiwcorpo.mcp.gateway.admin.RegistryController;
import pl.aiwcorpo.mcp.gateway.registry.ChangeCounter;
import pl.aiwcorpo.mcp.gateway.stream.ToolStreams;
import pl.aiwcorpo.mcp.gateway.stream.UserToolLists;
import pl.aiwcorpo.mcp.gateway.registry.ChangeWatcher;
import pl.aiwcorpo.mcp.gateway.registry.DefinitionCheck;
import pl.aiwcorpo.mcp.gateway.killswitch.KillSwitchHealth;
import pl.aiwcorpo.mcp.gateway.killswitch.KillSwitchStore;
import pl.aiwcorpo.mcp.gateway.killswitch.KillSwitches;
import pl.aiwcorpo.mcp.gateway.admin.KillSwitchController;
import pl.aiwcorpo.mcp.gateway.registry.DefinitionGuard;
import pl.aiwcorpo.mcp.gateway.registry.ManifestFetcher;
import pl.aiwcorpo.mcp.gateway.registry.ManifestValidator;
import pl.aiwcorpo.mcp.gateway.registry.RegistryBootstrap;
import pl.aiwcorpo.mcp.gateway.registry.RegistryService;
import pl.aiwcorpo.mcp.gateway.registry.RegistryStore;
import pl.aiwcorpo.mcp.gateway.admin.ConfirmationAdminController;
import pl.aiwcorpo.mcp.gateway.confirm.ConfirmationService;
import pl.aiwcorpo.mcp.gateway.confirm.ConfirmationStore;
import pl.aiwcorpo.mcp.gateway.confirm.RedisConfirmationStore;
import pl.aiwcorpo.mcp.gateway.auth.PublicUrls;
import pl.aiwcorpo.mcp.gateway.auth.ResourceMetadata;
import pl.aiwcorpo.mcp.gateway.authz.CedarToolAuthorizer;
import pl.aiwcorpo.mcp.gateway.admin.FreshMfa;
import pl.aiwcorpo.mcp.gateway.admin.PolicyController;
import pl.aiwcorpo.mcp.gateway.admin.ServerController;
import pl.aiwcorpo.mcp.gateway.policy.PolicyDataStore;
import pl.aiwcorpo.mcp.gateway.policy.PolicyService;
import pl.aiwcorpo.mcp.gateway.registry.DevBootstrap;
import pl.aiwcorpo.mcp.gateway.registry.ServerAdmin;
import pl.aiwcorpo.mcp.gateway.registry.ServerChecks;
import pl.aiwcorpo.mcp.gateway.link.PolicyDataPusher;
import pl.aiwcorpo.mcp.gateway.link.ServerLinks;
import pl.aiwcorpo.mcp.gateway.net.AddressPolicy;
import pl.aiwcorpo.mcp.gateway.tls.ServerTls;
import pl.aiwcorpo.mcp.gateway.authz.ToolAccess;
import pl.aiwcorpo.mcp.gateway.authz.ToolAuthorizer;
import pl.aiwcorpo.mcp.gateway.broker.BrokerClient;
import pl.aiwcorpo.mcp.gateway.broker.CredentialCache;
import pl.aiwcorpo.mcp.gateway.broker.CredentialService;
import pl.aiwcorpo.mcp.gateway.broker.InvalidationListener;
import pl.aiwcorpo.mcp.gateway.broker.SystemsCheck;
import pl.aiwcorpo.mcp.gateway.broker.TokenExchangeClient;
import pl.aiwcorpo.mcp.gateway.edge.JsonErrorReportValveCustomizer;
import pl.aiwcorpo.mcp.gateway.edge.PublicEdgeFilter;
import pl.aiwcorpo.mcp.gateway.edge.ConcurrencyLimitFilter;
import pl.aiwcorpo.mcp.gateway.edge.RemovedRouteFilter;
import pl.aiwcorpo.mcp.gateway.edge.WellKnownGuard;
import pl.aiwcorpo.mcp.gateway.jwt.InternalPortFilter;
import pl.aiwcorpo.mcp.gateway.jwt.InternalTokenIssuer;
import pl.aiwcorpo.mcp.gateway.jwt.SigningKeys;
import pl.aiwcorpo.mcp.gateway.mcp.ClientSessionStore;
import pl.aiwcorpo.mcp.gateway.mcp.McpGatewayService;
import pl.aiwcorpo.mcp.gateway.ratelimit.EndpointAuditThrottle;
import pl.aiwcorpo.mcp.gateway.mcp.ToolsListCursor;
import pl.aiwcorpo.mcp.gateway.mcp.ToolErrors;
import pl.aiwcorpo.mcp.gateway.server.ServerRegistry;
import pl.aiwcorpo.mcp.gateway.tls.InternalTls;
import pl.aiwcorpo.mcp.gateway.upstream.StreamableHttpClient;
import pl.aiwcorpo.mcp.gateway.upstream.UpstreamSessions;
import tools.jackson.databind.json.JsonMapper;

@Configuration
public class GatewayConfiguration {

    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }

    @Bean
    JsonMapper gatewayJson() {
        return JsonMapper.builder().build();
    }

    @Bean
    @DependsOn("devstackGuard")
    ServerRegistry serverRegistry(MeterRegistry meters) {
        ServerRegistry registry = new ServerRegistry();
        registry.bindTo(meters);
        return registry;
    }

    @Bean
    @DependsOn("devstackGuard")
    PublicUrls publicUrls(GatewayProperties properties) {
        return new PublicUrls(properties.publicUrl(), properties.allowPlainHttp());
    }

    @Bean
    ResourceMetadata resourceMetadata(PublicUrls urls) {
        return new ResourceMetadata(urls);
    }

    @Bean
    InternalConnector internalConnector(GatewayProperties properties) {
        return new InternalConnector(properties.internalEndpoint().port(), properties.tls().keystore(),
                properties.tls().storePassword());
    }

    @Bean
    ClientCertificateVerifier clientCertificateVerifier(GatewayProperties properties) {
        return new ClientCertificateVerifier(Path.of(properties.tls().truststore()), properties.tls().storePassword().toCharArray());
    }

    @Bean
    JsonErrorReportValveCustomizer jsonErrorReportValveCustomizer() {
        return new JsonErrorReportValveCustomizer();
    }

    @Bean
    FilterRegistrationBean<PublicEdgeFilter> publicEdgeFilter() {
        FilterRegistrationBean<PublicEdgeFilter> registration = new FilterRegistrationBean<>(new PublicEdgeFilter());
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
        registration.setDispatcherTypes(DispatcherType.REQUEST, DispatcherType.ERROR, DispatcherType.ASYNC);
        return registration;
    }

    @Bean
    FilterRegistrationBean<InternalPortFilter> internalPortFilter(GatewayProperties properties) {
        FilterRegistrationBean<InternalPortFilter> registration =
                new FilterRegistrationBean<>(new InternalPortFilter(properties.internalEndpoint().port()));
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE + 1);
        return registration;
    }

    @Bean
    FilterRegistrationBean<WellKnownGuard> wellKnownGuard(ResourceMetadata metadata) {
        FilterRegistrationBean<WellKnownGuard> registration = new FilterRegistrationBean<>(new WellKnownGuard(metadata));
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE + 2);
        return registration;
    }

    /** After the authentication (the security chain is at -100), so that only authenticated requests take a place. */
    @Bean
    FilterRegistrationBean<ConcurrencyLimitFilter> concurrencyLimitFilter(GatewayProperties properties, MeterRegistry meters) {
        GatewayProperties.Mcp mcp = properties.mcp();
        FilterRegistrationBean<ConcurrencyLimitFilter> registration = new FilterRegistrationBean<>(new ConcurrencyLimitFilter(
                mcp.maxConcurrentRequests(), mcp.queueWait(), mcp.shedRetryAfterSeconds(), meters, System::nanoTime));
        registration.setOrder(-50);
        registration.setDispatcherTypes(DispatcherType.REQUEST);
        return registration;
    }

    /**
     * The queue of commands waiting for the shared Redis connection is bounded: when Redis answers slowly the commands of requests that
     * wait for it would otherwise pile up without limit (Lettuce's default). A full queue fails the command at once, which the callers
     * treat as an unavailable store (fail-closed).
     */
    @Bean
    org.springframework.boot.data.redis.autoconfigure.LettuceClientConfigurationBuilderCustomizer boundedRedisRequestQueue(GatewayProperties properties) {
        int size = Math.max(1024, properties.mcp().maxConcurrentRequests() * 16);
        return builder -> builder.clientOptions(io.lettuce.core.ClientOptions.builder().requestQueueSize(size).build());
    }

    @Bean
    FilterRegistrationBean<RemovedRouteFilter> removedRouteFilter() {
        FilterRegistrationBean<RemovedRouteFilter> registration = new FilterRegistrationBean<>(new RemovedRouteFilter());
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE + 3);
        return registration;
    }

    @Bean
    AdminController adminController(ServerRegistry registry, ToolAuthorizer authorizer, JsonMapper gatewayJson,
                                    GatewayProperties properties, DefinitionGuard definitionGuard, KillSwitches killSwitches) {
        return new AdminController(registry, authorizer, gatewayJson, properties.componentId(), definitionGuard, killSwitches);
    }

    @Bean
    ChangeCounter changeCounter(JdbcClient jdbc) {
        return new ChangeCounter(jdbc);
    }

    @Bean
    KillSwitchStore killSwitchStore(JdbcClient jdbc, PlatformTransactionManager transactions, ChangeCounter changes) {
        return new KillSwitchStore(jdbc, transactions, changes);
    }

    @Bean
    KillSwitches killSwitches(KillSwitchStore store, GatewayProperties properties, MeterRegistry meters) {
        return new KillSwitches(store::all, properties.mcp().killSwitchCacheTtl(), System::nanoTime, meters);
    }

    @Bean
    KillSwitchHealth killSwitchHealth(KillSwitches killSwitches) {
        return new KillSwitchHealth(killSwitches);
    }

    @Bean
    KillSwitchController killSwitchController(KillSwitchStore store, KillSwitches killSwitches, ServerRegistry servers, AuditLog audit,
                                              GatewayProperties properties, JsonMapper gatewayJson) {
        return new KillSwitchController(store, killSwitches, servers, audit, properties.componentId(), gatewayJson, killSwitches::refresh);
    }

    @Bean
    UserToolLists userToolLists(ServerRegistry servers, ToolAccess access, KillSwitches killSwitches, DefinitionGuard guard) {
        return new UserToolLists(servers, access, killSwitches, guard);
    }

    /**
     * Whatever may change a list wakes the streams: the registry (a registration, an approval, a change made on another instance), an
     * emergency switch, the definitions a server presents, the policies (CC-192).
     */
    @Bean
    ToolStreams toolStreams(UserToolLists lists, GatewayProperties properties, MeterRegistry meters, ClientSessionStore sessions,
                            JsonMapper gatewayJson, RegistryService registry, KillSwitches killSwitches, DefinitionGuard guard,
                            PolicyService policies) {
        ToolStreams streams = new ToolStreams(lists, properties.mcp().sseHeartbeatInterval(), java.time.Duration.ofSeconds(1),
                System::currentTimeMillis, meters, id -> sessions.find(id).isPresent(), gatewayJson,
                properties.mcp().maxOpenStreams(), properties.mcp().streamRecomputeParallelism(), java.time.Duration.ofMillis(100));
        registry.onChange(streams::changed);
        killSwitches.onChange(streams::changed);
        guard.onVerdictChange(streams::changed);
        policies.onChange(() -> {
            lists.policiesChanged();
            streams.changed();
        });
        return streams;
    }

    @Bean
    ChangeWatcher changeWatcher(ChangeCounter counter, RegistryService registry, KillSwitches killSwitches, PolicyService policies,
                                GatewayProperties properties) {
        return new ChangeWatcher(counter, registry, killSwitches, policies, properties.mcp().changePollInterval(), java.util.List.of());
    }

    /** Created before anything that uses a relaxed setting: the start is refused here, not after a bundle was pulled over http. */
    @Bean
    DevstackGuard devstackGuard(GatewayProperties properties, org.springframework.core.env.Environment environment) {
        return DevstackGuard.check(properties, environment, System.getenv());
    }

    @Bean
    io.micrometer.core.instrument.binder.MeterBinder devstackMetric(org.springframework.core.env.Environment environment) {
        return registry -> DevstackGuard.bindMetric(environment, registry);
    }

    @Bean
    @DependsOn("devstackGuard")
    SigningKeys signingKeys(GatewayProperties properties, org.springframework.core.env.Environment environment) {
        GatewayProperties.InternalJwt jwt = properties.internalJwt();
        return SigningKeys.load(jwt.keysFile(), jwt.activeKid(), jwt.allowTestKeys(), DevstackGuard.devstackActive(environment));
    }

    @Bean
    PolicyDataStore policyDataStore(JdbcClient jdbc, JsonMapper gatewayJson) {
        return new PolicyDataStore(jdbc, gatewayJson);
    }

    /** Reads the policy data before the first request: without it every decision is a deny (policy_unavailable). */
    @Bean
    @DependsOn("devstackGuard")
    PolicyService policyService(RegistryStore store, PolicyDataStore data, AuditLog audit, JsonMapper gatewayJson, GatewayProperties properties) {
        return new PolicyService(store, data, audit, properties.componentId(), gatewayJson, properties.allowedClients()).start();
    }

    @Bean
    ToolAuthorizer toolAuthorizer(PolicyService policies, JsonMapper gatewayJson) {
        return new CedarToolAuthorizer(policies, gatewayJson);
    }

    @Bean
    ToolAccess toolAccess(ToolAuthorizer authorizer) {
        return new ToolAccess(authorizer);
    }

    @Bean
    InternalTokenIssuer internalTokenIssuer(SigningKeys keys, GatewayProperties properties, ToolAuthorizer authorizer,
                                            Clock clock) {
        return new InternalTokenIssuer(keys, properties.internalJwt().issuer(), properties.internalJwt().lifetime(),
                authorizer::policyRevision, clock);
    }

    @Bean
    InternalTls internalTls(GatewayProperties properties) {
        GatewayProperties.Tls tls = properties.tls();
        return new InternalTls(Path.of(tls.keystore()), Path.of(tls.truststore()), tls.storePassword().toCharArray());
    }

    @Bean
    BrokerClient brokerClient(GatewayProperties properties, InternalTls tls, InternalTokenIssuer tokens, JsonMapper gatewayJson) {
        GatewayProperties.Broker broker = properties.broker();
        if (!"https".equals(broker.url().getScheme())) {
            throw new IllegalStateException("gateway.broker.url must be https (mTLS, C4)");
        }
        return new BrokerClient(broker.url(), tls.clientFor(broker.tlsName(), broker.timeout()), tokens, gatewayJson,
                broker.timeout());
    }

    @Bean
    @DependsOn("devstackGuard")
    TokenExchangeClient tokenExchangeClient(GatewayProperties properties, JsonMapper gatewayJson) {
        GatewayProperties.Oidc oidc = properties.oidc();
        if (oidc.tokenUri() != null && !"https".equals(oidc.tokenUri().getScheme()) && !properties.allowPlainHttp()) {
            // Only token-exchange systems need it; refusing here would block servers that do not.
            org.slf4j.LoggerFactory.getLogger(GatewayConfiguration.class)
                    .warn("gateway.oidc.token-uri is not https: token exchange disabled (gateway.allow-plain-http=false)");
            return new TokenExchangeClient(null, null, null, oidc.exchangeAudience(), oidc.exchangeScope(),
                    java.net.http.HttpClient.newHttpClient(), gatewayJson, properties.broker().timeout());
        }
        return new TokenExchangeClient(oidc.tokenUri(), oidc.clientId(), oidc.clientSecret(), oidc.exchangeAudience(),
                oidc.exchangeScope(), java.net.http.HttpClient.newBuilder()
                        .followRedirects(java.net.http.HttpClient.Redirect.NEVER).build(),
                gatewayJson, properties.broker().timeout());
    }

    @Bean
    CredentialCache credentialCache(GatewayProperties properties, Clock clock, MeterRegistry meters) {
        CredentialCache cache = new CredentialCache(properties.broker().maxCacheTtl(), clock);
        cache.bindTo(meters);
        return cache;
    }

    @Bean
    InvalidationListener invalidationListener(GatewayProperties properties, CredentialCache cache, JsonMapper gatewayJson) {
        GatewayProperties.Redis redis = properties.redis();
        RedisURI.Builder uri = RedisURI.builder().withHost(redis.host()).withPort(redis.port())
                .withTimeout(java.time.Duration.ofSeconds(2));
        if (redis.password() != null && !redis.password().isEmpty()) {
            if (redis.username() != null && !redis.username().isEmpty()) {
                uri.withAuthentication(redis.username(), redis.password().toCharArray());
            } else {
                uri.withPassword(redis.password().toCharArray());
            }
        }
        return new InvalidationListener(uri.build(), redis.invalidationChannel(), cache, gatewayJson, redis.healthInterval());
    }

    @Bean
    CredentialService credentialService(BrokerClient broker, TokenExchangeClient exchange, CredentialCache cache,
                                        InvalidationListener invalidations, MeterRegistry meters) {
        return new CredentialService(broker, exchange, cache, invalidations::live, meters);
    }

    @Bean
    @ConditionalOnProperty(name = "gateway.broker.check-systems-at-startup", havingValue = "true", matchIfMissing = true)
    SystemsCheck systemsCheck(BrokerClient broker, ServerRegistry servers) {
        return new SystemsCheck(broker, servers);
    }

    @Bean
    @DependsOn("devstackGuard")
    AddressPolicy addressPolicy(GatewayProperties properties) {
        return new AddressPolicy(properties.servers().allowLoopback());
    }

    @Bean
    @DependsOn("devstackGuard")
    ServerTls serverTls(GatewayProperties properties) {
        String bundle = properties.servers().trustedCas();
        return new ServerTls(bundle == null || bundle.isBlank() ? null : Path.of(bundle));
    }

    @Bean
    ServerLinks serverLinks(AddressPolicy addresses, ServerTls serverTls, InternalTokenIssuer tokens, JsonMapper gatewayJson) {
        return new ServerLinks(addresses, serverTls, tokens, gatewayJson);
    }

    @Bean
    PolicyDataPusher policyDataPusher(PolicyService policies, ServerRegistry servers, ServerLinks links, JsonMapper gatewayJson,
                                      GatewayProperties properties) {
        return new PolicyDataPusher(policies, servers, links, gatewayJson, properties.servers().loopPoll(),
                properties.servers().policyDataPushInterval(), java.time.Duration.ofSeconds(10), System::nanoTime);
    }

    @Bean
    UpstreamSessions upstreamSessions(GatewayProperties properties, ServerLinks links, PolicyDataPusher policyData,
                                      InternalTokenIssuer tokens, JsonMapper gatewayJson, Clock clock) {
        GatewayProperties.Upstream upstream = properties.upstream();
        return new UpstreamSessions(server -> new StreamableHttpClient(server.internalUrl(),
                links.client(server.connection().tlsMode(), server.connection().fingerprint()), gatewayJson, upstream.timeout(),
                upstream.maxResponseBytes(), () -> links.checkAddress(server.internalUrl()).map(refusal -> refusal.message())),
                policyData::push, tokens, gatewayJson, properties.sessions().upstreamIdleTimeout(), clock, properties.componentId(),
                properties.version());
    }

    @Bean
    ClientSessionStore clientSessionStore(StringRedisTemplate redis, JsonMapper gatewayJson, GatewayProperties properties) {
        return new ClientSessionStore(redis, gatewayJson, properties.redis().keyPrefix(),
                properties.sessions().clientIdleTimeout());
    }

    @Bean
    AuditLog auditLog() {
        return new AuditLog();
    }

    @Bean
    ToolErrors toolErrors(JsonMapper gatewayJson) {
        return new ToolErrors(gatewayJson);
    }

    @Bean
    ActivityStore activityStore(JdbcClient jdbc, JsonMapper gatewayJson) {
        return new ActivityStore(jdbc, gatewayJson);
    }

    @Bean
    ActivityRecorder activityRecorder(ActivityStore store, AuditLog audit, MeterRegistry meters) {
        ActivityRecorder recorder = new ActivityRecorder(store, meters);
        audit.listen(recorder::record);
        return recorder;
    }

    @Bean
    ActivityService activityService(ActivityStore store, JsonMapper gatewayJson, Clock clock, GatewayProperties properties) {
        return new ActivityService(store, new ActivityAggregator(gatewayJson), clock, properties.activity().retention());
    }

    /** Key of the cursor MAC: shared by all instances (M4 HA); without one a random key is made at start and cursors die with it. */
    @Bean
    ActivityCursor activityCursor(GatewayProperties properties, JsonMapper gatewayJson) {
        String configured = properties.activity().cursorKey();
        byte[] key = configured == null || configured.isBlank() ? randomKey() : configured.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        return new ActivityCursor(key, gatewayJson);
    }

    private static byte[] randomKey() {
        byte[] key = new byte[32];
        new java.security.SecureRandom().nextBytes(key);
        return key;
    }

    /** Key of the tools/list cursor MAC: shared by all instances (HA); the dev stack may leave it empty and get one per process. */
    @Bean
    ToolsListCursor toolsListCursor(GatewayProperties properties, JsonMapper gatewayJson) {
        String configured = properties.mcp().listCursorKey();
        byte[] key = configured == null || configured.isBlank() ? randomKey() : configured.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        return new ToolsListCursor(key, gatewayJson);
    }

    /** One event per user, reason and target in an interval for the refusals a client can repeat (CC-190, CC-191). */
    @Bean
    EndpointAuditThrottle endpointAuditThrottle(GatewayProperties properties, MeterRegistry meters, AuditLog audit, ToolAuthorizer authorizer) {
        return new EndpointAuditThrottle(properties.rateLimit().auditInterval(), properties.audit().throttleMaxTargetsPerUser(),
                System::currentTimeMillis, meters, audit, properties.componentId(), authorizer::policyRevision);
    }

    @Bean
    ActivityController activityController(ActivityService activity, ActivityCursor cursors, Clock clock, JsonMapper gatewayJson) {
        return new ActivityController(activity, cursors, clock, gatewayJson);
    }

    @Bean
    ActivityRetention activityRetention(ActivityStore store, Clock clock, GatewayProperties properties) {
        return new ActivityRetention(store, clock, properties.activity().retention());
    }

    @Bean
    ConfirmationStore confirmationStore(StringRedisTemplate redis, JsonMapper gatewayJson, GatewayProperties properties) {
        GatewayProperties.Redis config = properties.redis();
        org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory dedicated = null;
        if (config.waitReplicas() > 0) {
            org.springframework.data.redis.connection.RedisStandaloneConfiguration standalone =
                    new org.springframework.data.redis.connection.RedisStandaloneConfiguration(config.host(), config.port());
            if (config.username() != null && !config.username().isEmpty()) {
                standalone.setUsername(config.username());
            }
            if (config.password() != null && !config.password().isEmpty()) {
                standalone.setPassword(config.password());
            }
            dedicated = new org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory(standalone,
                    org.springframework.data.redis.connection.lettuce.LettuceClientConfiguration.builder()
                            .commandTimeout(java.time.Duration.ofSeconds(2)).build());
            dedicated.setShareNativeConnection(false);
            dedicated.afterPropertiesSet();
        }
        return new RedisConfirmationStore(redis, gatewayJson, config.keyPrefix(), config.waitReplicas(), config.waitTimeout(), dedicated);
    }

    @Bean
    ConfirmationService confirmationService(ConfirmationStore store, BrokerClient broker, AuditLog audit, Clock clock,
                                            GatewayProperties properties) {
        java.security.SecureRandom random = new java.security.SecureRandom();
        return new ConfirmationService(store, broker, audit, properties.componentId(), clock,
                properties.confirmations().pendingLimit(), () -> {
                    byte[] bytes = new byte[16];
                    random.nextBytes(bytes);
                    return "cnf_" + java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
                });
    }

    @Bean
    pl.aiwcorpo.mcp.gateway.offboarding.UserPurge userPurge(ConfirmationService confirmations,
                                                            ClientSessionStore sessions, UpstreamSessions upstream,
                                                            CredentialCache credentials, AuditLog audit, GatewayProperties properties,
                                                            ToolStreams streams) {
        return new pl.aiwcorpo.mcp.gateway.offboarding.UserPurge(confirmations, sessions, upstream, credentials, audit,
                properties.componentId(), streams);
    }

    @Bean
    pl.aiwcorpo.mcp.gateway.admin.OffboardingController offboardingController(pl.aiwcorpo.mcp.gateway.offboarding.UserPurge purge) {
        return new pl.aiwcorpo.mcp.gateway.admin.OffboardingController(purge);
    }

    @Bean
    ConfirmationAdminController confirmationAdminController(ConfirmationService confirmations, JsonMapper gatewayJson) {
        return new ConfirmationAdminController(confirmations, gatewayJson);
    }

    @Bean
    McpGatewayService mcpGatewayService(ServerRegistry registry, PublicUrls urls, UpstreamSessions upstream,
                                        CredentialService credentials, ToolAuthorizer authorizer, AuditLog audit,
                                        ToolErrors errors, JsonMapper gatewayJson, MeterRegistry meters,
                                        GatewayProperties properties, ConfirmationService confirmations,
                                        RegistryService registryService, DefinitionGuard definitionGuard,
                                        pl.aiwcorpo.mcp.gateway.ratelimit.RateLimiter rateLimiter,
                                        pl.aiwcorpo.mcp.gateway.ratelimit.RateLimitAuditThrottle rateLimitAudit,
                                        EndpointAuditThrottle endpointAudit, ToolsListCursor listCursor, KillSwitches killSwitches,
                                        ToolAccess toolAccess, Clock clock) {
        return new McpGatewayService(registry, urls, upstream, credentials, authorizer, audit, errors, gatewayJson, meters,
                properties.componentId(), confirmations, registryService, definitionGuard, rateLimiter, rateLimitAudit, endpointAudit, listCursor,
                killSwitches, toolAccess, properties.mcp().toolsListTimeout(), clock);
    }

    @Bean
    pl.aiwcorpo.mcp.gateway.ratelimit.RateLimiter rateLimiter(StringRedisTemplate redis, GatewayProperties properties, MeterRegistry meters) {
        return new pl.aiwcorpo.mcp.gateway.ratelimit.RateLimiter(redis, properties.redis().keyPrefix(), properties::rateLimit, meters);
    }

    @Bean
    pl.aiwcorpo.mcp.gateway.ratelimit.RateLimitAuditThrottle rateLimitAuditThrottle(GatewayProperties properties, MeterRegistry meters) {
        return new pl.aiwcorpo.mcp.gateway.ratelimit.RateLimitAuditThrottle(properties.rateLimit().auditInterval(), System::nanoTime, meters);
    }

    @Bean
    DefinitionCheck definitionCheck(JsonMapper gatewayJson) {
        return new DefinitionCheck(gatewayJson);
    }

    @Bean
    DefinitionGuard definitionGuard(Clock clock, GatewayProperties properties) {
        return new DefinitionGuard(clock, properties.registry().definitionCheckTtl());
    }

    @Bean
    RegistryStore registryStore(JdbcClient jdbc, JsonMapper gatewayJson, PlatformTransactionManager transactions, ChangeCounter changes,
                                PolicyDataStore policyData) {
        return new RegistryStore(jdbc, gatewayJson, transactions, changes, policyData);
    }

    @Bean
    ManifestFetcher manifestFetcher(ServerLinks links) {
        return new ManifestFetcher(links);
    }

    @Bean
    ManifestValidator manifestValidator(JsonMapper gatewayJson, org.springframework.core.env.Environment environment) {
        return new ManifestValidator(gatewayJson, DevstackGuard.devstackActive(environment));
    }

    @Bean
    RegistryService registryService(ServerRegistry servers, RegistryStore store, ManifestFetcher fetcher, ManifestValidator validator,
                                    DefinitionGuard guard, DefinitionCheck definitionCheck, AuditLog audit, GatewayProperties properties,
                                    JsonMapper gatewayJson, PolicyService policies) {
        RegistryService registry = new RegistryService(servers, store, validator, fetcher, guard, definitionCheck, audit,
                properties.componentId(), gatewayJson, policies, properties.registry().policyCheckFailures(),
                properties.registry().policyCheckMaxAge(), Clock.systemUTC());
        registry.load();
        return registry;
    }

    @Bean
    ServerChecks serverChecks(RegistryStore store, RegistryService registry, ServerLinks links, AuditLog audit, GatewayProperties properties,
                              Clock clock) {
        return new ServerChecks(store, registry, links, audit, properties.componentId(), clock, properties.servers().manifestPullInterval(),
                properties.servers().loopPoll());
    }

    @Bean
    ServerAdmin serverAdmin(RegistryStore store, RegistryService registry, ServerChecks checks, ManifestValidator validator,
                            AddressPolicy addresses, PolicyService policies, AuditLog audit, GatewayProperties properties,
                            JsonMapper gatewayJson, Clock clock, UpstreamSessions upstream) {
        return new ServerAdmin(store, registry, checks, validator, addresses, policies, audit, properties.componentId(), gatewayJson, clock,
                properties.servers().refreshInterval(), upstream::forgetServer);
    }

    @Bean
    ServerController serverController(ServerAdmin servers, JsonMapper gatewayJson, FreshMfa mfa) {
        return new ServerController(servers, gatewayJson, mfa);
    }

    @Bean
    FreshMfa freshMfa(GatewayProperties properties, Clock clock, AuditLog audit) {
        return new FreshMfa(properties.admin().mfaAcrValues(), properties.admin().mfaAmrValues(), clock, audit, properties.componentId());
    }

    @Bean
    PolicyController policyController(PolicyService policies, JsonMapper gatewayJson, FreshMfa mfa) {
        return new PolicyController(policies, gatewayJson, mfa);
    }

    /** Takes what other instances stored; in development it also approves what a server that was just added brought. */
    @Bean
    @DependsOn("devstackGuard")
    RegistryBootstrap registryBootstrap(RegistryService registry, ServerRegistry servers, ServerAdmin admin, RegistryStore store,
                                        JsonMapper gatewayJson, GatewayProperties properties) {
        Runnable development = properties.registry().bootstrapFromServer() ? new DevBootstrap(servers, registry, admin, store, gatewayJson) : null;
        return new RegistryBootstrap(registry, development, properties.registry().bootstrapRetry());
    }

    @Bean
    RegistryController registryController(RegistryService registry, ServerRegistry servers, JsonMapper gatewayJson, FreshMfa mfa) {
        return new RegistryController(registry, servers, gatewayJson, mfa);
    }
}
