package pl.aiwcorpo.mcp.gateway.config;

import java.nio.file.Path;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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
import pl.aiwcorpo.mcp.gateway.registry.DefinitionCheck;
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
import pl.aiwcorpo.mcp.gateway.authz.GroupToolAuthorizer;
import pl.aiwcorpo.mcp.gateway.authz.ToolAuthorizer;
import pl.aiwcorpo.mcp.gateway.broker.BrokerClient;
import pl.aiwcorpo.mcp.gateway.broker.CredentialCache;
import pl.aiwcorpo.mcp.gateway.broker.CredentialService;
import pl.aiwcorpo.mcp.gateway.broker.InvalidationListener;
import pl.aiwcorpo.mcp.gateway.broker.SystemsCheck;
import pl.aiwcorpo.mcp.gateway.broker.TokenExchangeClient;
import pl.aiwcorpo.mcp.gateway.edge.JsonErrorReportValveCustomizer;
import pl.aiwcorpo.mcp.gateway.edge.PublicEdgeFilter;
import pl.aiwcorpo.mcp.gateway.edge.WellKnownGuard;
import pl.aiwcorpo.mcp.gateway.jwt.InternalPortFilter;
import pl.aiwcorpo.mcp.gateway.jwt.InternalTokenIssuer;
import pl.aiwcorpo.mcp.gateway.jwt.SigningKeys;
import pl.aiwcorpo.mcp.gateway.mcp.ClientSessionStore;
import pl.aiwcorpo.mcp.gateway.mcp.McpGatewayService;
import pl.aiwcorpo.mcp.gateway.mcp.ToolErrors;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.server.ServerRegistry;
import pl.aiwcorpo.mcp.gateway.tls.InternalTls;
import pl.aiwcorpo.mcp.gateway.upstream.StreamableHttpClient;
import pl.aiwcorpo.mcp.gateway.upstream.UpstreamSessions;
import pl.aiwcorpo.mcp.gateway.virtual.VirtualServerService;
import pl.aiwcorpo.mcp.gateway.virtual.VirtualServerStore;
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
    ServerRegistry serverRegistry(GatewayProperties properties) {
        return new ServerRegistry(properties.servers(), properties.registry().mode());
    }

    @Bean
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

    @Bean
    VirtualServerStore virtualServerStore(JdbcClient jdbc, JsonMapper gatewayJson, PlatformTransactionManager transactions) {
        return new VirtualServerStore(jdbc, gatewayJson, transactions);
    }

    @Bean
    VirtualServerService virtualServerService(VirtualServerStore store, ServerRegistry registry, ToolAuthorizer authorizer,
                                              GatewayProperties properties) {
        return new VirtualServerService(store, registry, authorizer, properties.virtualServers().maxPerUser());
    }

    @Bean
    AdminController adminController(ServerRegistry registry, ToolAuthorizer authorizer, VirtualServerService virtualServers,
                                    PublicUrls urls, AuditLog audit, JsonMapper gatewayJson, GatewayProperties properties,
                                    DefinitionGuard definitionGuard) {
        return new AdminController(registry, authorizer, virtualServers, urls, audit, gatewayJson, properties.componentId(),
                definitionGuard);
    }

    @Bean
    SigningKeys signingKeys(GatewayProperties properties) {
        GatewayProperties.InternalJwt jwt = properties.internalJwt();
        return SigningKeys.load(jwt.keysFile(), jwt.activeKid(), jwt.allowTestKeys());
    }

    @Bean
    ToolAuthorizer toolAuthorizer() {
        return new GroupToolAuthorizer();
    }

    @Bean
    InternalTokenIssuer internalTokenIssuer(SigningKeys keys, GatewayProperties properties, ToolAuthorizer authorizer,
                                            Clock clock) {
        return new InternalTokenIssuer(keys, properties.internalJwt().issuer(), properties.internalJwt().lifetime(),
                () -> authorizer.policyRevision() != null ? authorizer.policyRevision() : properties.policyRevision(), clock);
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
    CredentialCache credentialCache(GatewayProperties properties, Clock clock) {
        return new CredentialCache(properties.broker().maxCacheTtl(), clock);
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
    UpstreamSessions upstreamSessions(GatewayProperties properties, ServerRegistry servers, InternalTls tls,
                                      InternalTokenIssuer tokens, JsonMapper gatewayJson, Clock clock) {
        Map<String, StreamableHttpClient> clients = new LinkedHashMap<>();
        GatewayProperties.Upstream upstream = properties.upstream();
        for (McpServer server : servers.all()) {
            clients.put(server.serverId(), new StreamableHttpClient(server.internalUrl(),
                    tls.clientFor(server.tlsName(), java.time.Duration.ofSeconds(5)), gatewayJson, upstream.timeout(),
                    upstream.maxResponseBytes()));
        }
        return new UpstreamSessions(clients, tokens, gatewayJson, properties.sessions().upstreamIdleTimeout(), clock,
                properties.componentId(), properties.version());
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
    ActivityService activityService(ActivityStore store, JsonMapper gatewayJson, Clock clock) {
        return new ActivityService(store, new ActivityAggregator(gatewayJson), clock);
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

    @Bean
    ActivityController activityController(ActivityService activity, ActivityCursor cursors, Clock clock, JsonMapper gatewayJson) {
        return new ActivityController(activity, cursors, clock, gatewayJson);
    }

    @Bean
    ActivityRetention activityRetention(ActivityStore store, Clock clock) {
        return new ActivityRetention(store, clock);
    }

    @Bean
    ConfirmationStore confirmationStore(StringRedisTemplate redis, JsonMapper gatewayJson, GatewayProperties properties) {
        return new RedisConfirmationStore(redis, gatewayJson, properties.redis().keyPrefix());
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
    ConfirmationAdminController confirmationAdminController(ConfirmationService confirmations, JsonMapper gatewayJson) {
        return new ConfirmationAdminController(confirmations, gatewayJson);
    }

    @Bean
    McpGatewayService mcpGatewayService(ServerRegistry registry, PublicUrls urls, UpstreamSessions upstream,
                                        CredentialService credentials, ToolAuthorizer authorizer, AuditLog audit,
                                        ToolErrors errors, JsonMapper gatewayJson, MeterRegistry meters,
                                        GatewayProperties properties, ConfirmationService confirmations,
                                        DefinitionCheck definitionCheck, DefinitionGuard definitionGuard) {
        return new McpGatewayService(registry, urls, upstream, credentials, authorizer, audit, errors, gatewayJson, meters,
                properties.componentId(), confirmations, definitionCheck, definitionGuard);
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
    RegistryStore registryStore(JdbcClient jdbc, JsonMapper gatewayJson) {
        return new RegistryStore(jdbc, gatewayJson);
    }

    @Bean
    ManifestFetcher manifestFetcher(InternalTls tls, InternalTokenIssuer tokens, JsonMapper gatewayJson) {
        return new ManifestFetcher(tls, tokens, gatewayJson);
    }

    @Bean
    RegistryService registryService(ServerRegistry servers, RegistryStore store, ManifestFetcher fetcher, DefinitionGuard guard,
                                    JsonMapper gatewayJson) {
        RegistryService registry = new RegistryService(servers, store, new ManifestValidator(gatewayJson), fetcher, guard);
        registry.load();
        return registry;
    }

    /** Servers that wait for a manifest get the one they serve, retried until it works. */
    @Bean
    RegistryBootstrap registryBootstrap(RegistryService registry, GatewayProperties properties) {
        return new RegistryBootstrap(registry, properties.registry().bootstrapFromServer(), properties.registry().bootstrapRetry());
    }

    @Bean
    RegistryController registryController(RegistryService registry, ServerRegistry servers, JsonMapper gatewayJson) {
        return new RegistryController(registry, servers, gatewayJson);
    }
}
