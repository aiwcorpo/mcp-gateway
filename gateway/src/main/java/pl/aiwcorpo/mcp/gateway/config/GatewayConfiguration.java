package pl.aiwcorpo.mcp.gateway.config;

import java.nio.file.Path;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.data.redis.core.StringRedisTemplate;

import io.lettuce.core.RedisURI;
import io.micrometer.core.instrument.MeterRegistry;
import pl.aiwcorpo.mcp.gateway.audit.AuditLog;
import pl.aiwcorpo.mcp.gateway.auth.ResourceMetadata;
import pl.aiwcorpo.mcp.gateway.authz.GroupToolAuthorizer;
import pl.aiwcorpo.mcp.gateway.authz.ToolAuthorizer;
import pl.aiwcorpo.mcp.gateway.broker.BrokerClient;
import pl.aiwcorpo.mcp.gateway.broker.CredentialCache;
import pl.aiwcorpo.mcp.gateway.broker.CredentialService;
import pl.aiwcorpo.mcp.gateway.broker.InvalidationListener;
import pl.aiwcorpo.mcp.gateway.broker.SystemsCheck;
import pl.aiwcorpo.mcp.gateway.broker.TokenExchangeClient;
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
        return new ServerRegistry(properties.servers());
    }

    @Bean
    ResourceMetadata resourceMetadata(GatewayProperties properties) {
        return new ResourceMetadata(properties.publicUrl());
    }

    @Bean
    InternalConnector internalConnector(GatewayProperties properties) {
        return new InternalConnector(properties.internalEndpoint().port(), properties.tls().keystore(),
                properties.tls().storePassword());
    }

    @Bean
    FilterRegistrationBean<InternalPortFilter> internalPortFilter(GatewayProperties properties) {
        FilterRegistrationBean<InternalPortFilter> registration =
                new FilterRegistrationBean<>(new InternalPortFilter(properties.internalEndpoint().port()));
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return registration;
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
    McpGatewayService mcpGatewayService(UpstreamSessions upstream, CredentialService credentials, ToolAuthorizer authorizer,
                                        AuditLog audit, ToolErrors errors, JsonMapper gatewayJson, MeterRegistry meters,
                                        GatewayProperties properties) {
        return new McpGatewayService(upstream, credentials, authorizer, audit, errors, gatewayJson, meters,
                properties.componentId());
    }
}
