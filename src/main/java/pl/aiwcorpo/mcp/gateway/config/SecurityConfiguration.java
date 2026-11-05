package pl.aiwcorpo.mcp.gateway.config;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import io.micrometer.core.instrument.MeterRegistry;
import jakarta.servlet.http.HttpServletResponse;
import pl.aiwcorpo.mcp.gateway.admin.AdminClientCertificateFilter;
import pl.aiwcorpo.mcp.gateway.admin.AdminOperations;
import pl.aiwcorpo.mcp.gateway.admin.ClientCertificateVerifier;
import pl.aiwcorpo.mcp.gateway.audit.AuditLog;
import pl.aiwcorpo.mcp.gateway.auth.AuthenticationAudit;
import pl.aiwcorpo.mcp.gateway.auth.AuthenticationEventLimiter;
import pl.aiwcorpo.mcp.gateway.auth.ClassifyingJwtDecoder;
import pl.aiwcorpo.mcp.gateway.auth.ClientTokenUnavailable;
import pl.aiwcorpo.mcp.gateway.auth.IdpKeySet;
import pl.aiwcorpo.mcp.gateway.auth.McpAuthenticationEntryPoint;
import pl.aiwcorpo.mcp.gateway.auth.ResourceMetadata;
import pl.aiwcorpo.mcp.gateway.jwt.JwksController;
import pl.aiwcorpo.mcp.gateway.jwt.UuidV7;

/**
 * OAuth resource server for C1: JWKS from configuration (the issuer as seen from containers differs from
 * {@code iss}), issuer, audience {@code mcp-gateway}, required claims. Nothing is anonymous except the RFC 9728
 * metadata and the internal JWKS.
 */
@Configuration
public class SecurityConfiguration {

    @Bean
    @DependsOn("devstackGuard")
    IdpKeySet idpKeySet(GatewayProperties properties, Clock clock) {
        GatewayProperties.Oidc oidc = properties.oidc();
        return IdpKeySet.overHttp(oidc.jwksUri(), clock, oidc.jwksRetryInterval(), oidc.jwksFreshFor(), oidc.jwksUsableFor());
    }

    @Bean
    JwtDecoder jwtDecoder(GatewayProperties properties, IdpKeySet keys, Clock clock) {
        return new ClassifyingJwtDecoder(keys,
                decoder(keys, properties.oidc(), properties.oidc().audience(), properties.admin().audience(), null, clock));
    }

    /** The BFF's user token exchanged for the admin audience (C5): same issuer, keys and claim rules. */
    @Bean
    JwtDecoder adminJwtDecoder(GatewayProperties properties, IdpKeySet keys, Clock clock) {
        return new ClassifyingJwtDecoder(keys, decoder(keys, properties.oidc(), properties.admin().audience(),
                properties.oidc().audience(), properties.admin().authorizedParty(), clock));
    }

    @Bean
    AuthenticationAudit authenticationAudit(AuditLog audit, GatewayProperties properties, MeterRegistry meters) {
        return new AuthenticationAudit(audit, properties.componentId(),
                new AuthenticationEventLimiter(properties.audit().unauthenticatedPerSecond(),
                        properties.audit().certificateRejectionInterval(), System::nanoTime, meters));
    }

    /**
     * A token serves one API: it must name the audience of that API and not the other one, so a token that was
     * minted for both can never act on both. {@code requiredAzp} (when set) pins the client the token was issued to.
     */
    private static JwtDecoder decoder(IdpKeySet keys, GatewayProperties.Oidc oidc, String requiredAudience,
                                      String forbiddenAudience, String requiredAzp, Clock clock) {
        // Keys come from the copy of IdpKeySet only: the lookup and its fetch rules (CC-124) are decided before this runs.
        JWKSource<SecurityContext> source = (selector, context) -> selector.select(new JWKSet(keys.snapshot()));
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSource(source)
                .jwsAlgorithms(algorithms -> {
                    algorithms.add(SignatureAlgorithm.RS256);
                    algorithms.add(SignatureAlgorithm.ES256);
                })
                .build();
        OAuth2TokenValidator<Jwt> audience = jwt -> jwt.getAudience() != null && jwt.getAudience().contains(requiredAudience)
                && !jwt.getAudience().contains(forbiddenAudience)
                && (requiredAzp == null || requiredAzp.equals(jwt.getClaimAsString("azp")))
                ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "wrong_audience", null));
        // A token issued to a client that serves the admin API only is no MCP client token, whatever its audience says.
        OAuth2TokenValidator<Jwt> notForC5Only = jwt -> requiredAzp == null && oidc.c5OnlyClients().contains(jwt.getClaimAsString("azp"))
                ? OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "invalid_claims", null))
                : OAuth2TokenValidatorResult.success();
        // The claims are copied into C2 and C8, whose schemas bound them; "system:" is the service variant's sub.
        OAuth2TokenValidator<Jwt> claims = jwt -> bounded(jwt.getSubject()) && !jwt.getSubject().startsWith("system:")
                && bounded(jwt.getClaimAsString("azp")) && bounded(jwt.getClaimAsString("preferred_username"))
                && jwt.getExpiresAt() != null && jwt.getIssuedAt() != null
                && !Duration.between(jwt.getIssuedAt(), jwt.getExpiresAt()).minus(oidc.maxTokenLifetime()).isPositive()
                ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "invalid_claims", null));
        // The defaults (typ, certificate binding) stay; the timestamps are checked by named validators first, so no
        // reason depends on the wording of a library message (an expired token fails the default one too, with the
        // same outcome).
        decoder.setJwtValidator(JwtValidators.createDefaultWithValidators(
                List.of(named("wrong_issuer", new JwtIssuerValidator(oidc.issuer())), audience, notForC5Only, claims,
                        timestamps(clock))));
        return decoder;
    }

    private static OAuth2TokenValidator<Jwt> timestamps(Clock clock) {
        Duration skew = Duration.ofSeconds(60);
        return jwt -> {
            Instant now = clock.instant();
            if (jwt.getExpiresAt() != null && !now.minus(skew).isBefore(jwt.getExpiresAt())) {
                return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "expired", null));
            }
            if (jwt.getNotBefore() != null && now.plus(skew).isBefore(jwt.getNotBefore())) {
                return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "not_yet_valid", null));
            }
            return OAuth2TokenValidatorResult.success();
        };
    }

    private static OAuth2TokenValidator<Jwt> named(String reason, OAuth2TokenValidator<Jwt> validator) {
        return jwt -> validator.validate(jwt).hasErrors()
                ? OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", reason, null))
                : OAuth2TokenValidatorResult.success();
    }

    /**
     * The two operations of C5 that have no user: registerServer (the pipeline of one server, CN {@code mcp-registry-ci-<serverId>}
     * equal to the {@code serverId} of the path, CC-161) and purgeUser (the offboarding process, CN {@code mcp-offboarding}, CC-155).
     * Both are {@code security: mtls} in the contract, so no bearer token is asked for. Any other name is 403.
     */
    @Bean
    @Order(0)
    SecurityFilterChain registryPipelineFilterChain(HttpSecurity http, GatewayProperties properties,
                                                    ClientCertificateVerifier certificates, AuthenticationAudit authenticationAudit)
            throws Exception {
        // The same patterns as the rules below: the emergency switches are PUT under /registry/servers/ too, and they carry a user token.
        org.springframework.security.web.util.matcher.RequestMatcher certificateOnly = request -> {
            org.springframework.http.server.PathContainer path = org.springframework.http.server.PathContainer.parsePath(request.getServletPath());
            return AdminOperations.certificateOnly(properties.admin().offboardingClientCns()).stream().anyMatch(rule -> rule.covers(request.getMethod(), path));
        };
        http.securityMatcher(certificateOnly)
                .csrf(csrf -> csrf.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .requestCache(cache -> cache.disable())
                .formLogin(form -> form.disable())
                .httpBasic(basic -> basic.disable())
                .logout(logout -> logout.disable())
                .addFilterBefore(new AdminClientCertificateFilter(AdminOperations.certificateOnly(properties.admin().offboardingClientCns()),
                        true, certificates, authenticationAudit), org.springframework.security.web.access.intercept.AuthorizationFilter.class)
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
        return http.build();
    }

    /** C5 on the internal port: client certificate name, then the user token with aud mcp-gateway-admin. */
    @Bean
    @Order(1)
    SecurityFilterChain adminFilterChain(HttpSecurity http, @Qualifier("adminJwtDecoder") JwtDecoder decoder,
                                         GatewayProperties properties, ClientCertificateVerifier certificates,
                                         AuthenticationAudit authenticationAudit) throws Exception {
        AuthenticationEntryPoint unauthenticated = (request, response, e) -> {
            String requestId = UuidV7.next();
            String reason = AuthenticationAudit.reasonOf(e);
            authenticationAudit.rejected(requestId, request.getHeader("X-Request-Id"), reason,
                    AuthenticationAudit.errorCodeOf(reason), null);
            response.setHeader("X-Request-Id", requestId);
            if (ClientTokenUnavailable.REASON.equals(reason)) {
                response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
                response.setHeader(HttpHeaders.RETRY_AFTER, Integer.toString(AuthenticationAudit.retryAfterOf(e)));
                writeError(response, HttpServletResponse.SC_SERVICE_UNAVAILABLE, "upstream_unavailable");
                return;
            }
            response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
            writeError(response, HttpServletResponse.SC_UNAUTHORIZED, "unauthenticated");
        };
        http.securityMatcher("/admin/v1/**")
                .csrf(csrf -> csrf.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .requestCache(cache -> cache.disable())
                .formLogin(form -> form.disable())
                .httpBasic(basic -> basic.disable())
                .logout(logout -> logout.disable())
                .addFilterBefore(new AdminClientCertificateFilter(AdminOperations.admin(properties.admin().allowedClientCns()),
                        true, certificates, authenticationAudit),
                        BearerTokenAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .oauth2ResourceServer(rs -> rs.jwt(jwt -> jwt.decoder(decoder)).authenticationEntryPoint(unauthenticated)
                        .withObjectPostProcessor(routeServiceFailuresTo(unauthenticated)))
                .exceptionHandling(e -> e.authenticationEntryPoint(unauthenticated)
                        .accessDeniedHandler((request, response, denied) ->
                                writeError(response, HttpServletResponse.SC_FORBIDDEN, "access_denied")));
        return http.build();
    }

    /**
     * An unreachable JWKS surfaces as an AuthenticationServiceException, which the filter would rethrow (500, no
     * event); route it to the entry point like every other rejection.
     */
    private static ObjectPostProcessor<BearerTokenAuthenticationFilter> routeServiceFailuresTo(AuthenticationEntryPoint entryPoint) {
        return new ObjectPostProcessor<>() {
            @Override
            public <O extends BearerTokenAuthenticationFilter> O postProcess(O filter) {
                AuthenticationEntryPointFailureHandler handler = new AuthenticationEntryPointFailureHandler(entryPoint);
                handler.setRethrowAuthenticationServiceException(false);
                filter.setAuthenticationFailureHandler(handler);
                return filter;
            }
        };
    }

    private static void writeError(HttpServletResponse response, int status, String code) throws java.io.IOException {
        response.setStatus(status);
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write("{\"error\":\"" + code + "\"}");
    }

    @Bean
    @Order(2)
    SecurityFilterChain securityFilterChain(HttpSecurity http, @Qualifier("jwtDecoder") JwtDecoder decoder,
                                            ResourceMetadata metadata, GatewayProperties properties,
                                            ClientCertificateVerifier certificates,
                                            AuthenticationAudit authenticationAudit) throws Exception {
        McpAuthenticationEntryPoint entryPoint = new McpAuthenticationEntryPoint(metadata, authenticationAudit);
        String authorizationServer = properties.oidc().advertisedAuthorizationServer();
        http.csrf(csrf -> csrf.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .requestCache(cache -> cache.disable())
                .formLogin(form -> form.disable())
                .httpBasic(basic -> basic.disable())
                .logout(logout -> logout.disable())
                // Prometheus is permitted below, so the scraper's certificate is the only thing that guards it.
                .addFilterBefore(new AdminClientCertificateFilter(AdminOperations.metrics(properties.metrics().allowedClientCns()),
                        false, certificates, authenticationAudit), BearerTokenAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(ResourceMetadata.WELL_KNOWN, ResourceMetadata.WELL_KNOWN + "/**").permitAll()
                        .requestMatchers(JwksController.PATH, "/actuator/health", "/actuator/prometheus").permitAll()
                        .requestMatchers("/error").permitAll()
                        .anyRequest().authenticated())
                .oauth2ResourceServer(rs -> rs.jwt(jwt -> jwt.decoder(decoder)).authenticationEntryPoint(entryPoint)
                        .withObjectPostProcessor(routeServiceFailuresTo(entryPoint))
                        // RFC 9728 documents come from Spring Security's metadata filter
                        // (/.well-known/oauth-protected-resource/<path>); resource = the requested path.
                        .protectedResourceMetadata(m -> m.protectedResourceMetadataCustomizer(builder -> builder
                                .authorizationServer(authorizationServer)
                                .resourceName("MCP Gateway")
                                .tlsClientCertificateBoundAccessTokens(false)
                                .claims(claims -> claims.computeIfPresent("resource",
                                        (k, resource) -> metadata.rebase(resource.toString()))))))
                .exceptionHandling(e -> e.authenticationEntryPoint(entryPoint));
        return http.build();
    }

    private static boolean bounded(String value) {
        return value != null && !value.isBlank() && value.length() <= 255;
    }
}
