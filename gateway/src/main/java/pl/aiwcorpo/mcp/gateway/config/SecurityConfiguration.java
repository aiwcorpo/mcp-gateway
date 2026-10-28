package pl.aiwcorpo.mcp.gateway.config;

import java.time.Duration;
import java.util.List;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;

import jakarta.servlet.http.HttpServletResponse;
import pl.aiwcorpo.mcp.gateway.admin.AdminClientCertificateFilter;
import pl.aiwcorpo.mcp.gateway.auth.McpAuthenticationEntryPoint;
import pl.aiwcorpo.mcp.gateway.auth.ResourceMetadata;
import pl.aiwcorpo.mcp.gateway.jwt.JwksController;

/**
 * OAuth resource server for C1: JWKS from configuration (the issuer as seen from containers differs from
 * {@code iss}), issuer, audience {@code mcp-gateway}, required claims. Nothing is anonymous except the RFC 9728
 * metadata and the internal JWKS.
 */
@Configuration
public class SecurityConfiguration {

    @Bean
    JwtDecoder jwtDecoder(GatewayProperties properties) {
        return decoder(properties.oidc(), properties.oidc().audience());
    }

    /** The BFF's user token exchanged for the admin audience (C5): same issuer, keys and claim rules. */
    @Bean
    JwtDecoder adminJwtDecoder(GatewayProperties properties) {
        return decoder(properties.oidc(), properties.admin().audience());
    }

    private static JwtDecoder decoder(GatewayProperties.Oidc oidc, String requiredAudience) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(oidc.jwksUri().toString())
                .jwsAlgorithms(algorithms -> {
                    algorithms.add(SignatureAlgorithm.RS256);
                    algorithms.add(SignatureAlgorithm.ES256);
                })
                .build();
        OAuth2TokenValidator<Jwt> audience = jwt -> jwt.getAudience() != null && jwt.getAudience().contains(requiredAudience)
                ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "audience", null));
        // The claims are copied into C2 and C8, whose schemas bound them; "system:" is the service variant's sub.
        OAuth2TokenValidator<Jwt> claims = jwt -> bounded(jwt.getSubject()) && !jwt.getSubject().startsWith("system:")
                && bounded(jwt.getClaimAsString("azp")) && bounded(jwt.getClaimAsString("preferred_username"))
                && jwt.getExpiresAt() != null && jwt.getIssuedAt() != null
                && !Duration.between(jwt.getIssuedAt(), jwt.getExpiresAt()).minus(oidc.maxTokenLifetime()).isPositive()
                ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "required claims", null));
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                List.of(JwtValidators.createDefaultWithIssuer(oidc.issuer()), audience, claims)));
        return decoder;
    }

    /** C5 on the internal port: client certificate name, then the user token with aud mcp-gateway-admin. */
    @Bean
    @Order(1)
    SecurityFilterChain adminFilterChain(HttpSecurity http, @Qualifier("adminJwtDecoder") JwtDecoder decoder,
                                         GatewayProperties properties) throws Exception {
        AuthenticationEntryPoint unauthenticated = (request, response, e) -> {
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
                .addFilterBefore(new AdminClientCertificateFilter(properties.admin().allowedClientCns()),
                        BearerTokenAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .oauth2ResourceServer(rs -> rs.jwt(jwt -> jwt.decoder(decoder)).authenticationEntryPoint(unauthenticated))
                .exceptionHandling(e -> e.authenticationEntryPoint(unauthenticated)
                        .accessDeniedHandler((request, response, denied) ->
                                writeError(response, HttpServletResponse.SC_FORBIDDEN, "access_denied")));
        return http.build();
    }

    private static void writeError(HttpServletResponse response, int status, String code) throws java.io.IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.getWriter().write("{\"error\":\"" + code + "\"}");
    }

    @Bean
    @Order(2)
    SecurityFilterChain securityFilterChain(HttpSecurity http, @Qualifier("jwtDecoder") JwtDecoder decoder,
                                            ResourceMetadata metadata, GatewayProperties properties) throws Exception {
        McpAuthenticationEntryPoint entryPoint = new McpAuthenticationEntryPoint(metadata);
        String authorizationServer = properties.oidc().advertisedAuthorizationServer();
        http.csrf(csrf -> csrf.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .requestCache(cache -> cache.disable())
                .formLogin(form -> form.disable())
                .httpBasic(basic -> basic.disable())
                .logout(logout -> logout.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(ResourceMetadata.WELL_KNOWN, ResourceMetadata.WELL_KNOWN + "/**").permitAll()
                        .requestMatchers(JwksController.PATH, "/actuator/health", "/actuator/prometheus").permitAll()
                        .requestMatchers("/error").permitAll()
                        .anyRequest().authenticated())
                .oauth2ResourceServer(rs -> rs.jwt(jwt -> jwt.decoder(decoder)).authenticationEntryPoint(entryPoint)
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
