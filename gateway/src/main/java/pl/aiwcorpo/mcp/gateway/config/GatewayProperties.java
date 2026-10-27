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
        /* Public base URL as clients see it (RFC 9728 resource); empty = taken from the request. */
        URI publicUrl,
        @Valid @NotNull Oidc oidc,
        @Valid @NotNull InternalJwt internalJwt,
        @Valid @NotNull InternalEndpoint internalEndpoint,
        @Valid @NotNull Tls tls,
        @Valid @NotNull Broker broker,
        @Valid @NotNull Redis redis,
        @Valid @NotNull Sessions sessions,
        @Valid @NotNull Upstream upstream,
        @DefaultValue("00000000000000-0000000") String policyRevision,
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
            @DefaultValue("mcp-credential-broker-audience") String exchangeScope) {

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
            @DefaultValue("credential.invalidated") String invalidationChannel) {
    }

    public record Sessions(
            @DefaultValue("1h") Duration clientIdleTimeout,
            @DefaultValue("30m") Duration upstreamIdleTimeout) {
    }

    public record Upstream(
            @DefaultValue("30s") Duration timeout,
            @DefaultValue("4194304") int maxResponseBytes) {
    }

    /** Static configuration of one MCP server (M1 stand-in for the registry, C5). */
    public record Server(
            @NotBlank String system,
            @NotNull URI internalUrl,
            @Valid @NotNull Credential credential,
            @Valid @NotEmpty Map<String, Tool> tools) {
    }

    public record Credential(
            @DefaultValue("true") boolean required,
            @DefaultValue List<String> acceptedTypes,
            @DefaultValue List<String> scopes,
            /* token-exchange systems need the user's token exchanged for the broker (C4 subjectToken). */
            @DefaultValue("false") boolean tokenExchange) {
    }

    public record Tool(@NotBlank String risk) {
    }
}
