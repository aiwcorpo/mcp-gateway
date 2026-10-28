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
import jakarta.validation.constraints.Pattern;

/** All gateway settings; environment variable names are in application.yml and README. */
@Validated
@ConfigurationProperties(prefix = "gateway")
public record GatewayProperties(
        @DefaultValue("mcp-gateway") @NotBlank String componentId,
        @DefaultValue("0.1.0") String version,
        /*
         * Public base URL as clients see it (publicBaseUrl of C5, CC-089): RFC 9728 resource, WWW-Authenticate,
         * MCP endpoint and portal links. Always configuration, never the Host of a request.
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
        @Valid @NotNull VirtualServers virtualServers,
        @Valid @NotNull Metrics metrics,
        @DefaultValue @Valid Audit audit,
        @DefaultValue @Valid Confirmations confirmations,
        @DefaultValue("00000000000000-0000000") @Pattern(regexp = "^[0-9]{14}-[0-9a-f]{7}$") String policyRevision,
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
            @DefaultValue("1h") Duration jwksUsableFor) {

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
            @DefaultValue("5s") Duration healthInterval) {
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
            /* Certificate names of the operations the contract gives to registry CI. */
            @DefaultValue("mcp-registry-ci") @NotEmpty List<String> registryClientCns) {
    }

    public record VirtualServers(
            /* Links one user may own; creating more is refused. */
            @DefaultValue("50") @Min(1) int maxPerUser) {
    }

    /** Confirmations of DESTRUCTIVE calls (C11); TTL, attempts and the validity of a code are fixed by the contract. */
    public record Confirmations(
            /* Pending confirmations of a risk other than DESTRUCTIVE (required by policy) per user. */
            @DefaultValue("3") @Min(1) int pendingLimit) {
    }

    /** Caps on authentication events that cost the sender nothing (CC-120, CC-125). */
    public record Audit(
            /* Per second and per reason, for missing_token and malformed. */
            @DefaultValue("20") @Min(1) int unauthenticatedPerSecond,
            /* One client_certificate_rejected event per source address in this time on the admin port. */
            @DefaultValue("1m") Duration certificateRejectionInterval) {
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
