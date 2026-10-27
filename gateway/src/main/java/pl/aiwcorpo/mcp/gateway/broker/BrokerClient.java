package pl.aiwcorpo.mcp.gateway.broker;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.jwt.InternalTokenIssuer;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** Client of the credential broker (C4) over mTLS with a fresh internal JWT per request. */
public class BrokerClient {

    public static final String AUDIENCE = "mcp-credential-broker";
    private static final Logger log = LoggerFactory.getLogger(BrokerClient.class);
    private static final Set<String> SCHEMES = Set.of("Bearer", "Basic", "Token", "ApiKey");
    private static final Set<String> TYPES = Set.of("user-oauth", "user-secret", "token-exchange", "service-account");
    private static final int MAX_BODY = 64 * 1024;

    private final URI baseUrl;
    private final HttpClient http;
    private final InternalTokenIssuer tokens;
    private final JsonMapper json;
    private final Duration timeout;

    public BrokerClient(URI baseUrl, HttpClient http, InternalTokenIssuer tokens, JsonMapper json, Duration timeout) {
        this.baseUrl = baseUrl;
        this.http = http;
        this.tokens = tokens;
        this.json = json;
        this.timeout = timeout;
    }

    /** {@code POST /v1/credentials/resolve}; {@code tool} is the server-side tool name (C2, CC-038). */
    public Resolution resolve(GatewayUser user, String system, List<String> scopes, String subjectToken, String tool,
                              String requestId) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("system", system);
        if (!scopes.isEmpty()) {
            body.put("scopes", scopes);
        }
        if (subjectToken != null) {
            body.put("subjectToken", subjectToken);
        }
        HttpRequest request = HttpRequest.newBuilder(baseUrl.resolve("/v1/credentials/resolve"))
                .timeout(timeout)
                .header("Authorization", "Bearer " + tokens.forUser(AUDIENCE, user, tool, requestId))
                .header("X-Request-Id", requestId)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json.writeValueAsString(body)))
                .build();
        HttpResponse<byte[]> response;
        try {
            response = http.send(request, HttpResponse.BodyHandlers.ofByteArray());
        } catch (IOException e) {
            log.warn("broker resolve rid={} failed: {}", requestId, e.getClass().getSimpleName());
            return new Resolution.Unavailable("broker_unreachable");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new Resolution.Unavailable("interrupted");
        }
        int status = response.statusCode();
        if (response.body().length > MAX_BODY) {
            return new Resolution.Failed("broker_response_too_large");
        }
        return switch (status) {
            case 200 -> granted(response.body(), requestId);
            case 409 -> required(response.body(), system, requestId);
            case 503 -> new Resolution.Unavailable("broker_503");
            default -> {
                if (status >= 500) {
                    yield new Resolution.Unavailable("broker_" + status);
                }
                log.error("broker resolve rid={} answered {}: the gateway's request was rejected", requestId, status);
                yield new Resolution.Failed("broker_" + status);
            }
        };
    }

    /** {@code GET /v1/systems} with the service variant (CC-030), used as a start-up configuration check. */
    public JsonNode systems(String requestId) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(baseUrl.resolve("/v1/systems"))
                .timeout(timeout)
                .header("Authorization", "Bearer " + tokens.forService(AUDIENCE, requestId))
                .header("X-Request-Id", requestId)
                .header("Accept", "application/json")
                .GET().build();
        HttpResponse<byte[]> response = http.send(request, HttpResponse.BodyHandlers.ofByteArray());
        if (response.statusCode() != 200) {
            throw new IOException("GET /v1/systems answered " + response.statusCode());
        }
        return json.readTree(response.body());
    }

    private Resolution granted(byte[] body, String requestId) {
        try {
            JsonNode node = json.readTree(body);
            String scheme = node.path("scheme").asString(null);
            String value = node.path("value").asString(null);
            String type = node.path("type").asString(null);
            JsonNode ttl = node.path("cacheTtlSeconds");
            if (!SCHEMES.contains(scheme) || value == null || value.isEmpty() || !TYPES.contains(type) || !ttl.isInt()
                    || ttl.asInt() < 0 || ttl.asInt() > 60 || value.chars().anyMatch(c -> c < 0x20 || c == 0x7f)) {
                log.error("broker resolve rid={}: 200 body outside C4", requestId);
                return new Resolution.Failed("broker_body_invalid");
            }
            JsonNode expiresNode = node.path("expiresAt");
            Instant expiresAt = expiresNode.isString() ? Instant.parse(expiresNode.asString()) : null;
            return new Resolution.Granted(new Credential(scheme, value, type, expiresAt, ttl.asInt()), false);
        } catch (JacksonException | DateTimeParseException e) {
            log.error("broker resolve rid={}: unreadable 200 body", requestId);
            return new Resolution.Failed("broker_body_invalid");
        }
    }

    private Resolution required(byte[] body, String system, String requestId) {
        try {
            JsonNode node = json.readTree(body);
            String connectUrl = node.path("connectUrl").asString(null);
            if (!"credential_required".equals(node.path("error").asString(null)) || !system.equals(node.path("system").asString(null))
                    || connectUrl == null || !isAbsoluteHttpUrl(connectUrl)) {
                log.error("broker resolve rid={}: 409 body outside C4", requestId);
                return new Resolution.Failed("broker_body_invalid");
            }
            return new Resolution.Required(system, connectUrl);
        } catch (JacksonException e) {
            return new Resolution.Failed("broker_body_invalid");
        }
    }

    private static boolean isAbsoluteHttpUrl(String value) {
        try {
            URI uri = URI.create(value);
            return ("https".equals(uri.getScheme()) || "http".equals(uri.getScheme())) && uri.getHost() != null;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
