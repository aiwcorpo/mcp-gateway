package pl.aiwcorpo.mcp.gateway.broker;

import java.io.IOException;
import java.io.InputStream;
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
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.jwt.InternalTokenIssuer;
import pl.aiwcorpo.mcp.gateway.upstream.BoundedInputStream;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** Client of the credential broker (C4) over mTLS with a fresh internal JWT per request. */
public class BrokerClient implements AuthenticatorPort {

    public static final String AUDIENCE = "mcp-credential-broker";
    private static final Logger log = LoggerFactory.getLogger(BrokerClient.class);
    private static final Set<String> SCHEMES = Set.of("Bearer", "Basic", "Token", "ApiKey");
    private static final Set<String> TYPES = Set.of("user-oauth", "user-secret", "token-exchange", "service-account");
    private static final int MAX_BODY = 64 * 1024;
    /* The value becomes an HTTP header: only visible ASCII, otherwise the JDK rejects it with the value in the message. */
    private static final Pattern VISIBLE_ASCII = Pattern.compile("^[\\x21-\\x7e]{1,8192}$");

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
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("system", system);
        if (!scopes.isEmpty()) {
            payload.put("scopes", scopes);
        }
        if (subjectToken != null) {
            payload.put("subjectToken", subjectToken);
        }
        HttpRequest request = HttpRequest.newBuilder(baseUrl.resolve("/v1/credentials/resolve"))
                .timeout(timeout)
                .header("Authorization", "Bearer " + tokens.forUser(AUDIENCE, user, tool, requestId))
                .header("X-Request-Id", requestId)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json.writeValueAsString(payload)))
                .build();
        int status;
        byte[] body;
        try {
            HttpResponse<InputStream> response = http.send(request, HttpResponse.BodyHandlers.ofInputStream());
            status = response.statusCode();
            try (InputStream in = new BoundedInputStream(response.body(), MAX_BODY)) {
                body = in.readAllBytes();
            }
        } catch (BoundedInputStream.LimitExceededException e) {
            log.error("broker resolve rid={}: response over {} bytes", requestId, MAX_BODY);
            return new Resolution.Failed("broker_response_too_large");
        } catch (IOException e) {
            log.warn("broker resolve rid={} failed: {}", requestId, e.getClass().getSimpleName());
            return new Resolution.Unavailable("broker_unreachable");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new Resolution.Unavailable("interrupted");
        }
        return switch (status) {
            case 200 -> granted(body, requestId);
            case 409 -> required(body, system, requestId);
            case 403 -> "exchange_denied".equals(errorOf(body)) ? new Resolution.Denied("exchange_denied") : failed(status, requestId);
            case 422 -> "system_not_configured".equals(errorOf(body)) ? configuration(system, requestId) : failed(status, requestId);
            case 503 -> new Resolution.Unavailable("broker_503");
            default -> status >= 500 ? new Resolution.Unavailable("broker_" + status) : failed(status, requestId);
        };
    }

    private Resolution failed(int status, String requestId) {
        log.error("broker resolve rid={} answered {}: the gateway's request was rejected", requestId, status);
        return new Resolution.Failed("broker_" + status);
    }

    /** CC-158: a defect of the installation; the client gets internal_error, the log and the audit say why. */
    private Resolution configuration(String system, String requestId) {
        log.error("broker resolve rid={}: the system {} is not configured in the broker (system_not_configured)", requestId, system);
        return new Resolution.Failed("system_not_configured");
    }

    private String errorOf(byte[] body) {
        try {
            return json.readTree(body).path("error").asString(null);
        } catch (JacksonException e) {
            return null;
        }
    }

    /** {@code GET /v1/authenticator}; {@code tool} is the server-side name of the tool being confirmed (C2, CC-092). */
    @Override
    public State state(GatewayUser user, String tool, String requestId) {
        try {
            HttpResponse<InputStream> response = http.send(authenticatorRequest(user, tool, requestId, "GET", "/v1/authenticator", null),
                    HttpResponse.BodyHandlers.ofInputStream());
            byte[] body = readBounded(response);
            if (response.statusCode() != 200) {
                return State.UNAVAILABLE;
            }
            return switch (json.readTree(body).path("state").asString("")) {
                case "none" -> State.NONE;
                case "active" -> State.ACTIVE;
                case "disabled" -> State.DISABLED;
                default -> State.UNAVAILABLE;
            };
        } catch (IOException | JacksonException e) {
            log.warn("broker authenticator rid={} failed: {}", requestId, e.getClass().getSimpleName());
            return State.UNAVAILABLE;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return State.UNAVAILABLE;
        }
    }

    /** {@code POST /v1/authenticator/verify}. The code is only in the request body, never logged. */
    @Override
    public Verdict verify(GatewayUser user, String tool, String code, String requestId) {
        try {
            HttpResponse<InputStream> response = http.send(authenticatorRequest(user, tool, requestId, "POST",
                    "/v1/authenticator/verify", json.writeValueAsString(Map.of("code", code))), HttpResponse.BodyHandlers.ofInputStream());
            byte[] body = readBounded(response);
            if (response.statusCode() != 200) {
                log.warn("broker verify rid={} answered {}", requestId, response.statusCode());
                return new Verdict("unavailable", 0);
            }
            JsonNode node = json.readTree(body);
            String result = node.path("result").asString("");
            if (!Set.of("ok", "invalid", "replayed", "burned", "locked", "disabled", "not_registered").contains(result)) {
                return new Verdict("unavailable", 0);
            }
            return new Verdict(result, node.path("retryAfterSeconds").asInt(1));
        } catch (IOException | JacksonException e) {
            log.warn("broker verify rid={} failed: {}", requestId, e.getClass().getSimpleName());
            return new Verdict("unavailable", 0);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new Verdict("unavailable", 0);
        }
    }

    /** {@code POST /v1/authenticator/invalidate-codes}: true only for a 204 (fail-closed for the caller otherwise). */
    @Override
    public boolean invalidateCodes(GatewayUser user, String tool, String requestId) {
        try {
            HttpResponse<InputStream> response = http.send(authenticatorRequest(user, tool, requestId, "POST",
                    "/v1/authenticator/invalidate-codes", null), HttpResponse.BodyHandlers.ofInputStream());
            readBounded(response);
            return response.statusCode() == 204;
        } catch (IOException e) {
            log.warn("broker invalidate-codes rid={} failed: {}", requestId, e.getClass().getSimpleName());
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private HttpRequest authenticatorRequest(GatewayUser user, String tool, String requestId, String method, String path,
                                             String body) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(baseUrl.resolve(path)).timeout(timeout)
                .header("Authorization", "Bearer " + tokens.forUser(AUDIENCE, user, tool, requestId))
                .header("X-Request-Id", requestId)
                .header("Accept", "application/json");
        if (body != null) {
            builder.header("Content-Type", "application/json").method(method, HttpRequest.BodyPublishers.ofString(body));
        } else {
            builder.method(method, HttpRequest.BodyPublishers.noBody());
        }
        return builder.build();
    }

    private static byte[] readBounded(HttpResponse<InputStream> response) throws IOException {
        try (InputStream in = new BoundedInputStream(response.body(), MAX_BODY)) {
            return in.readAllBytes();
        }
    }

    /** {@code GET /v1/systems} with the service variant (CC-030), used as a start-up configuration check. */
    public JsonNode systems(String requestId) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(baseUrl.resolve("/v1/systems"))
                .timeout(timeout)
                .header("Authorization", "Bearer " + tokens.forService(AUDIENCE, requestId))
                .header("X-Request-Id", requestId)
                .header("Accept", "application/json")
                .GET().build();
        HttpResponse<InputStream> response = http.send(request, HttpResponse.BodyHandlers.ofInputStream());
        try (InputStream in = new BoundedInputStream(response.body(), MAX_BODY)) {
            byte[] body = in.readAllBytes();
            if (response.statusCode() != 200) {
                throw new IOException("GET /v1/systems answered " + response.statusCode());
            }
            return json.readTree(body);
        }
    }

    private Resolution granted(byte[] body, String requestId) {
        try {
            JsonNode node = json.readTree(body);
            String scheme = node.path("scheme").asString(null);
            String value = node.path("value").asString(null);
            String type = node.path("type").asString(null);
            JsonNode ttl = node.path("cacheTtlSeconds");
            if (type != null && !TYPES.contains(type) && SCHEMES.contains(scheme) && value != null && !value.isEmpty()) {
                // A type outside the four is no type of any system's set (CC-166): the same refusal, but the audit cannot name a value
                // that is not one of the four.
                log.error("broker resolve rid={}: a credential type outside the contract", requestId);
                return new Resolution.TypeMismatch(null);
            }
            if (!SCHEMES.contains(scheme) || value == null || value.isEmpty() || !TYPES.contains(type) || !ttl.isInt()
                    || ttl.asInt() < 0 || ttl.asInt() > 60 || !VISIBLE_ASCII.matcher(value).matches()) {
                log.error("broker resolve rid={}: 200 body outside C4", requestId);
                return new Resolution.Failed("broker_body_invalid");
            }
            JsonNode expiresNode = node.path("expiresAt");
            Instant expiresAt = expiresNode.isString() ? Instant.parse(expiresNode.asString()) : null;
            if ("token-exchange".equals(type) && expiresAt == null) {
                // CC-157: an exchanged token always says when it ends; one that does not is not cached and not used.
                log.error("broker resolve rid={}: a token-exchange credential without expiresAt", requestId);
                return new Resolution.Failed("broker_body_invalid");
            }
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
