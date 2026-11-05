package pl.aiwcorpo.mcp.gateway.broker;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.stream.Collectors;

import pl.aiwcorpo.mcp.gateway.upstream.BoundedInputStream;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.json.JsonMapper;

/**
 * RFC 8693 token exchange of the user's token (C1) for {@code aud=mcp-credential-broker}; the result is the
 * {@code subjectToken} of resolve for token-exchange systems. The raw C1 token never goes to the broker.
 */
public class TokenExchangeClient {

    private static final int MAX_BODY = 64 * 1024;

    private final URI tokenUri;
    private final String clientId;
    private final String clientSecret;
    private final String audience;
    private final String scope;
    private final HttpClient http;
    private final JsonMapper json;
    private final Duration timeout;

    public TokenExchangeClient(URI tokenUri, String clientId, String clientSecret, String audience, String scope,
                               HttpClient http, JsonMapper json, Duration timeout) {
        this.tokenUri = tokenUri;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.audience = audience;
        this.scope = scope;
        this.http = http;
        this.json = json;
        this.timeout = timeout;
    }

    public boolean configured() {
        return tokenUri != null && clientId != null && !clientId.isBlank() && clientSecret != null && !clientSecret.isBlank();
    }

    /** Exchanged access token, or null when the IdP refused or did not answer. */
    public String exchange(String subjectToken) {
        if (!configured()) {
            return null;
        }
        Map<String, String> form = Map.of(
                "grant_type", "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token", subjectToken,
                "subject_token_type", "urn:ietf:params:oauth:token-type:access_token",
                "requested_token_type", "urn:ietf:params:oauth:token-type:access_token",
                "audience", audience,
                "scope", scope);
        String body = form.entrySet().stream()
                .map(e -> e.getKey() + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));
        String basic = Base64.getEncoder().encodeToString((URLEncoder.encode(clientId, StandardCharsets.UTF_8) + ":"
                + URLEncoder.encode(clientSecret, StandardCharsets.UTF_8)).getBytes(StandardCharsets.UTF_8));
        try {
            HttpResponse<InputStream> response = http.send(HttpRequest.newBuilder(tokenUri).timeout(timeout)
                    .header("Authorization", "Basic " + basic)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofInputStream());
            byte[] bytes;
            try (InputStream in = new BoundedInputStream(response.body(), MAX_BODY)) {
                bytes = in.readAllBytes();
            }
            if (response.statusCode() != 200) {
                return null;
            }
            String token = json.readTree(bytes).path("access_token").asString(null);
            return token == null || token.isEmpty() ? null : token;
        } catch (IOException | JacksonException e) {
            return null;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        }
    }
}
