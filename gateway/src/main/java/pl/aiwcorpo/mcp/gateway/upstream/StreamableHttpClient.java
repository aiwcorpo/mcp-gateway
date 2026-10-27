package pl.aiwcorpo.mcp.gateway.upstream;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Locale;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Client side of Streamable HTTP (2025-03-26 .. 2025-11-25) towards one MCP server over mTLS. The answer to a
 * request is either application/json or an SSE stream; on a stream only the response with the request's id is
 * kept (request-scoped notifications are not forwarded in M1). Every body, JSON or SSE, is read through a hard
 * byte limit ({@code maxBytes}).
 */
public class StreamableHttpClient {

    private final URI endpoint;
    private final HttpClient http;
    private final JsonMapper json;
    private final Duration timeout;
    private final int maxBytes;

    public StreamableHttpClient(URI endpoint, HttpClient http, JsonMapper json, Duration timeout, int maxBytes) {
        this.endpoint = endpoint;
        this.http = http;
        this.json = json;
        this.timeout = timeout;
        this.maxBytes = maxBytes;
    }

    public UpstreamResponse post(UpstreamRequest request, JsonNode expectedId) throws UpstreamException {
        HttpRequest.Builder builder = HttpRequest.newBuilder(endpoint)
                .timeout(timeout)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream")
                .POST(HttpRequest.BodyPublishers.ofString(request.body()));
        headers(builder, request);
        HttpResponse<InputStream> response = send(builder.build());
        int status = response.statusCode();
        String sessionId = response.headers().firstValue("Mcp-Session-Id").orElse(null);
        try (InputStream body = new BoundedInputStream(response.body(), maxBytes)) {
            if (status == 202) {
                return new UpstreamResponse(status, sessionId, null);
            }
            if (status != 200) {
                return new UpstreamResponse(status, sessionId, null);
            }
            String contentType = response.headers().firstValue("Content-Type").orElse("").toLowerCase(Locale.ROOT);
            JsonNode message;
            if (contentType.startsWith("application/json")) {
                message = json.readTree(body.readAllBytes());
            } else if (contentType.startsWith("text/event-stream")) {
                message = fromEventStream(body, expectedId);
            } else {
                throw new UpstreamException(UpstreamException.Kind.PROTOCOL, "unexpected content type");
            }
            return new UpstreamResponse(status, sessionId, message);
        } catch (BoundedInputStream.LimitExceededException e) {
            throw new UpstreamException(UpstreamException.Kind.PROTOCOL, "response too large");
        } catch (IOException e) {
            throw new UpstreamException(UpstreamException.Kind.UNAVAILABLE, "reading the response failed");
        } catch (JacksonException e) {
            throw new UpstreamException(UpstreamException.Kind.PROTOCOL, "response is not JSON");
        }
    }

    /** Ends the server's session (legacy DELETE); failures are irrelevant to the caller. */
    public void delete(UpstreamRequest request) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(endpoint).timeout(timeout).DELETE();
        headers(builder, request);
        try {
            http.send(builder.build(), HttpResponse.BodyHandlers.discarding());
        } catch (IOException e) {
            // the session expires on the server anyway
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static void headers(HttpRequest.Builder builder, UpstreamRequest request) {
        builder.header("Authorization", "Bearer " + request.jwt());
        builder.header("X-Request-Id", request.requestId());
        if (request.sessionId() != null) {
            builder.header("Mcp-Session-Id", request.sessionId());
        }
        if (request.protocolVersion() != null) {
            builder.header("MCP-Protocol-Version", request.protocolVersion());
        }
        if (request.credential() != null) {
            builder.header("X-MCP-Credential", request.credential().headerValue());
            builder.header("X-MCP-Credential-Type", request.credential().type());
        }
    }

    private HttpResponse<InputStream> send(HttpRequest request) throws UpstreamException {
        try {
            return http.send(request, HttpResponse.BodyHandlers.ofInputStream());
        } catch (IOException e) {
            throw new UpstreamException(UpstreamException.Kind.UNAVAILABLE, e.getClass().getSimpleName());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new UpstreamException(UpstreamException.Kind.UNAVAILABLE, "interrupted");
        }
    }

    private JsonNode fromEventStream(InputStream body, JsonNode expectedId) throws IOException, UpstreamException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(body, StandardCharsets.UTF_8));
        StringBuilder data = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            if (line.isEmpty()) {
                JsonNode message = dispatch(data, expectedId);
                data.setLength(0);
                if (message != null) {
                    return message;
                }
            } else if (line.startsWith("data:")) {
                String value = line.substring(5);
                data.append(value.startsWith(" ") ? value.substring(1) : value).append('\n');
            }
        }
        JsonNode message = dispatch(data, expectedId);
        if (message != null) {
            return message;
        }
        throw new UpstreamException(UpstreamException.Kind.PROTOCOL, "event stream ended without a response");
    }

    private JsonNode dispatch(StringBuilder data, JsonNode expectedId) {
        if (data.isEmpty()) {
            return null;
        }
        JsonNode message = json.readTree(data.toString());
        boolean isResponse = message.has("id") && !message.has("method") && (message.has("result") || message.has("error"))
                && message.get("id").equals(expectedId);
        return isResponse ? message : null;
    }
}
