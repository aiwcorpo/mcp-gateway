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
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Client side of Streamable HTTP (2025-03-26 .. 2025-11-25) towards one MCP server under the trust approved for it (no client
 * certificate, CC-249). The answer to a
 * request is either application/json or an SSE stream; on a stream only the response with the request's id is
 * kept (request-scoped notifications are not forwarded in M1). Every body, JSON or SSE, is read through a hard
 * byte limit ({@code maxBytes}).
 */
public class StreamableHttpClient {

    private static final ScheduledExecutorService DEADLINES = Executors.newSingleThreadScheduledExecutor(
            Thread.ofPlatform().daemon().name("upstream-deadline").factory());

    private final URI endpoint;
    private final HttpClient http;
    private final JsonMapper json;
    private final Duration timeout;
    private final int maxBytes;
    private final java.util.function.Supplier<Optional<String>> addressRefusal;

    public StreamableHttpClient(URI endpoint, HttpClient http, JsonMapper json, Duration timeout, int maxBytes) {
        this(endpoint, http, json, timeout, maxBytes, Optional::empty);
    }

    /**
     * @param addressRefusal asked before every request: why the address may not be connected to now (a name that resolves to a refused
     *                       address since the server was added), or empty
     */
    public StreamableHttpClient(URI endpoint, HttpClient http, JsonMapper json, Duration timeout, int maxBytes,
                                java.util.function.Supplier<Optional<String>> addressRefusal) {
        this.endpoint = endpoint;
        this.http = http;
        this.json = json;
        this.timeout = timeout;
        this.maxBytes = maxBytes;
        this.addressRefusal = addressRefusal;
    }

    public UpstreamResponse post(UpstreamRequest request, JsonNode expectedId) throws UpstreamException {
        HttpRequest.Builder builder = HttpRequest.newBuilder(endpoint)
                .timeout(timeout)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream")
                .POST(HttpRequest.BodyPublishers.ofString(request.body()));
        headers(builder, request);
        long deadline = System.nanoTime() + timeout.toNanos();
        HttpResponse<InputStream> response = send(builder.build());
        int status = response.statusCode();
        String sessionId = response.headers().firstValue("Mcp-Session-Id").orElse(null);
        InputStream raw = response.body();
        // HttpRequest.timeout covers only the response headers; the body (an SSE stream may stay open) gets
        // the rest of the same budget, after which the stream is closed under the reader.
        AtomicBoolean expired = new AtomicBoolean();
        ScheduledFuture<?> guard = DEADLINES.schedule(() -> {
            expired.set(true);
            closeQuietly(raw);
        }, Math.max(0, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
        try (InputStream body = new BoundedInputStream(raw, maxBytes)) {
            if (status == 202) {
                return new UpstreamResponse(status, sessionId, null);
            }
            if (status == 409) {
                // The body of a 409 says whether it is policy_data_stale (C14): the gateway pushes its data and repeats the call once.
                try {
                    return new UpstreamResponse(status, sessionId, json.readTree(body.readAllBytes()));
                } catch (JacksonException e) {
                    return new UpstreamResponse(status, sessionId, null);
                }
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
            throw new UpstreamException(UpstreamException.Kind.UNAVAILABLE,
                    expired.get() ? "response not complete in time" : "reading the response failed");
        } catch (JacksonException e) {
            if (expired.get()) {
                throw new UpstreamException(UpstreamException.Kind.UNAVAILABLE, "response not complete in time");
            }
            throw new UpstreamException(UpstreamException.Kind.PROTOCOL, "response is not JSON");
        } finally {
            guard.cancel(false);
        }
    }

    private static void closeQuietly(InputStream in) {
        try {
            in.close();
        } catch (IOException e) {
            // the reader sees the closed stream either way
        }
    }

    /** The deadline ({@link System#nanoTime}) of an operation that starts now: the timeout covers it whole, however many requests it makes. */
    public long deadline() {
        return System.nanoTime() + timeout.toNanos();
    }

    /** Ends the server's session (legacy DELETE); failures are irrelevant to the caller. */
    public void delete(UpstreamRequest request) {
        delete(request, deadline());
    }

    /**
     * Ends the server's session (legacy DELETE) no later than {@code deadline} ({@link #deadline()}); failures are irrelevant to the caller.
     * Nothing of the answer is read: the body is closed as soon as the status arrives, so a server that keeps it open holds nothing.
     */
    public void delete(UpstreamRequest request, long deadline) {
        long remaining = deadline - System.nanoTime();
        if (remaining <= 0 || addressRefusal.get().isPresent()) {
            return;
        }
        HttpRequest.Builder builder = HttpRequest.newBuilder(endpoint).timeout(Duration.ofNanos(remaining)).DELETE();
        headers(builder, request);
        try {
            http.send(builder.build(), HttpResponse.BodyHandlers.ofInputStream()).body().close();
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
        Optional<String> refused = addressRefusal.get();
        if (refused.isPresent()) {
            throw new UpstreamException(UpstreamException.Kind.UNAVAILABLE, "address_refused: " + refused.get());
        }
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
