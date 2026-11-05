package pl.aiwcorpo.mcp.gateway.support;

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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** An open SSE response read line by line on a thread of its own: tests wait for the messages and comments of a stream. */
public final class SseClient implements AutoCloseable {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    private final HttpResponse<InputStream> response;
    private final BlockingQueue<String> lines = new LinkedBlockingQueue<>();
    private final Thread reader;
    private volatile boolean ended;

    private SseClient(HttpResponse<InputStream> response) {
        this.response = response;
        this.reader = Thread.ofVirtual().start(() -> {
            try (BufferedReader in = new BufferedReader(new InputStreamReader(response.body(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = in.readLine()) != null) {
                    lines.add(line);
                }
            } catch (IOException e) {
                // The connection was closed by the test or by the server.
            } finally {
                ended = true;
            }
        });
    }

    public static SseClient get(HttpClient http, String url, Map<String, String> headers) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(url)).GET().header("Accept", "text/event-stream");
        headers.forEach(builder::setHeader);
        return new SseClient(http.send(builder.build(), HttpResponse.BodyHandlers.ofInputStream()));
    }

    public static SseClient post(HttpClient http, String url, String body, Map<String, String> headers) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(url)).POST(HttpRequest.BodyPublishers.ofString(body))
                .header("Accept", "application/json, text/event-stream").header("Content-Type", "application/json");
        headers.forEach(builder::setHeader);
        return new SseClient(http.send(builder.build(), HttpResponse.BodyHandlers.ofInputStream()));
    }

    public int status() {
        return response.statusCode();
    }

    public HttpResponse<InputStream> response() {
        return response;
    }

    /** The next line, or null when none comes within the time. */
    public String nextLine(Duration within) throws InterruptedException {
        return lines.poll(within.toMillis(), TimeUnit.MILLISECONDS);
    }

    /** The next JSON message ({@code data:} line) within the time, skipping comments; null when none comes. */
    public JsonNode nextMessage(Duration within) throws InterruptedException {
        long deadline = System.nanoTime() + within.toNanos();
        while (true) {
            long left = deadline - System.nanoTime();
            if (left <= 0) {
                return null;
            }
            String line = lines.poll(left, TimeUnit.NANOSECONDS);
            if (line == null) {
                return null;
            }
            if (line.startsWith("data: ")) {
                return JSON.readTree(line.substring(6));
            }
        }
    }

    /** True when a comment line {@code : keepalive} comes within the time; the lines before it are dropped. */
    public boolean keepalive(Duration within) throws InterruptedException {
        long deadline = System.nanoTime() + within.toNanos();
        while (true) {
            long left = deadline - System.nanoTime();
            if (left <= 0) {
                return false;
            }
            String line = lines.poll(left, TimeUnit.NANOSECONDS);
            if (line == null) {
                return false;
            }
            if (": keepalive".equals(line)) {
                return true;
            }
        }
    }

    /** Everything that is still coming until the server ends the stream, within the time. */
    public List<String> untilEnd(Duration within) throws InterruptedException {
        List<String> all = new ArrayList<>();
        long deadline = System.nanoTime() + within.toNanos();
        while (System.nanoTime() < deadline && !(ended && lines.isEmpty())) {
            String line = lines.poll(100, TimeUnit.MILLISECONDS);
            if (line != null) {
                all.add(line);
            }
        }
        return all;
    }

    /** The server closed the stream (what is left unread does not matter). */
    public boolean ended() {
        return ended;
    }

    @Override
    public void close() {
        try {
            response.body().close();
        } catch (IOException e) {
            // Already closed.
        }
        reader.interrupt();
    }
}
