package pl.aiwcorpo.mcp.gateway.policy;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Optional;

import pl.aiwcorpo.mcp.gateway.upstream.BoundedInputStream;
import pl.aiwcorpo.mcp.policy.bundle.BundlePointer;
import pl.aiwcorpo.mcp.policy.bundle.BundleRejectedException;

/**
 * Pulls a bundle (C7): {@code latest.json} (conditional by ETag), then the archive and the signature it names. Only file names
 * in the directory of {@code latest.json} are followed, redirects never, every body is capped at 16 MiB before anything
 * reads it. The server is not trusted: the signature, the schema and the revision are checked by the bundle library.
 */
public class BundleFetcher {

    public static final int MAX_BYTES = 16 * 1024 * 1024;

    /** What a pull found. {@code etag} goes into the next conditional request. */
    public record Fetched(BundlePointer pointer, byte[] archive, byte[] signature, String etag) {
    }

    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3))
            .followRedirects(HttpClient.Redirect.NEVER).build();

    /**
     * @param directory URL of the channel directory, ending with a slash
     * @param knownEtag ETag of the last {@code latest.json} that was processed, or null
     * @return empty when nothing changed ({@code 304})
     */
    public Optional<Fetched> fetch(URI directory, String knownEtag) throws IOException, InterruptedException, BundleRejectedException {
        URI latest = directory.resolve("latest.json");
        HttpRequest.Builder request = HttpRequest.newBuilder(latest).timeout(Duration.ofSeconds(10)).header("Accept", "application/json");
        if (knownEtag != null) {
            request.header("If-None-Match", knownEtag);
        }
        HttpResponse<InputStream> response = http.send(request.GET().build(), HttpResponse.BodyHandlers.ofInputStream());
        if (response.statusCode() == 304) {
            response.body().close();
            return Optional.empty();
        }
        byte[] latestBody = read(response, "latest.json");
        BundlePointer pointer = BundlePointer.parse(latestBody);
        byte[] archive = get(directory.resolve(pointer.url()), directory);
        byte[] signature = get(directory.resolve(pointer.sigUrl()), directory);
        return Optional.of(new Fetched(pointer, archive, signature, response.headers().firstValue("ETag").orElse(null)));
    }

    private byte[] get(URI file, URI directory) throws IOException, InterruptedException {
        if (!file.toString().startsWith(directory.toString())) {
            throw new IOException("a bundle file outside the channel directory");
        }
        HttpResponse<InputStream> response = http.send(HttpRequest.newBuilder(file).timeout(Duration.ofSeconds(30)).GET().build(),
                HttpResponse.BodyHandlers.ofInputStream());
        return read(response, file.getPath());
    }

    private static byte[] read(HttpResponse<InputStream> response, String what) throws IOException {
        try (InputStream in = new BoundedInputStream(response.body(), MAX_BYTES)) {
            byte[] body = in.readAllBytes();
            if (response.statusCode() != 200) {
                throw new IOException(what + " answered " + response.statusCode());
            }
            return body;
        }
    }
}
