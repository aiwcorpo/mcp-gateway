package pl.aiwcorpo.mcp.gateway.registry;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pl.aiwcorpo.mcp.gateway.jwt.InternalTokenIssuer;
import pl.aiwcorpo.mcp.gateway.jwt.UuidV7;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.tls.InternalTls;
import pl.aiwcorpo.mcp.gateway.upstream.BoundedInputStream;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * {@code GET /mcp-manifest} of a server (C6) over mTLS with the service variant of the internal JWT (C2): at the dev bootstrap, and at every
 * check of the definitions of a running server, which compares the hash of its policies with the approved one.
 */
public class ManifestFetcher {

    private static final Logger log = LoggerFactory.getLogger(ManifestFetcher.class);
    private static final int MAX_BYTES = 1024 * 1024;

    private final InternalTls tls;
    private final InternalTokenIssuer tokens;
    private final JsonMapper json;
    /** One client per TLS name: the running servers are read on every check of their definitions, which would build a TLS context each time. */
    private final java.util.Map<String, HttpClient> clients = new java.util.concurrent.ConcurrentHashMap<>();

    public ManifestFetcher(InternalTls tls, InternalTokenIssuer tokens, JsonMapper json) {
        this.tls = tls;
        this.tokens = tokens;
        this.json = json;
    }

    public Optional<JsonNode> fetch(McpServer server) {
        String requestId = UuidV7.next();
        URI url = server.internalUrl().resolve("/mcp-manifest");
        HttpClient http = clients.computeIfAbsent(server.tlsName(), name -> tls.clientFor(name, Duration.ofSeconds(5)));
        HttpRequest request = HttpRequest.newBuilder(url).timeout(Duration.ofSeconds(10))
                .header("Authorization", "Bearer " + tokens.forService(server.serverId(), requestId))
                .header("X-Request-Id", requestId).header("Accept", "application/json").GET().build();
        try {
            HttpResponse<InputStream> response = http.send(request, HttpResponse.BodyHandlers.ofInputStream());
            try (InputStream in = new BoundedInputStream(response.body(), MAX_BYTES)) {
                byte[] body = in.readAllBytes();
                if (response.statusCode() != 200) {
                    log.warn("manifest of {} answered {}", server.serverId(), response.statusCode());
                    return Optional.empty();
                }
                return Optional.of(json.readTree(body));
            }
        } catch (IOException | JacksonException e) {
            log.warn("manifest of {} not fetched: {}", server.serverId(), e.getClass().getSimpleName());
            return Optional.empty();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Optional.empty();
        }
    }
}
