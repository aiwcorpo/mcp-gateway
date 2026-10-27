package pl.aiwcorpo.mcp.testserver;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;

import javax.net.ssl.SSLContext;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;

/** Gateway JWKS fetched over HTTPS; refreshed on an unknown kid, at most once per {@code minRefresh}. */
public final class JwksKeySource implements InternalJwtVerifier.KeySource {

    private final URI uri;
    private final HttpClient http;
    private final Duration minRefresh;
    private volatile JWKSet current = new JWKSet();
    private volatile Instant lastFetch = Instant.EPOCH;

    public JwksKeySource(URI uri, SSLContext sslContext, Duration minRefresh) {
        this.uri = uri;
        this.minRefresh = minRefresh;
        this.http = HttpClient.newBuilder().sslContext(sslContext).connectTimeout(Duration.ofSeconds(3))
                .followRedirects(HttpClient.Redirect.NEVER).build();
    }

    @Override
    public JWK find(String kid) {
        JWK key = current.getKeyByKeyId(kid);
        if (key == null && Instant.now().isAfter(lastFetch.plus(minRefresh))) {
            refresh();
            key = current.getKeyByKeyId(kid);
        }
        return key;
    }

    private synchronized void refresh() {
        lastFetch = Instant.now();
        try {
            HttpResponse<String> response = http.send(HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(5)).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                current = JWKSet.parse(response.body());
            } else {
                System.err.println("JWKS " + uri + " answered " + response.statusCode());
            }
        } catch (Exception e) {
            System.err.println("JWKS " + uri + " unreachable: " + e.getClass().getSimpleName());
        }
    }
}
