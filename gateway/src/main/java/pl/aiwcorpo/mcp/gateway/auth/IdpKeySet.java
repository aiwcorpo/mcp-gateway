package pl.aiwcorpo.mcp.gateway.auth;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;

import pl.aiwcorpo.mcp.gateway.upstream.BoundedInputStream;

/**
 * Copy of the IdP key set with the fetch rules of CC-124. A token whose key is in a usable copy never waits for the
 * IdP. An unknown {@code kid} (or no usable copy) causes at most one fetch per {@code retryInterval}: when the last
 * fetch succeeded less than that ago the answer is "unknown kid" (the IdP was just asked), when it failed the answer is
 * "unavailable". This keeps a flood of tokens with random {@code kid}s from being multiplied into a flood of requests
 * to the IdP, and keeps an IdP outage from being reported as the client's mistake.
 */
public final class IdpKeySet {

    /** What the key set says about a token header. */
    public sealed interface Lookup {
        /** The keys that may have signed the token (never empty). */
        record Found(List<JWK> keys) implements Lookup {
        }

        record UnknownKid() implements Lookup {
        }

        /** No usable key set and none could be fetched. */
        record Unavailable() implements Lookup {
        }
    }

    private static final Logger log = LoggerFactory.getLogger(IdpKeySet.class);
    private static final int MAX_BODY = 256 * 1024;

    private final Callable<JWKSet> fetcher;
    private final Clock clock;
    private final Duration retryInterval;
    private final Duration freshFor;
    private final Duration usableFor;

    private volatile JWKSet current;
    private volatile Instant currentFetchedAt;
    private Instant lastAttemptAt;
    private boolean lastAttemptSucceeded;

    public IdpKeySet(Callable<JWKSet> fetcher, Clock clock, Duration retryInterval, Duration freshFor, Duration usableFor) {
        long seconds = retryInterval.toSeconds();
        if (seconds < 1 || seconds > 60) {
            throw new IllegalArgumentException("the key fetch retry interval is 1..60 s (CC-124), got " + retryInterval);
        }
        this.fetcher = fetcher;
        this.clock = clock;
        this.retryInterval = retryInterval;
        this.freshFor = freshFor;
        this.usableFor = usableFor;
    }

    public static IdpKeySet overHttp(URI jwksUri, Clock clock, Duration retryInterval, Duration freshFor, Duration usableFor) {
        HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3))
                .followRedirects(HttpClient.Redirect.NEVER).build();
        return new IdpKeySet(() -> fetch(http, jwksUri), clock, retryInterval, freshFor, usableFor);
    }

    private static JWKSet fetch(HttpClient http, URI jwksUri) throws IOException, InterruptedException, ParseException {
        HttpRequest request = HttpRequest.newBuilder(jwksUri).timeout(Duration.ofSeconds(5))
                .header("Accept", "application/json").GET().build();
        HttpResponse<InputStream> response = http.send(request, HttpResponse.BodyHandlers.ofInputStream());
        try (InputStream in = new BoundedInputStream(response.body(), MAX_BODY)) {
            byte[] body = in.readAllBytes();
            if (response.statusCode() != 200) {
                throw new IOException("JWKS answered " + response.statusCode());
            }
            return JWKSet.parse(new String(body, java.nio.charset.StandardCharsets.UTF_8));
        }
    }

    /** Seconds a client should wait before retrying after an unavailable answer. */
    public int retryAfterSeconds() {
        return (int) retryInterval.toSeconds();
    }

    /** The keys of the current copy, for the signature check that follows a {@link Lookup.Found}. */
    public List<JWK> snapshot() {
        JWKSet set = current;
        return set == null ? List.of() : List.copyOf(set.getKeys());
    }

    public Lookup lookup(String kid) {
        Instant now = clock.instant();
        List<JWK> hit = match(kid, usable(now));
        if (!hit.isEmpty() && age(now) <= freshFor.toMillis()) {
            return new Lookup.Found(hit);
        }
        synchronized (this) {
            now = clock.instant();
            JWKSet usable = usable(now);
            hit = match(kid, usable);
            if (!hit.isEmpty() && age(now) <= freshFor.toMillis()) {
                return new Lookup.Found(hit);
            }
            boolean attemptAllowed = lastAttemptAt == null || Duration.between(lastAttemptAt, now).compareTo(retryInterval) >= 0;
            if (!attemptAllowed) {
                if (!hit.isEmpty()) {
                    return new Lookup.Found(hit);
                }
                return lastAttemptSucceeded && usable != null ? new Lookup.UnknownKid() : new Lookup.Unavailable();
            }
            lastAttemptAt = now;
            try {
                JWKSet fetched = fetcher.call();
                current = fetched;
                currentFetchedAt = now;
                lastAttemptSucceeded = true;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                lastAttemptSucceeded = false;
            } catch (Exception e) {
                lastAttemptSucceeded = false;
                log.warn("fetching the IdP key set failed: {}", e.getClass().getSimpleName());
            }
            if (lastAttemptSucceeded) {
                List<JWK> fresh = match(kid, current);
                return fresh.isEmpty() ? new Lookup.UnknownKid() : new Lookup.Found(fresh);
            }
            // The IdP could not be asked: a usable copy that has the key still serves, anything else is an outage.
            return hit.isEmpty() ? new Lookup.Unavailable() : new Lookup.Found(hit);
        }
    }

    private JWKSet usable(Instant now) {
        JWKSet set = current;
        return set != null && age(now) <= usableFor.toMillis() ? set : null;
    }

    private long age(Instant now) {
        Instant fetchedAt = currentFetchedAt;
        return fetchedAt == null ? Long.MAX_VALUE : Duration.between(fetchedAt, now).toMillis();
    }

    /** With a kid: the key of that id. Without one: every key (the signature check decides which one signed). */
    private static List<JWK> match(String kid, JWKSet set) {
        if (set == null) {
            return List.of();
        }
        List<JWK> out = new ArrayList<>();
        for (JWK key : set.getKeys()) {
            if (kid == null || kid.equals(key.getKeyID())) {
                out.add(key);
            }
        }
        return out;
    }
}
