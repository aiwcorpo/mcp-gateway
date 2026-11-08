package pl.aiwcorpo.mcp.gateway.link;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pl.aiwcorpo.mcp.gateway.jwt.InternalTokenIssuer;
import pl.aiwcorpo.mcp.gateway.jwt.UuidV7;
import pl.aiwcorpo.mcp.gateway.net.AddressPolicy;
import pl.aiwcorpo.mcp.gateway.net.CheckedTunnel;
import pl.aiwcorpo.mcp.gateway.tls.ServerCertificate;
import pl.aiwcorpo.mcp.gateway.tls.ServerTls;
import pl.aiwcorpo.mcp.gateway.upstream.BoundedInputStream;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Everything the gateway does to reach a server outside its MCP endpoint (C14, CC-249): the address check, the TLS probe, the pull of
 * {@code /.well-known/mcp-manifest} and the push of {@code /.well-known/mcp-policy-data}. The well-known paths are at the origin of the
 * {@code internalUrl}, not under its path. The address is judged at the moment of the connection and the connection goes to the address
 * that was judged ({@link CheckedTunnel}: a name is resolved once, by the gateway, never again by the HTTP client), so a name that
 * resolves to an allowed address for the check and to another one afterwards (DNS rebinding) cannot reach a refused address. Every
 * request carries a new token of the right purpose and no client certificate.
 */
public final class ServerLinks implements java.io.Closeable {

    private static final Logger log = LoggerFactory.getLogger(ServerLinks.class);
    private static final int MAX_MANIFEST_BYTES = 1024 * 1024;
    private static final int MAX_ACK_BYTES = 64 * 1024;
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(5);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(10);

    /** Why a pull or a push did not reach the server's answer. */
    public enum Failure { ADDRESS_REFUSED, TLS_HANDSHAKE_FAILED, UNREACHABLE, REJECTED, INVALID }

    /** The result of a pull: the manifest and the certificate the connection was made with, or a failure. */
    public record Pull(JsonNode manifest, Optional<ServerCertificate> certificate, Failure failure, String message) {
        public boolean succeeded() {
            return failure == null;
        }

        static Pull failed(Failure failure, String message) {
            return new Pull(null, Optional.empty(), failure, message);
        }
    }

    /** The result of a push; {@code ack} is the answer of the server when it gave one. */
    public record Push(boolean delivered, int status, JsonNode ack, Failure failure) {
    }

    private final AddressPolicy addresses;
    private final ServerTls tls;
    private final InternalTokenIssuer tokens;
    private final JsonMapper json;
    private final CheckedTunnel tunnel;
    private final Map<String, HttpClient> clients = new ConcurrentHashMap<>();

    public ServerLinks(AddressPolicy addresses, ServerTls tls, InternalTokenIssuer tokens, JsonMapper json) {
        this(addresses, tls, tokens, json, CONNECT_TIMEOUT);
    }

    public ServerLinks(AddressPolicy addresses, ServerTls tls, InternalTokenIssuer tokens, JsonMapper json, Duration connectTimeout) {
        this.addresses = addresses;
        this.tls = tls;
        this.tokens = tokens;
        this.json = json;
        try {
            this.tunnel = new CheckedTunnel(addresses, connectTimeout);
        } catch (IOException e) {
            throw new java.io.UncheckedIOException("cannot open the tunnel to the servers", e);
        }
    }

    @Override
    public void close() throws IOException {
        tunnel.close();
    }

    public AddressPolicy addresses() {
        return addresses;
    }

    public ServerTls tls() {
        return tls;
    }

    /** The host of an address as the address policy wants it: without the brackets of an IPv6 literal. */
    public static String hostOf(URI url) {
        String host = url.getHost();
        return host != null && host.startsWith("[") ? host.substring(1, host.length() - 1) : host;
    }

    public static int portOf(URI url) {
        return url.getPort() != -1 ? url.getPort() : "https".equals(url.getScheme()) ? 443 : 80;
    }

    /**
     * Empty when the host of the address may be connected to now. A look at the moment (the answer the user of the API gets); the
     * connections themselves do not rely on it, they are judged where they are made.
     */
    public Optional<AddressPolicy.Refusal> checkAddress(URI url) {
        return addresses.check(hostOf(url));
    }

    /** The HTTP client for a trust; one per mode and pinned certificate, shared by the servers that use it. */
    public HttpClient client(String tlsMode, String fingerprint) {
        return clients.computeIfAbsent(tlsMode + "|" + fingerprint, key -> tls.client(tlsMode, fingerprint, CONNECT_TIMEOUT, tunnel.selector()));
    }

    /**
     * The URL a request is sent to: an {@code https} URL as it is (the client connects through the tunnel, which judges the address), a
     * plain {@code http} URL with the address that was judged as its host.
     */
    public URI target(URI url) throws IOException {
        try {
            return "https".equalsIgnoreCase(url.getScheme()) ? url : tunnel.pin(url);
        } catch (CheckedTunnel.AddressRefusedException e) {
            throw new AddressRefused(e.refusal());
        }
    }

    /** The address check that refused a connection. */
    public static final class AddressRefused extends IOException {
        private final transient AddressPolicy.Refusal refusal;

        AddressRefused(AddressPolicy.Refusal refusal) {
            super(refusal.message());
            this.refusal = refusal;
        }

        public AddressPolicy.Refusal refusal() {
            return refusal;
        }
    }

    /** A handshake that reads the certificate of an {@code https} address; the address is checked first ({@link AddressRefused}). */
    public ServerTls.Presented probe(URI url) throws IOException {
        AddressPolicy.Resolution resolution = addresses.resolve(hostOf(url));
        if (resolution instanceof AddressPolicy.Resolution.Refused refused) {
            throw new AddressRefused(refused.refusal());
        }
        return tls.probe(hostOf(url), portOf(url), ((AddressPolicy.Resolution.Addresses) resolution).all(), CONNECT_TIMEOUT);
    }

    private static URI wellKnown(URI internalUrl, String name) {
        return internalUrl.resolve("/.well-known/" + name);
    }

    /**
     * {@code GET /.well-known/mcp-manifest} under a trust. {@code audience} is the {@code serverId} the token is for; a server that is not
     * added yet has none (the id comes from its manifest), so the caller then gives a placeholder (see {@code ServerAdmin}).
     */
    public Pull pullManifest(URI internalUrl, String audience, String tlsMode, String fingerprint) {
        URI target;
        try {
            target = target(wellKnown(internalUrl, "mcp-manifest"));
        } catch (AddressRefused e) {
            return Pull.failed(Failure.ADDRESS_REFUSED, e.getMessage());
        } catch (IOException e) {
            return Pull.failed(Failure.UNREACHABLE, "the server could not be reached");
        }
        String requestId = UuidV7.next();
        HttpRequest request = HttpRequest.newBuilder(target).timeout(REQUEST_TIMEOUT)
                .header("Authorization", "Bearer " + tokens.forManifest(audience, requestId)).header("X-Request-Id", requestId)
                .header("Accept", "application/json").GET().build();
        try {
            HttpResponse<InputStream> response = client(tlsMode, fingerprint).send(request, HttpResponse.BodyHandlers.ofInputStream());
            try (InputStream in = new BoundedInputStream(response.body(), MAX_MANIFEST_BYTES)) {
                byte[] body = in.readAllBytes();
                if (response.statusCode() != 200) {
                    return Pull.failed(Failure.REJECTED, "GET /.well-known/mcp-manifest answered " + response.statusCode());
                }
                return new Pull(json.readTree(body), ServerTls.leafOf(response.sslSession()), null, null);
            }
        } catch (JacksonException | BoundedInputStream.LimitExceededException e) {
            return Pull.failed(Failure.INVALID, "the manifest is not a JSON document of a size the gateway takes");
        } catch (IOException e) {
            if (CheckedTunnel.refused(e)) {
                return Pull.failed(Failure.ADDRESS_REFUSED, "the address of the server is refused");
            }
            log.warn("manifest of {} not fetched: {}", hostOf(internalUrl), describe(e));
            return Pull.failed(tlsFailure(e) ? Failure.TLS_HANDSHAKE_FAILED : Failure.UNREACHABLE,
                    tlsFailure(e) ? "the TLS handshake with the server failed" : "the server could not be reached");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Pull.failed(Failure.UNREACHABLE, "interrupted");
        }
    }

    /** {@code POST /.well-known/mcp-policy-data} under the approved trust; {@code revision} is the revision of {@code body} and of the token. */
    public Push pushPolicyData(URI internalUrl, String serverId, String tlsMode, String fingerprint, long revision, JsonNode body) {
        URI target;
        try {
            target = target(wellKnown(internalUrl, "mcp-policy-data"));
        } catch (AddressRefused e) {
            return new Push(false, 0, null, Failure.ADDRESS_REFUSED);
        } catch (IOException e) {
            return new Push(false, 0, null, Failure.UNREACHABLE);
        }
        String requestId = UuidV7.next();
        HttpRequest request = HttpRequest.newBuilder(target).timeout(REQUEST_TIMEOUT)
                .header("Authorization", "Bearer " + tokens.forPolicyData(serverId, requestId, revision)).header("X-Request-Id", requestId)
                .header("Content-Type", "application/json").header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json.writeValueAsString(body))).build();
        try {
            HttpResponse<InputStream> response = client(tlsMode, fingerprint).send(request, HttpResponse.BodyHandlers.ofInputStream());
            try (InputStream in = new BoundedInputStream(response.body(), MAX_ACK_BYTES)) {
                byte[] answer = in.readAllBytes();
                if (response.statusCode() != 200) {
                    log.warn("policy data of {} was refused with {}", serverId, response.statusCode());
                    return new Push(false, response.statusCode(), null, Failure.REJECTED);
                }
                JsonNode ack = answer.length == 0 ? null : json.readTree(answer);
                return new Push(true, 200, ack, null);
            }
        } catch (JacksonException | BoundedInputStream.LimitExceededException e) {
            return new Push(false, 200, null, Failure.INVALID);
        } catch (IOException e) {
            if (CheckedTunnel.refused(e)) {
                return new Push(false, 0, null, Failure.ADDRESS_REFUSED);
            }
            log.warn("policy data of {} not pushed: {}", serverId, describe(e));
            return new Push(false, 0, null, tlsFailure(e) ? Failure.TLS_HANDSHAKE_FAILED : Failure.UNREACHABLE);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new Push(false, 0, null, Failure.UNREACHABLE);
        }
    }

    /** The class of a failure and what its root cause says, for the log: no address or secret is in either. */
    private static String describe(Throwable error) {
        Throwable root = error;
        while (root.getCause() != null && root.getCause() != root) {
            root = root.getCause();
        }
        return error.getClass().getSimpleName() + (root == error ? "" : " caused by " + root.getClass().getSimpleName() + ": " + root.getMessage());
    }

    /** Whether a failure of the connection is a failure of TLS (the certificate, the protocol) and not of the network. */
    public static boolean tlsFailure(Throwable error) {
        for (Throwable cause = error; cause != null; cause = cause.getCause() == cause ? null : cause.getCause()) {
            if (cause instanceof javax.net.ssl.SSLException) {
                return true;
            }
        }
        return false;
    }
}
