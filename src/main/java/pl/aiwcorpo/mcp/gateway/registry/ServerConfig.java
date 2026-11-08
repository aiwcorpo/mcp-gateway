package pl.aiwcorpo.mcp.gateway.registry;

import java.net.URI;
import java.time.Instant;
import java.util.List;

/**
 * One server as the registry holds it (C5 {@code ServerConfig}): the rows of table {@code servers}. The settings come from the
 * administrator and from the manifest at the time the server was added; the connection and the state of the last check are what the
 * gateway learned by connecting to the address. The tools of the server are not here; they come from its approved manifest.
 *
 * @param status          {@code pending_approval}, {@code connected}, {@code unreachable}, {@code certificate_changed} or {@code manifest_invalid}
 * @param connection      the trust the administrator approved, null until the first approval
 * @param pendingConnection what waits for an approval: the first connection, or a certificate the approved trust did not accept
 */
public record ServerConfig(String serverId, String system, URI internalUrl, Credential credential, boolean enabled, boolean adapter,
                           boolean allowPlainHttp, String status, Instant lastCheckedAt, String lastError, Connection connection,
                           PendingConnection pendingConnection) {

    public static final String PENDING_APPROVAL = "pending_approval";
    public static final String CONNECTED = "connected";
    public static final String UNREACHABLE = "unreachable";
    public static final String CERTIFICATE_CHANGED = "certificate_changed";
    public static final String MANIFEST_INVALID = "manifest_invalid";

    /** {@code type} is the default credential type of the system and goes into {@code context.credentialType} (CC-136). */
    public record Credential(boolean required, List<String> acceptedTypes, String type) {
        public Credential {
            acceptedTypes = List.copyOf(acceptedTypes);
        }
    }

    /** The approved trust. {@code fingerprint} and the certificate fields are null for {@code plain}. */
    public record Connection(String tlsMode, String fingerprint, String subject, String issuer, List<String> sans, Instant notAfter,
                             String approvedBy, Instant approvedAt) {
        public Connection {
            sans = sans == null ? List.of() : List.copyOf(sans);
        }
    }

    /** What the last probe saw and what the gateway proposes to trust; {@code reason} is first_connection, certificate_changed or ca_validation_failed. */
    public record PendingConnection(String tlsMode, String fingerprint, String subject, String issuer, List<String> sans, Instant notAfter,
                                    boolean validatesAsCa, String reason, Instant detectedAt) {
        public PendingConnection {
            sans = sans == null ? List.of() : List.copyOf(sans);
        }
    }

    /** A server added just now: nothing approved, nothing checked beyond the probe that produced {@code pending}. */
    public static ServerConfig added(String serverId, String system, URI url, Credential credential, boolean adapter, boolean allowPlainHttp,
                                     PendingConnection pending, Instant now) {
        return new ServerConfig(serverId, system, url, credential, true, adapter, allowPlainHttp, PENDING_APPROVAL, now, null, null, pending);
    }

    public boolean connectionApproved() {
        return connection != null;
    }

    /**
     * The same server without what the last check saw (its time, the status and the error): that moves with the network and is no change of
     * what the instances hold. The connection and the connection that waits are kept: they decide what a tool may do.
     */
    public ServerConfig withoutObservation() {
        return new ServerConfig(serverId, system, internalUrl, credential, enabled, adapter, allowPlainHttp, PENDING_APPROVAL, null, null,
                connection, pendingConnection);
    }
}
