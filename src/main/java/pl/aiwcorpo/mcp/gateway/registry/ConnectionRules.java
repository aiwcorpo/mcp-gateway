package pl.aiwcorpo.mcp.gateway.registry;

import java.util.Objects;

import pl.aiwcorpo.mcp.gateway.tls.ServerTls;

/**
 * The rules of the connection of a server (C5, CC-249) as functions without I/O: what the gateway proposes for a certificate, whether an
 * approval is acceptable, what a certificate that the server presents does to an approved connection, and when a tool is listed and callable.
 */
public final class ConnectionRules {

    /** What a handshake showed: the fingerprint of the leaf, and whether it validates as {@code ca} for the host of the address. */
    public record Seen(String fingerprint, boolean validatesAsCa) {
    }

    /** The answer to an approval: either the approved trust, or the refusal as the admin API gives it. */
    public sealed interface Approval {
        record Accepted(String tlsMode, String fingerprint) implements Approval {
        }

        record Refused(int status, String error, String reason) implements Approval {
        }
    }

    /**
     * What a check of an approved connection concludes. {@code pendingMode} and {@code pendingReason} are set when the certificate needs an
     * approval; {@code refreshed} is true when a {@code ca} server shows another certificate than the one on record (nothing to approve).
     */
    public record Check(String status, String pendingMode, String pendingReason, boolean refreshed) {
    }

    /** Whether a tool is shown to a user who may call it, and the error code a call gets when it cannot be made. */
    public record Availability(boolean listed, String errorCode, String disabledBy) {
    }

    private ConnectionRules() {
    }

    /** {@code ca} when the certificate validates for the host, else {@code pinned}; {@code plain} for an {@code http} address. */
    public static String proposal(boolean https, boolean validatesAsCa) {
        return !https ? ServerTls.PLAIN : validatesAsCa ? ServerTls.CA : ServerTls.PINNED;
    }

    /**
     * The approval of the pending connection. The body repeats the fingerprint the administrator saw ({@code 409 connection_changed}
     * when it is not the pending one); the mode may be the proposed one or {@code pinned} instead of {@code ca}; {@code ca} needs a
     * certificate that validates, {@code plain} an {@code http} address added with {@code allowPlainHttp} ({@code 422 tls_mode_not_allowed}).
     */
    public static Approval approve(ServerConfig.PendingConnection pending, String tlsMode, String fingerprint, boolean https,
                                   boolean addedWithAllowPlainHttp) {
        if (pending == null) {
            return new Approval.Refused(409, "no_pending_connection", null);
        }
        if (!Objects.equals(pending.fingerprint(), fingerprint)) {
            return new Approval.Refused(409, "connection_changed", null);
        }
        boolean allowed = switch (tlsMode) {
            case ServerTls.CA -> https && pending.validatesAsCa();
            case ServerTls.PINNED -> https && fingerprint != null;
            case ServerTls.PLAIN -> !https && addedWithAllowPlainHttp && fingerprint == null;
            default -> false;
        };
        return allowed ? new Approval.Accepted(tlsMode, fingerprint) : new Approval.Refused(422, "server_rejected", "tls_mode_not_allowed");
    }

    /**
     * The certificate an approved connection met. {@code plain} has none. {@code ca} stays connected while the certificate validates (a
     * renewal needs nothing) and otherwise proposes {@code pinned}; {@code pinned} stays connected for the pinned certificate only, and
     * another one is proposed as {@code ca} when it validates, as {@code pinned} when it does not, and is never accepted unseen.
     */
    public static Check check(String approvedMode, String approvedFingerprint, Seen presented) {
        return switch (approvedMode) {
            case ServerTls.PLAIN -> new Check(ServerConfig.CONNECTED, null, null, false);
            case ServerTls.CA -> presented.validatesAsCa()
                    ? new Check(ServerConfig.CONNECTED, null, null, !presented.fingerprint().equals(approvedFingerprint))
                    : new Check(ServerConfig.CERTIFICATE_CHANGED, ServerTls.PINNED, "ca_validation_failed", false);
            case ServerTls.PINNED -> presented.fingerprint().equals(approvedFingerprint)
                    ? new Check(ServerConfig.CONNECTED, null, null, false)
                    : new Check(ServerConfig.CERTIFICATE_CHANGED, presented.validatesAsCa() ? ServerTls.CA : ServerTls.PINNED,
                            "certificate_changed", false);
            default -> throw new IllegalArgumentException("unknown trust " + approvedMode);
        };
    }

    /**
     * A tool is listed and callable only when the connection, the policies and the tool are all approved: until then the call is
     * {@code tool_disabled} (disabledBy approval). An approved tool of a server that cannot be reached, or whose certificate the approved
     * trust does not accept, is still listed and the call is {@code upstream_unavailable}.
     *
     * @param serverStatus the status of the server, or null
     */
    public static Availability availability(boolean connectionApproved, boolean policiesApproved, String toolStatus, String serverStatus) {
        if (!connectionApproved || !policiesApproved || !"approved".equals(toolStatus)) {
            return new Availability(false, "tool_disabled", "approval");
        }
        boolean down = ServerConfig.UNREACHABLE.equals(serverStatus) || ServerConfig.CERTIFICATE_CHANGED.equals(serverStatus);
        return new Availability(true, down ? "upstream_unavailable" : null, null);
    }
}
