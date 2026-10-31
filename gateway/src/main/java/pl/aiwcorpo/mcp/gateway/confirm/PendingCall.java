package pl.aiwcorpo.mcp.gateway.confirm;

import java.util.List;

/**
 * One pending (or recently ended) DESTRUCTIVE call of a user, the unit of C11. Times are epoch milliseconds of the
 * gateway clock. {@code ended} is null while the call waits, else {@code confirmed}, {@code exhausted} or
 * {@code cancelled}. A record that is not waiting stays as a trace until {@code createdAt + TTL + 90 s}: the trace of
 * a viewed call keeps blocking and burning after the call itself is over (CC-127).
 *
 * <p>{@code display} is what the preview shows; it is computed from the arguments the gateway received and holds the
 * values the owner is shown (cut to a limit), never the secret credential or the code.
 */
public record PendingCall(String confirmationId, String serverId, String tool, String risk, String argsSha256,
                          long createdAt, int attemptsLeft, Long previewViewedAt, String ended, boolean burned,
                          String supersededBy, Long cancelledAt, String client, String filter, Display display) {

    public static final String CONFIRMED = "confirmed";
    public static final String EXHAUSTED = "exhausted";
    public static final String CANCELLED = "cancelled";

    public record Display(String qualifiedTool, String system, Resource resource, List<Argument> arguments,
                          String description) {
    }

    public record Resource(String type, String id, String parent) {
    }

    public record Argument(String name, String value, boolean truncated) {
    }

    public boolean sameOperation(String otherServerId, String otherTool, String otherArgsSha256) {
        return serverId.equals(otherServerId) && tool.equals(otherTool) && argsSha256.equals(otherArgsSha256);
    }

    public boolean destructive() {
        return "DESTRUCTIVE".equals(risk);
    }

    public long expiresAt(long ttlMillis) {
        return createdAt + ttlMillis;
    }

    PendingCall withAttemptsLeft(int value) {
        return new PendingCall(confirmationId, serverId, tool, risk, argsSha256, createdAt, value, previewViewedAt, ended,
                burned, supersededBy, cancelledAt, client, filter, display);
    }

    PendingCall withPreviewViewedAt(long value) {
        return new PendingCall(confirmationId, serverId, tool, risk, argsSha256, createdAt, attemptsLeft, value, ended,
                burned, supersededBy, cancelledAt, client, filter, display);
    }

    PendingCall withEnded(String value) {
        return new PendingCall(confirmationId, serverId, tool, risk, argsSha256, createdAt, attemptsLeft, previewViewedAt,
                value, burned, supersededBy, cancelledAt, client, filter, display);
    }

    PendingCall withBurned() {
        return new PendingCall(confirmationId, serverId, tool, risk, argsSha256, createdAt, attemptsLeft, previewViewedAt,
                ended, true, supersededBy, cancelledAt, client, filter, display);
    }

    PendingCall withSupersededBy(String id) {
        return new PendingCall(confirmationId, serverId, tool, risk, argsSha256, createdAt, attemptsLeft, previewViewedAt,
                ended, burned, id, cancelledAt, client, filter, display);
    }

    PendingCall withCancelled(long at) {
        return new PendingCall(confirmationId, serverId, tool, risk, argsSha256, createdAt, attemptsLeft, previewViewedAt,
                CANCELLED, burned, supersededBy, at, client, filter, display);
    }
}
