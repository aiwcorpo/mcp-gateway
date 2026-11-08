package pl.aiwcorpo.mcp.gateway.registry;

/**
 * What an administrator operation of the gateway ended with, before it becomes an HTTP answer. {@code reason} and {@code message} are
 * the ones of the contract's rejection bodies ({@code server_rejected}, {@code scope_mapping_rejected}, {@code override_rejected}).
 */
public record Outcome<T>(Status status, T value, String reason, String message, String manifestReason) {

    /**
     * {@code CONFLICT}: the request is well formed but the state does not fit it; {@code reason} is the error code of the 409.
     * {@code TOO_MANY_REQUESTS}: {@code value} is not set and {@code message} holds the seconds to wait.
     */
    public enum Status {
        OK, CREATED, NO_CONTENT, NOT_FOUND, EXISTS, PRECONDITION_FAILED, PRECONDITION_REQUIRED, REJECTED, CONFLICT, TOO_MANY_REQUESTS
    }

    public Outcome(Status status, T value, String reason, String message) {
        this(status, value, reason, message, null);
    }

    /** A refusal of a manifest: {@code manifestReason} is the cause the contract names (environment_mismatch, policies_invalid, ...). */
    public static <T> Outcome<T> manifestRejected(String message, String manifestReason) {
        return new Outcome<>(Status.REJECTED, null, "manifest_invalid", message, manifestReason);
    }

    public static <T> Outcome<T> conflict(String error) {
        return new Outcome<>(Status.CONFLICT, null, error, null, null);
    }

    public static <T> Outcome<T> ok(T value) {
        return new Outcome<>(Status.OK, value, null, null);
    }

    public static <T> Outcome<T> created(T value) {
        return new Outcome<>(Status.CREATED, value, null, null);
    }

    public static <T> Outcome<T> noContent() {
        return new Outcome<>(Status.NO_CONTENT, null, null, null);
    }

    public static <T> Outcome<T> of(Status status) {
        return new Outcome<>(status, null, null, null);
    }

    public static <T> Outcome<T> rejected(String reason, String message) {
        return new Outcome<>(Status.REJECTED, null, reason, message);
    }

    public boolean succeeded() {
        return status == Status.OK || status == Status.CREATED || status == Status.NO_CONTENT;
    }
}
