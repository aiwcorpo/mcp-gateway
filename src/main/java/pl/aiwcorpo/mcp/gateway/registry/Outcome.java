package pl.aiwcorpo.mcp.gateway.registry;

/**
 * What an administrator operation of the gateway ended with, before it becomes an HTTP answer. {@code reason} and {@code message} are
 * the ones of the contract's rejection bodies ({@code server_rejected}, {@code scope_mapping_rejected}, {@code override_rejected}).
 */
public record Outcome<T>(Status status, T value, String reason, String message) {

    public enum Status {
        OK, CREATED, NO_CONTENT, NOT_FOUND, EXISTS, PRECONDITION_FAILED, PRECONDITION_REQUIRED, REJECTED, CONFLICT
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
