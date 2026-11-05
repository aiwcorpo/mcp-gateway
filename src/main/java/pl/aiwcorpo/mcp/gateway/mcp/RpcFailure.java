package pl.aiwcorpo.mcp.gateway.mcp;

/** JSON-RPC level error of one request (not a tool error); {@code httpStatus} for the modern transport. */
public class RpcFailure extends Exception {

    private final int code;
    private final int httpStatus;

    public RpcFailure(int code, String message, int httpStatus) {
        super(message);
        this.code = code;
        this.httpStatus = httpStatus;
    }

    public int code() {
        return code;
    }

    public int httpStatus() {
        return httpStatus;
    }
}
