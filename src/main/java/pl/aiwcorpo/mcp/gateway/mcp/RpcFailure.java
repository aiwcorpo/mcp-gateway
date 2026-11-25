package pl.aiwcorpo.mcp.gateway.mcp;

import tools.jackson.databind.JsonNode;

/** JSON-RPC level error of one request (not a tool error); {@code httpStatus} for the modern transport, {@code data} for the {@code error.data} member. */
public class RpcFailure extends Exception {

    private final int code;
    private final int httpStatus;
    private final transient JsonNode data;

    public RpcFailure(int code, String message, int httpStatus) {
        this(code, message, httpStatus, null);
    }

    public RpcFailure(int code, String message, int httpStatus, JsonNode data) {
        super(message);
        this.code = code;
        this.httpStatus = httpStatus;
        this.data = data;
    }

    public int code() {
        return code;
    }

    public int httpStatus() {
        return httpStatus;
    }

    /** Null when the error carries none. */
    public JsonNode data() {
        return data;
    }
}
