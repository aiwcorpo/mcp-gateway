package pl.aiwcorpo.mcp.gateway.upstream;

/** The MCP server could not be reached or answered outside the protocol; never carries server content. */
public class UpstreamException extends Exception {

    public enum Kind { UNAVAILABLE, REJECTED, PROTOCOL }

    private final Kind kind;

    public UpstreamException(Kind kind, String message) {
        super(message);
        this.kind = kind;
    }

    public Kind kind() {
        return kind;
    }
}
