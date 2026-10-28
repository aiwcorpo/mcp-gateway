package pl.aiwcorpo.mcp.gateway.admin;

import org.springframework.http.HttpStatus;

/** Error answer of the C5 admin API: status plus the {@code error} code of the generic Error shape. */
public final class AdminException extends RuntimeException {

    private final HttpStatus status;
    private final String code;
    private final String auditReason;

    public AdminException(HttpStatus status, String code) {
        this(status, code, code);
    }

    /** {@code auditReason} is the C8 reason of the virtual_server_change event; it may be finer than the client-visible code. */
    public AdminException(HttpStatus status, String code, String auditReason) {
        super(code, null, false, false);
        this.status = status;
        this.code = code;
        this.auditReason = auditReason;
    }

    public HttpStatus status() {
        return status;
    }

    public String code() {
        return code;
    }

    public String auditReason() {
        return auditReason;
    }
}
