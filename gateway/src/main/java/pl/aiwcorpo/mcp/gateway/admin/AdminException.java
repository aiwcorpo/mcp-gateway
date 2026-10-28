package pl.aiwcorpo.mcp.gateway.admin;

import org.springframework.http.HttpStatus;

/** Error answer of the C5 admin API: status plus the {@code error} code of the generic Error shape. */
public final class AdminException extends RuntimeException {

    private final HttpStatus status;
    private final String code;

    public AdminException(HttpStatus status, String code) {
        super(code, null, false, false);
        this.status = status;
        this.code = code;
    }

    public HttpStatus status() {
        return status;
    }

    public String code() {
        return code;
    }
}
