package pl.aiwcorpo.mcp.gateway.edge;

import org.springframework.boot.webmvc.error.ErrorController;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;

/**
 * Error pages of the container and of Spring MVC: always {@code application/json}, whatever the client's Accept
 * says (CC-089: never text/html on a public route). The body is the generic Error shape and carries nothing from
 * the request.
 */
@RestController
public class JsonErrorController implements ErrorController {

    @RequestMapping("/error")
    public ResponseEntity<String> error(HttpServletRequest request) {
        Object attribute = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
        int status = attribute instanceof Integer code && code >= 400 && code <= 599 ? code : 500;
        return ResponseEntity.status(status).contentType(MediaType.APPLICATION_JSON).body(body(status));
    }

    public static String body(int status) {
        return "{\"error\":\"" + code(status) + "\"}";
    }

    public static String code(int status) {
        return switch (status) {
            case 401 -> "unauthenticated";
            case 403 -> "access_denied";
            case 404 -> "not_found";
            case 405 -> "method_not_allowed";
            case 406 -> "not_acceptable";
            case 413 -> "payload_too_large";
            case 415 -> "unsupported_media_type";
            case 503 -> "upstream_unavailable";
            default -> status >= 500 ? "internal_error" : "invalid_request";
        };
    }
}
