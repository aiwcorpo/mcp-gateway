package pl.aiwcorpo.mcp.gateway.jwt;

import java.time.Duration;
import java.util.Map;

import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** Public keys of the internal JWT (C2); served only on the internal TLS port ({@link InternalPortFilter}). */
@RestController
public class JwksController {

    public static final String PATH = "/.well-known/jwks.json";

    private final SigningKeys keys;

    public JwksController(SigningKeys keys) {
        this.keys = keys;
    }

    @GetMapping(path = PATH, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> jwks() {
        return ResponseEntity.ok().cacheControl(CacheControl.maxAge(Duration.ofMinutes(5)))
                .body(keys.publicJwks().toJSONObject(true));
    }
}
