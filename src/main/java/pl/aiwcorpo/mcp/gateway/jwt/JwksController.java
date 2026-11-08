package pl.aiwcorpo.mcp.gateway.jwt;

import java.time.Duration;
import java.util.Map;

import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Public keys of the internal JWT (C2). The servers fetch them from the public address of the platform, {@link #PUBLIC_PATH} (C14,
 * CC-249), which the reverse proxy forwards to the public port; the same document is on the internal TLS port at {@link #PATH}, where
 * the credential broker takes it from, and at {@link #PUBLIC_PATH} too ({@link InternalPortFilter}).
 */
@RestController
public class JwksController {

    public static final String PATH = "/.well-known/jwks.json";
    public static final String PUBLIC_PATH = "/.well-known/mcp-jwks.json";

    private final SigningKeys keys;

    public JwksController(SigningKeys keys) {
        this.keys = keys;
    }

    @GetMapping(path = {PATH, PUBLIC_PATH}, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> jwks() {
        return ResponseEntity.ok().cacheControl(CacheControl.maxAge(Duration.ofMinutes(5)).cachePublic())
                .body(keys.publicJwks().toJSONObject(true));
    }
}
