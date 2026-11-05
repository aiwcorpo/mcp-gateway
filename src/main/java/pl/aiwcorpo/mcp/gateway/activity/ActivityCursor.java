package pl.aiwcorpo.mcp.gateway.activity;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * The cursor of {@code GET /admin/v1/activity/calls} (CC-095): opaque, carries only the position, authenticated by the
 * gateway with HMAC-SHA-256 over (sub, position, issue time), a tag of 128 bits compared in constant time, valid 15 minutes.
 * A cursor that was changed, belongs to another user or is stale is refused; the sub, the filters and the window never come
 * from it.
 */
public final class ActivityCursor {

    public static final long LIFETIME_SECONDS = 900;
    private static final int TAG_BYTES = 16;

    public record Position(String ts, String requestId) {
    }

    private final byte[] key;
    private final JsonMapper json;

    public ActivityCursor(byte[] key, JsonMapper json) {
        if (key.length < 16) {
            throw new IllegalArgumentException("the cursor key needs at least 16 bytes");
        }
        this.key = key.clone();
        this.json = json;
    }

    public String issue(String sub, Position position, long issuedAtEpochSeconds) {
        ObjectNode payload = json.createObjectNode();
        payload.put("ts", position.ts());
        payload.put("requestId", position.requestId());
        payload.put("iat", issuedAtEpochSeconds);
        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(json.writeValueAsString(payload).getBytes(StandardCharsets.UTF_8));
        return encoded + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(tag(sub, encoded));
    }

    /** The position, or empty when the cursor must be answered with 400. */
    public Optional<Position> open(String sub, String cursor, long nowEpochSeconds) {
        String[] parts = cursor.split("\\.", -1);
        if (parts.length != 2 || parts[0].isEmpty() || parts[1].isEmpty()) {
            return Optional.empty();
        }
        try {
            byte[] given = Base64.getUrlDecoder().decode(parts[1]);
            if (!MessageDigest.isEqual(given, tag(sub, parts[0]))) {
                return Optional.empty();
            }
            JsonNode position = json.readTree(new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8));
            if (!position.path("iat").isIntegralNumber()) {
                return Optional.empty();
            }
            long issuedAt = position.path("iat").asLong();
            if (nowEpochSeconds < issuedAt || nowEpochSeconds - issuedAt > LIFETIME_SECONDS) {
                return Optional.empty();
            }
            String ts = position.path("ts").asString(null);
            String requestId = position.path("requestId").asString(null);
            return ts == null || requestId == null ? Optional.empty() : Optional.of(new Position(ts, requestId));
        } catch (IllegalArgumentException | tools.jackson.core.JacksonException e) {
            return Optional.empty();
        }
    }

    private byte[] tag(String sub, String payload) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return Arrays.copyOf(mac.doFinal((sub + "\n" + payload).getBytes(StandardCharsets.UTF_8)), TAG_BYTES);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
