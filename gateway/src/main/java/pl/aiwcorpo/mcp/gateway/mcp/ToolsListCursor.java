package pl.aiwcorpo.mcp.gateway.mcp;

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
 * The cursor of {@code tools/list} (CC-181): opaque, carries the name of the last tool of the previous page and the canonical
 * filter, authenticated by HMAC-SHA-256 over (sub, payload) with a key every instance shares, a tag of 128 bits compared in constant
 * time, valid 15 minutes. A cursor that is malformed, was changed, is stale or was issued to another user or for another filter is
 * refused, and the caller answers all of them the same way.
 */
public final class ToolsListCursor {

    public static final long LIFETIME_SECONDS = 900;
    private static final int TAG_BYTES = 16;

    private final byte[] key;
    private final JsonMapper json;

    public ToolsListCursor(byte[] key, JsonMapper json) {
        if (key.length < 16) {
            throw new IllegalArgumentException("the cursor key needs at least 16 bytes");
        }
        this.key = key.clone();
        this.json = json;
    }

    public String issue(String sub, String canonicalFilter, String afterName, long issuedAtEpochSeconds) {
        ObjectNode payload = json.createObjectNode();
        payload.put("afterName", afterName);
        payload.put("filter", canonicalFilter);
        payload.put("iat", issuedAtEpochSeconds);
        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(json.writeValueAsString(payload).getBytes(StandardCharsets.UTF_8));
        return encoded + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(tag(sub, encoded));
    }

    /** The name the next page starts after, or empty when the cursor must be refused. */
    public Optional<String> open(String sub, String canonicalFilter, String cursor, long nowEpochSeconds) {
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
            if (!position.path("filter").isString() || !canonicalFilter.equals(position.path("filter").asString())) {
                return Optional.empty();
            }
            String afterName = position.path("afterName").asString(null);
            return position.path("afterName").isString() && !afterName.isEmpty() ? Optional.of(afterName) : Optional.empty();
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
