package pl.aiwcorpo.mcp.gateway.redis;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/** Redis key parts: a sub or a tool name is never in a key name, only its SHA-256. */
public final class KeyHash {

    private KeyHash() {
    }

    public static String of(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
