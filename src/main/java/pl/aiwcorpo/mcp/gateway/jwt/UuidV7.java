package pl.aiwcorpo.mcp.gateway.jwt;

import java.security.SecureRandom;
import java.util.UUID;

/** RFC 9562 version 7 UUIDs: request ids (C2 {@code rid}, C8 {@code requestId}) and jti. */
public final class UuidV7 {

    private static final SecureRandom RANDOM = new SecureRandom();

    private UuidV7() {
    }

    public static String next() {
        long millis = System.currentTimeMillis();
        long randA = RANDOM.nextInt(1 << 12);
        long randB = RANDOM.nextLong() & 0x3FFF_FFFF_FFFF_FFFFL;
        long msb = (millis << 16) | 0x7000L | randA;
        long lsb = 0x8000_0000_0000_0000L | randB;
        return new UUID(msb, lsb).toString();
    }
}
