package pl.aiwcorpo.mcp.testserver;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * The broker's rules for the TOTP authenticator (C4, CC-091, CC-092, CC-126, CC-128) as pure functions, the Java form of
 * {@code scripts/lib/totp.mjs} of mcp-contracts: RFC 6238 with HMAC-SHA-1, 6 digits, 30 s step, a window of one step
 * either way, a step accepted once, 5 wrong codes in 15 minutes lock for 15 minutes, 20 in 24 hours disable. Used by the
 * stand-in broker of the tests and the host demo; the real broker is ws-06.
 */
public final class Totp {

    public static final int STEP_SECONDS = 30;
    private static final String BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final Pattern CODE = Pattern.compile("^[0-9]{6}$");

    private Totp() {
    }

    /** Counters of one user; times are epoch seconds. */
    public record State(Long lastAcceptedStep, List<Long> failures, List<Long> dailyFailures, Long lockedUntil, boolean disabled,
                        Long burnedThrough) {
        public static State fresh() {
            return new State(null, List.of(), List.of(), null, false, null);
        }
    }

    public record Verification(String result, long retryAfterSeconds, State state) {
    }

    public static long stepOf(long epochSeconds) {
        return Math.floorDiv(epochSeconds, STEP_SECONDS);
    }

    public static byte[] base32Decode(String text) {
        int bits = 0;
        int value = 0;
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        for (char ch : text.toCharArray()) {
            int index = BASE32.indexOf(ch);
            if (index < 0) {
                throw new IllegalArgumentException("not Base32");
            }
            value = (value << 5) | index;
            bits += 5;
            if (bits >= 8) {
                out.write((value >>> (bits - 8)) & 0xff);
                bits -= 8;
            }
        }
        return out.toByteArray();
    }

    public static String base32Encode(byte[] bytes) {
        StringBuilder out = new StringBuilder();
        int bits = 0;
        int value = 0;
        for (byte b : bytes) {
            value = (value << 8) | (b & 0xff);
            bits += 8;
            while (bits >= 5) {
                out.append(BASE32.charAt((value >>> (bits - 5)) & 31));
                bits -= 5;
            }
        }
        if (bits > 0) {
            out.append(BASE32.charAt((value << (5 - bits)) & 31));
        }
        return out.toString();
    }

    /** The 6-digit code of one step (leading zeros kept). */
    public static String code(String secretBase32, long step) {
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(base32Decode(secretBase32), "HmacSHA1"));
            byte[] hash = mac.doFinal(ByteBuffer.allocate(8).putLong(step).array());
            int offset = hash[hash.length - 1] & 0x0f;
            int binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16) | ((hash[offset + 2] & 0xff) << 8)
                    | (hash[offset + 3] & 0xff);
            return String.format("%06d", binary % 1_000_000);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The code that is valid at {@code epochSeconds}, as a phone would show it. */
    public static String currentCode(String secretBase32, long epochSeconds) {
        return code(secretBase32, stepOf(epochSeconds));
    }

    /** Greatest step of the window whose code equals the given one, or null. */
    static Long matchingStep(String secret, String code, long epochSeconds) {
        long now = stepOf(epochSeconds);
        for (long step = now + 1; step >= now - 1; step--) {
            if (MessageDigest.isEqual(code(secret, step).getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                    code.getBytes(java.nio.charset.StandardCharsets.US_ASCII))) {
                return step;
            }
        }
        return null;
    }

    public static Verification verify(String secret, State state, String code, long at) {
        if (code == null || !CODE.matcher(code).matches()) {
            return new Verification("malformed", 0, state);
        }
        if (state.disabled()) {
            return new Verification("disabled", 0, state);
        }
        Long lockedUntil = state.lockedUntil();
        List<Long> failures = new ArrayList<>(state.failures());
        if (lockedUntil != null && at < lockedUntil) {
            return new Verification("locked", lockedUntil - at, state);
        }
        if (lockedUntil != null) {
            lockedUntil = null;
            failures = new ArrayList<>();
        }
        Long step = matchingStep(secret, code, at);
        Long last = state.lastAcceptedStep();
        if (step != null && state.burnedThrough() != null && step <= state.burnedThrough()) {
            return new Verification("burned", 0, new State(last, failures, state.dailyFailures(), lockedUntil, false, state.burnedThrough()));
        }
        if (step != null && (last == null || step > last)) {
            return new Verification("ok", 0, new State(step, List.of(), state.dailyFailures(), lockedUntil, false, state.burnedThrough()));
        }
        failures.removeIf(t -> t <= at - 900);
        failures.add(at);
        List<Long> daily = new ArrayList<>(state.dailyFailures());
        daily.removeIf(t -> t <= at - 86400);
        daily.add(at);
        if (failures.size() >= 5) {
            lockedUntil = at + 900;
        }
        boolean disabled = daily.size() >= 20;
        return new Verification(step == null ? "invalid" : "replayed", 0,
                new State(last, failures, daily, lockedUntil, disabled, state.burnedThrough()));
    }

    /** The step of the broker clock and the next one become used; not a failure for any counter (CC-128). */
    public static State burn(State state, long at) {
        long through = Math.max(state.burnedThrough() == null ? -1 : state.burnedThrough(), stepOf(at) + 1);
        long last = Math.max(state.lastAcceptedStep() == null ? -1 : state.lastAcceptedStep(), through);
        return new State(last, state.failures(), state.dailyFailures(), state.lockedUntil(), state.disabled(), through);
    }

    /** First code of a registration: the step it proves, or -1 when it is wrong. */
    public static long enrollmentStep(String secret, String code, long at) {
        if (code == null || !CODE.matcher(code).matches()) {
            return -1;
        }
        Long step = matchingStep(secret, code, at);
        return step == null ? -1 : step;
    }

    /** State of a new registration: counters clean, the lock of the user stays. */
    public static State activate(State previous, long lastAcceptedStep) {
        return new State(lastAcceptedStep, List.of(), List.of(), previous.lockedUntil(), false, null);
    }
}
