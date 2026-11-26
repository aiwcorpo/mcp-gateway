package pl.aiwcorpo.mcp.gateway.primitive;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * Matching of a value against a pattern that an author wrote. The grammar checked at approval keeps patterns linear, but a pattern that slipped
 * through (an older approval, a row changed in the database) must cost a bounded time and no stack: the match gives up after a deadline, and a
 * stack overflow of the engine is a refusal. Either is "does not match", never an error that reaches the client.
 */
public final class BoundedMatch {

    static final Duration DEADLINE = Duration.ofMillis(100);
    private static final int MAX_COMPILED = 2048;
    private static final Map<String, Pattern> COMPILED = new ConcurrentHashMap<>();

    private BoundedMatch() {
    }

    private static final class DeadlineExceeded extends RuntimeException {
        DeadlineExceeded() {
            super(null, null, false, false);
        }
    }

    /** Each pattern is compiled once; the cache is bounded, so patterns of removed entries do not pile up. */
    public static Pattern compile(String regex) {
        if (COMPILED.size() >= MAX_COMPILED) {
            COMPILED.clear();
        }
        return COMPILED.computeIfAbsent(regex, Pattern::compile);
    }

    public static boolean matches(String regex, String text) {
        return matches(compile(regex), text);
    }

    public static boolean matches(Pattern pattern, String text) {
        long deadline = System.nanoTime() + DEADLINE.toNanos();
        CharSequence bounded = new CharSequence() {
            private int reads;

            @Override
            public int length() {
                return text.length();
            }

            @Override
            public char charAt(int index) {
                // The clock is read every few hundred characters: it costs more than the read of one.
                if ((++reads & 0xff) == 0 && System.nanoTime() > deadline) {
                    throw new DeadlineExceeded();
                }
                return text.charAt(index);
            }

            @Override
            public CharSequence subSequence(int start, int end) {
                return text.subSequence(start, end);
            }

            @Override
            public String toString() {
                return text;
            }
        };
        try {
            return pattern.matcher(bounded).matches();
        } catch (DeadlineExceeded | StackOverflowError e) {
            return false;
        }
    }
}
