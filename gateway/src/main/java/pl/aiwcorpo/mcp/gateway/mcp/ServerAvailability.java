package pl.aiwcorpo.mcp.gateway.mcp;

import java.time.Duration;

/**
 * Whether a server counts as available for one {@code tools/list} (CC-180). The read of its tools/list (taken from the cache within
 * the TTL, or made now) must end with a valid result within the timeout; a timeout, a connection or TLS error, a status other than
 * 200, a body that is not the result of tools/list and a result that does not match the schema all make it unavailable for that list.
 * The server is only skipped: nothing else is concluded about it.
 */
public final class ServerAvailability {

    public enum Outcome { OK, ERROR, INVALID, CACHED }

    private ServerAvailability() {
    }

    public static boolean available(Outcome outcome, Duration elapsed, Duration timeout) {
        if (outcome == Outcome.CACHED) {
            return true;
        }
        return outcome == Outcome.OK && elapsed.compareTo(timeout) <= 0;
    }
}
