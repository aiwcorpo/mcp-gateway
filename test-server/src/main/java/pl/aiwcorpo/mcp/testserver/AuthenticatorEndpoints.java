package pl.aiwcorpo.mcp.testserver;

import java.time.Clock;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The authenticator endpoints of the broker (C4: state, verify, invalidate-codes) over {@link Totp}, for the stand-in
 * brokers of the tests and the host demo. Registrations are made by the caller (a test or the demo setup); nothing is stored
 * outside the process.
 */
public final class AuthenticatorEndpoints {

    public record Response(int status, String body) {
    }

    private static final class Registration {
        final String secret;
        Totp.State state = Totp.State.fresh();

        Registration(String secret) {
            this.secret = secret;
        }
    }

    private final Map<String, Registration> registrations = new ConcurrentHashMap<>();
    private final Clock clock;
    private volatile boolean down;
    private volatile boolean invalidateFails;

    public AuthenticatorEndpoints(Clock clock) {
        this.clock = clock;
    }

    public void enroll(String sub, String secretBase32) {
        registrations.put(sub, new Registration(secretBase32));
    }

    public void remove(String sub) {
        registrations.remove(sub);
    }

    /** All authenticator endpoints answer 503. */
    public void down(boolean value) {
        this.down = value;
    }

    /** Only invalidate-codes answers 503. */
    public void invalidateFails(boolean value) {
        this.invalidateFails = value;
    }

    public static boolean handles(String path) {
        return path.startsWith("/v1/authenticator");
    }

    /** {@code sub} is the verified subject of the internal JWT; {@code body} the request body (may be empty). */
    public Response handle(String method, String path, String body, String sub) {
        if (down) {
            return new Response(503, "{\"error\":\"upstream_unavailable\"}");
        }
        Registration registration = registrations.get(sub);
        long now = clock.instant().getEpochSecond();
        if ("GET".equals(method) && "/v1/authenticator".equals(path)) {
            String state = registration == null ? "none" : registration.state.disabled() ? "disabled" : "active";
            return new Response(200, "{\"state\":\"" + state + "\""
                    + (registration == null ? "" : ",\"registeredAt\":\"2026-10-27T09:00:00Z\"")
                    + ("disabled".equals(state) ? ",\"disabledAt\":\"2026-10-28T11:00:00Z\",\"disabledReason\":\"daily_failure_limit\"" : "")
                    + "}");
        }
        if ("POST".equals(method) && "/v1/authenticator/verify".equals(path)) {
            if (registration == null) {
                return new Response(200, "{\"result\":\"not_registered\"}");
            }
            String code = body.replaceAll("(?s).*\"code\"\\s*:\\s*\"([^\"]*)\".*", "$1");
            synchronized (registration) {
                Totp.Verification result = Totp.verify(registration.secret, registration.state, code, now);
                if ("malformed".equals(result.result())) {
                    return new Response(400, "{\"error\":\"invalid_request\"}");
                }
                registration.state = result.state();
                return new Response(200, "{\"result\":\"" + result.result() + "\""
                        + ("locked".equals(result.result()) ? ",\"retryAfterSeconds\":" + result.retryAfterSeconds() : "") + "}");
            }
        }
        if ("POST".equals(method) && "/v1/authenticator/invalidate-codes".equals(path)) {
            if (invalidateFails) {
                return new Response(503, "{\"error\":\"upstream_unavailable\"}");
            }
            if (registration != null) {
                synchronized (registration) {
                    registration.state = Totp.burn(registration.state, now);
                }
            }
            return new Response(204, "");
        }
        return new Response(404, "{\"error\":\"not_found\"}");
    }
}
