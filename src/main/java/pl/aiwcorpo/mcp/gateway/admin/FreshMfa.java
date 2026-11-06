package pl.aiwcorpo.mcp.gateway.admin;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;

import org.springframework.security.oauth2.jwt.Jwt;

import pl.aiwcorpo.mcp.gateway.audit.AuditEvent;
import pl.aiwcorpo.mcp.gateway.audit.AuditLog;
import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import tools.jackson.databind.JsonNode;

/**
 * Fresh MFA of the administrator (C5, CC-239, CC-240) for the operations that widen access. The portal asks for it, and the gateway checks it
 * itself on the token it gets: the user authenticated at most 300 s ago ({@code auth_time}) <em>and</em> the token proves a second factor:
 * an {@code acr} among the configured MFA levels, or an {@code amr} with one of the configured methods. A token without {@code auth_time}, with
 * one in the future beyond the clock skew, or without proof of MFA is not fresh (a fresh password-only login is not MFA); the answer is
 * {@code 401 step_up_required} and the refusal is audited.
 */
public final class FreshMfa {

    public static final Duration MAX_AGE = Duration.ofSeconds(300);
    private static final Duration SKEW = Duration.ofSeconds(60);

    private final Set<String> acrValues;
    private final Set<String> amrValues;
    private final Clock clock;
    private final AuditLog audit;
    private final String componentId;

    public FreshMfa(List<String> acrValues, List<String> amrValues, Clock clock, AuditLog audit, String componentId) {
        this.acrValues = Set.copyOf(acrValues.stream().filter(value -> !value.isBlank()).toList());
        this.amrValues = Set.copyOf(amrValues.stream().filter(value -> !value.isBlank()).toList());
        this.clock = clock;
        this.audit = audit;
        this.componentId = componentId;
    }

    public boolean fresh(Jwt token) {
        if (token == null) {
            return false;
        }
        Instant authenticated = authTime(token.getClaim("auth_time"));
        Instant now = clock.instant();
        if (authenticated == null || authenticated.isAfter(now.plus(SKEW)) || Duration.between(authenticated, now).compareTo(MAX_AGE) > 0) {
            return false;
        }
        return provesMfa(token);
    }

    private boolean provesMfa(Jwt token) {
        Object acr = token.getClaim("acr");
        if (acr instanceof String level && acrValues.contains(level)) {
            return true;
        }
        Object amr = token.getClaim("amr");
        if (amr instanceof String method) {
            return amrValues.contains(method);
        }
        if (amr instanceof java.util.Collection<?> methods) {
            return methods.stream().anyMatch(method -> method instanceof String text && amrValues.contains(text));
        }
        return false;
    }

    private static Instant authTime(Object claim) {
        if (claim instanceof Instant instant) {
            return instant;
        }
        if (claim instanceof Number seconds) {
            return Instant.ofEpochSecond(seconds.longValue());
        }
        return null;
    }

    /** Records the refusal; nothing of the token goes into the event but who asked and for what. */
    public void refused(Jwt token, String requestId, String operation) {
        audit.emit(AuditEvent.of("admin_change", requestId, componentId).userWithoutClient(GatewayUser.from(token))
                .reason("step_up_required").outcome("denied"));
        org.slf4j.LoggerFactory.getLogger(FreshMfa.class).warn("{} refused: the administrator token is not a fresh MFA", operation);
    }

    /** A PATCH of a server that only switches it off needs no fresh MFA: it narrows access (CC-240). */
    public static boolean onlyDisables(JsonNode body) {
        return body != null && body.isObject() && body.size() == 1 && body.has("enabled") && body.get("enabled").isBoolean()
                && !body.get("enabled").asBoolean();
    }
}
