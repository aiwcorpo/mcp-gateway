package pl.aiwcorpo.mcp.gateway.agent;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * Who a validated client token belongs to (CC-266). After {@code iss}, {@code aud} and {@code exp} a token is an agent when its
 * {@code azp} is an entry of the registry, its {@code sub} is the service account of that entry, the identity provider marked it with
 * {@code principal_type: agent} and it lives at most 300 s. Anything that half fits is refused, never read as a human: a known
 * agent {@code azp} without the marker, the marker on an {@code azp} outside the registry, another {@code sub}, a longer lifetime. A
 * suspended agent is classified as an agent: the refusal belongs to the request (it needs the tool for its events), not to the token.
 * A registry that cannot be read leaves no way to tell, so a token that looks like an agent's is not accepted (fail-closed) and a
 * human client is not affected.
 */
public final class PrincipalClassifier {

    public static final Duration MAX_AGENT_TOKEN_LIFETIME = Duration.ofSeconds(300);
    public static final String MARKER_CLAIM = "principal_type";
    public static final String MARKER_VALUE = "agent";

    public sealed interface Classification {
        record Human() implements Classification {
        }

        record Agent(AgentClient entry) implements Classification {
        }

        /** 401; {@code reason} is {@code agent_not_registered} or {@code agent_token_lifetime}. */
        record Refused(String reason) implements Classification {
        }

        /** 503: the registry cannot be read. */
        record Unavailable() implements Classification {
        }
    }

    private static final Duration DEFAULT_SKEW = Duration.ofSeconds(60);

    private final AgentRegistry registry;
    private final Clock clock;
    private final Duration skew;

    public PrincipalClassifier(AgentRegistry registry) {
        this(registry, Clock.systemUTC(), DEFAULT_SKEW);
    }

    /** @param skew the clock skew the token validation allows; an agent token may not end later than the lifetime plus this from now */
    public PrincipalClassifier(AgentRegistry registry, Clock clock, Duration skew) {
        this.registry = registry;
        this.clock = clock;
        this.skew = skew;
    }

    public Classification classify(String azp, String sub, boolean marked, Instant issuedAt, Instant expiresAt) {
        switch (registry.find(azp)) {
            case AgentRegistry.Lookup.Unreadable unreadable -> {
                return marked || AgentClient.CLIENT_ID.matcher(azp).matches() ? new Classification.Unavailable() : new Classification.Human();
            }
            case AgentRegistry.Lookup.Absent absent -> {
                return marked ? new Classification.Refused("agent_not_registered") : new Classification.Human();
            }
            case AgentRegistry.Lookup.Found found -> {
                AgentClient entry = found.agent();
                if (!marked || !entry.serviceAccountSub().equals(sub)) {
                    return new Classification.Refused("agent_not_registered");
                }
                // iat is the token's own claim, so the end is also bounded from the clock of the gateway: an iat in the past cannot stretch it.
                if (Duration.between(issuedAt, expiresAt).compareTo(MAX_AGENT_TOKEN_LIFETIME) > 0
                        || Duration.between(clock.instant(), expiresAt).compareTo(MAX_AGENT_TOKEN_LIFETIME.plus(skew)) > 0) {
                    return new Classification.Refused("agent_token_lifetime");
                }
                return new Classification.Agent(entry);
            }
        }
    }
}
