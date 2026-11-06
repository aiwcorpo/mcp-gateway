package pl.aiwcorpo.mcp.gateway.jwt;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.function.LongSupplier;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;

/**
 * Issues the internal JWT (C2, mcp-contracts 2.0.0): a new token for every HTTP request to a server or the
 * broker. {@code tool} only for tools/call and the broker resolve (CC-038); the service variant only where C2
 * allows it, which the callers decide.
 */
public final class InternalTokenIssuer {

    public static final String SERVICE_SUBJECT = "system:mcp-gateway";

    private final SigningKeys keys;
    private final String issuer;
    private final Duration lifetime;
    private final LongSupplier policyRevision;
    private final Clock clock;

    public InternalTokenIssuer(SigningKeys keys, String issuer, Duration lifetime, LongSupplier policyRevision, Clock clock) {
        if (lifetime.isNegative() || lifetime.isZero() || lifetime.compareTo(Duration.ofSeconds(60)) > 0) {
            throw new IllegalStateException("internal JWT lifetime must be in (0, 60 s] (C2)");
        }
        this.keys = keys;
        this.issuer = issuer;
        this.lifetime = lifetime;
        this.policyRevision = policyRevision;
        this.clock = clock;
    }

    /** User variant; {@code tool} is the server-side name or null. The token carries no endpoint filter (C2 has no claim for it). */
    public String forUser(String audience, GatewayUser user, String tool, String requestId) {
        return forUser(audience, user, tool, requestId, null, null);
    }

    /**
     * As above; {@code risk} and {@code action} are the classification of the administrator of a tool of an adapter (CC-226), given by the
     * caller only for a server in adapter mode. They become {@code mcp_risk} and {@code mcp_action} only together, only as a pair that fits and
     * only with a {@code tool}: anything else is left out, and the sidecar then refuses the call.
     */
    public String forUser(String audience, GatewayUser user, String tool, String requestId, String risk, String action) {
        JWTClaimsSet.Builder claims = common(audience, requestId)
                .subject(user.sub())
                .claim("usr", user.username())
                .claim("grp", user.mcpGroups())
                .claim("azp", user.client());
        if (tool != null) {
            claims.claim("tool", tool);
            if (fits(risk, action)) {
                claims.claim("mcp_risk", risk).claim("mcp_action", action);
            }
        }
        return sign(claims.build());
    }

    /** READ_ONLY with read, UPDATE with update or admin, DESTRUCTIVE with delete or admin (CC-207). */
    private static boolean fits(String risk, String action) {
        return risk != null && action != null && switch (risk) {
            case "READ_ONLY" -> "read".equals(action);
            case "UPDATE" -> "update".equals(action) || "admin".equals(action);
            case "DESTRUCTIVE" -> "delete".equals(action) || "admin".equals(action);
            default -> false;
        };
    }

    /** Service variant (no user): C2 allows it for initialize, tools/list, ping, GET /mcp-manifest and GET /v1/systems. */
    public String forService(String audience, String requestId) {
        return sign(common(audience, requestId).subject(SERVICE_SUBJECT).claim("grp", List.of()).build());
    }

    private JWTClaimsSet.Builder common(String audience, String requestId) {
        Instant now = Instant.now(clock);
        return new JWTClaimsSet.Builder()
                .issuer(issuer)
                .audience(audience)
                .claim("rid", requestId)
                .claim("prv", policyRevision.getAsLong())
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(lifetime)))
                .jwtID(UuidV7.next());
    }

    private String sign(JWTClaimsSet claims) {
        try {
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(keys.active().getKeyID())
                    .type(JOSEObjectType.JWT).build(), claims);
            jwt.sign(new ECDSASigner(keys.active()));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("Signing the internal JWT failed", e);
        }
    }
}
