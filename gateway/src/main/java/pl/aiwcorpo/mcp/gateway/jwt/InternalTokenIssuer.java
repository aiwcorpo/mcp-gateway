package pl.aiwcorpo.mcp.gateway.jwt;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.function.Supplier;

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
    private final Supplier<String> policyRevision;
    private final Clock clock;

    public InternalTokenIssuer(SigningKeys keys, String issuer, Duration lifetime, Supplier<String> policyRevision, Clock clock) {
        if (lifetime.isNegative() || lifetime.isZero() || lifetime.compareTo(Duration.ofSeconds(60)) > 0) {
            throw new IllegalStateException("internal JWT lifetime must be in (0, 60 s] (C2)");
        }
        this.keys = keys;
        this.issuer = issuer;
        this.lifetime = lifetime;
        this.policyRevision = policyRevision;
        this.clock = clock;
    }

    /** User variant; {@code tool} is the server-side name or null. */
    public String forUser(String audience, GatewayUser user, String tool, String requestId) {
        JWTClaimsSet.Builder claims = common(audience, requestId)
                .subject(user.sub())
                .claim("usr", user.username())
                .claim("grp", user.mcpGroups())
                .claim("azp", user.client());
        if (tool != null) {
            claims.claim("tool", tool);
        }
        return sign(claims.build());
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
                .claim("prv", policyRevision.get())
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
