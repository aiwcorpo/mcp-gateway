package pl.aiwcorpo.mcp.gateway.auth;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import pl.aiwcorpo.mcp.gateway.agent.PrincipalClassifier;
import pl.aiwcorpo.mcp.gateway.agent.PrincipalClassifier.Classification;

/**
 * Decides, after the claims of a client token were validated, whether the caller is a human or an autonomous agent (CC-266). A token of
 * an agent leaves with the claims {@link GatewayUser#AGENT_CLIENT_CLAIM} and {@link GatewayUser#AGENT_OWNER_CLAIM} and with {@code groups}
 * already cut to the ceiling of the agent, before anything builds the claims for a server or the request for Cedar. The claims are in the
 * token the security chain keeps, not in a subclass of it: the chain copies the token into a principal of its own.
 */
public final class AgentClassifyingDecoder implements JwtDecoder {

    private final JwtDecoder validated;
    private final PrincipalClassifier classifier;

    public AgentClassifyingDecoder(JwtDecoder validated, PrincipalClassifier classifier) {
        this.validated = validated;
        this.classifier = classifier;
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        Jwt jwt = validated.decode(token);
        boolean marked = PrincipalClassifier.MARKER_VALUE.equals(jwt.getClaimAsString(PrincipalClassifier.MARKER_CLAIM));
        return switch (classifier.classify(jwt.getClaimAsString("azp"), jwt.getSubject(), marked, jwt.getIssuedAt(), jwt.getExpiresAt())) {
            case Classification.Human human -> jwt;
            case Classification.Refused refused -> throw new ClientTokenRejection(refused.reason());
            case Classification.Unavailable unavailable -> throw new AgentRegistryUnavailable();
            case Classification.Agent agent -> {
                java.util.List<String> groups = jwt.getClaimAsStringList("groups");
                yield Jwt.withTokenValue(jwt.getTokenValue()).headers(headers -> headers.putAll(jwt.getHeaders()))
                        .claims(claims -> {
                            claims.putAll(jwt.getClaims());
                            claims.put("groups", agent.entry().narrow(groups == null ? java.util.List.of() : groups));
                            claims.put(GatewayUser.AGENT_CLIENT_CLAIM, agent.entry().clientId());
                            claims.put(GatewayUser.AGENT_OWNER_CLAIM, agent.entry().ownerSub());
                        }).issuedAt(jwt.getIssuedAt()).expiresAt(jwt.getExpiresAt()).build();
            }
        };
    }
}
