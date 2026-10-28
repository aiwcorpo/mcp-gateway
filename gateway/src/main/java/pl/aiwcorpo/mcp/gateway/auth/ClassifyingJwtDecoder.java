package pl.aiwcorpo.mcp.gateway.auth;

import java.security.Key;
import java.text.ParseException;
import java.util.List;
import java.util.Set;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidationException;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;

/**
 * Maps every way the client token can fail to a reason of the C8 authentication event (CC-120) and decides, in the
 * order of CC-124, between 401 and 503: checks that need no key (format, algorithm) come first, then the key lookup
 * in {@link IdpKeySet}, then the signature, then the claims. Only the header is read before the signature is
 * verified, and nothing of an unverified token is kept. No reason is taken from the wording of a library message:
 * the key lookup and the signature check are done here, and every claim validator names its own failure.
 */
public final class ClassifyingJwtDecoder implements JwtDecoder {

    /** Validation failures by precedence: the first one present names the rejection. */
    private static final List<String> VALIDATION_REASONS = List.of("wrong_issuer", "wrong_audience", "expired",
            "not_yet_valid", "invalid_claims");

    private static final Set<JWSAlgorithm> ALLOWED = Set.of(JWSAlgorithm.RS256, JWSAlgorithm.ES256);

    private final IdpKeySet keys;
    private final JwtDecoder claimsDecoder;
    private final DefaultJWSVerifierFactory verifiers = new DefaultJWSVerifierFactory();

    /** {@code claimsDecoder} checks the signature again (against the same copy of the keys) and the claims. */
    public ClassifyingJwtDecoder(IdpKeySet keys, JwtDecoder claimsDecoder) {
        this.keys = keys;
        this.claimsDecoder = claimsDecoder;
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        JWT parsed;
        try {
            parsed = JWTParser.parse(token);
        } catch (ParseException e) {
            throw new ClientTokenRejection("malformed");
        }
        if (!(parsed instanceof SignedJWT signed) || !ALLOWED.contains(signed.getHeader().getAlgorithm())) {
            throw new ClientTokenRejection("alg_not_allowed");
        }
        switch (keys.lookup(signed.getHeader().getKeyID())) {
            case IdpKeySet.Lookup.Unavailable unavailable -> throw new ClientTokenUnavailable(keys.retryAfterSeconds());
            case IdpKeySet.Lookup.UnknownKid unknown -> throw new ClientTokenRejection("unknown_kid");
            case IdpKeySet.Lookup.Found found -> {
                if (found.keys().stream().noneMatch(key -> verifies(signed, key))) {
                    throw new ClientTokenRejection("bad_signature");
                }
            }
        }
        try {
            return claimsDecoder.decode(token);
        } catch (JwtValidationException e) {
            throw new ClientTokenRejection(validationReason(e.getErrors()));
        } catch (BadJwtException e) {
            throw new ClientTokenRejection("malformed");
        }
    }

    private boolean verifies(SignedJWT token, JWK key) {
        try {
            Key verificationKey = switch (key) {
                case RSAKey rsa -> rsa.toPublicKey();
                case ECKey ec -> ec.toPublicKey();
                default -> null;
            };
            if (verificationKey == null) {
                return false;
            }
            JWSVerifier verifier = verifiers.createJWSVerifier(token.getHeader(), verificationKey);
            return token.verify(verifier);
        } catch (JOSEException | RuntimeException e) {
            return false;
        }
    }

    private static String validationReason(java.util.Collection<OAuth2Error> errors) {
        Set<String> found = new java.util.HashSet<>();
        for (OAuth2Error error : errors) {
            String description = error.getDescription() == null ? "" : error.getDescription();
            found.add(VALIDATION_REASONS.contains(description) ? description : "invalid_claims");
        }
        return VALIDATION_REASONS.stream().filter(found::contains).findFirst().orElse("invalid_claims");
    }
}
