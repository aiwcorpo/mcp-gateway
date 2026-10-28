package pl.aiwcorpo.mcp.gateway.auth;

import java.text.ParseException;
import java.util.List;
import java.util.Set;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidationException;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;

/**
 * Maps every way the client token can fail to a reason of the C8 authentication event (CC-120). Only the header
 * is read before verification, and only to tell the algorithm; nothing of an unverified token is kept.
 */
public final class ClassifyingJwtDecoder implements JwtDecoder {

    /** Validation failures by precedence: the first one present names the rejection. */
    private static final List<String> VALIDATION_REASONS = List.of("wrong_issuer", "wrong_audience", "expired",
            "not_yet_valid", "invalid_claims");

    private static final Set<JWSAlgorithm> ALLOWED = Set.of(JWSAlgorithm.RS256, JWSAlgorithm.ES256);

    private final JwtDecoder delegate;

    public ClassifyingJwtDecoder(JwtDecoder delegate) {
        this.delegate = delegate;
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
        try {
            return delegate.decode(token);
        } catch (JwtValidationException e) {
            throw new ClientTokenRejection(validationReason(e.getErrors()));
        } catch (BadJwtException e) {
            throw new ClientTokenRejection(decodeReason(e.getMessage()));
        } catch (JwtException e) {
            // Only a failed key fetch is an infrastructure failure; anything else the decoder refuses is the token's.
            if (keySourceFailure(e)) {
                throw new ClientTokenUnavailable();
            }
            throw new ClientTokenRejection("malformed");
        }
    }

    private static boolean keySourceFailure(Throwable failure) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (cause instanceof com.nimbusds.jose.KeySourceException) {
                return true;
            }
        }
        return false;
    }

    /** The validators of the decoder name their failure in the error description; the timestamp validator by its text. */
    private static String validationReason(java.util.Collection<OAuth2Error> errors) {
        Set<String> found = new java.util.HashSet<>();
        for (OAuth2Error error : errors) {
            String description = error.getDescription() == null ? "" : error.getDescription();
            if (description.startsWith("Jwt expired")) {
                found.add("expired");
            } else if (description.startsWith("Jwt used before")) {
                found.add("not_yet_valid");
            } else if (VALIDATION_REASONS.contains(description)) {
                found.add(description);
            } else {
                found.add("invalid_claims");
            }
        }
        return VALIDATION_REASONS.stream().filter(found::contains).findFirst().orElse("invalid_claims");
    }

    /** Nimbus words its refusals; the matches below are pinned by tests against the real decoder. */
    private static String decodeReason(String message) {
        String text = message == null ? "" : message;
        if (text.contains("no matching key")) {
            return "unknown_kid";
        }
        if (text.contains("Invalid signature")) {
            return "bad_signature";
        }
        return "malformed";
    }
}
