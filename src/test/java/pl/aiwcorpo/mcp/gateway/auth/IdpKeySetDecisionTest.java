package pl.aiwcorpo.mcp.gateway.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

import pl.aiwcorpo.mcp.gateway.support.Vectors;
import tools.jackson.databind.JsonNode;

/** CC-124: the key decision of gateway-authentication-decision/ driven through the real key set with a fake IdP and clock. */
class IdpKeySetDecisionTest {

    private static final Duration INTERVAL = Duration.ofSeconds(10);
    private static final Duration FRESH = Duration.ofMinutes(5);
    private static final Duration USABLE = Duration.ofHours(1);
    private static final Instant T0 = Instant.parse("2026-10-28T12:00:00Z");

    /** Mutable clock and IdP behind one key set. */
    private static final class Fixture {
        final AtomicReference<Instant> now = new AtomicReference<>(T0);
        final AtomicReference<String> publishedKid = new AtomicReference<>("known-kid");
        final AtomicReference<Boolean> idpUp = new AtomicReference<>(true);
        final AtomicInteger fetches = new AtomicInteger();
        final IdpKeySet keys;

        Fixture() {
            Clock clock = new Clock() {
                @Override
                public java.time.ZoneId getZone() {
                    return ZoneOffset.UTC;
                }

                @Override
                public Clock withZone(java.time.ZoneId zone) {
                    return this;
                }

                @Override
                public Instant instant() {
                    return now.get();
                }
            };
            keys = new IdpKeySet(() -> {
                fetches.incrementAndGet();
                if (!idpUp.get()) {
                    throw new java.io.IOException("down");
                }
                return new JWKSet(new ECKeyGenerator(Curve.P_256).keyID(publishedKid.get()).generate().toPublicJWK());
            }, clock, INTERVAL, FRESH, USABLE);
        }

        void advance(Duration by) {
            now.set(now.get().plus(by));
        }
    }

    @TestFactory
    List<DynamicTest> decisionVectors() {
        List<DynamicTest> tests = new ArrayList<>();
        for (Vectors.Vector vector : Vectors.of("gateway-authentication-decision")) {
            JsonNode input = vector.document().path("input");
            if (input.has("independentReason")) {
                continue;
            }
            tests.add(DynamicTest.dynamicTest(vector.name(), () -> decide(vector.document())));
        }
        assertThat(tests).hasSizeGreaterThanOrEqualTo(8);
        return tests;
    }

    private static void decide(JsonNode vector) {
        JsonNode input = vector.path("input");
        String refresh = input.path("refresh").asString(null);
        boolean usableCache = "usable".equals(input.path("keyCache").asString());
        boolean knownKid = "known".equals(input.path("kid").asString());
        Fixture fixture = new Fixture();
        String asked = knownKid ? "known-kid" : "unknown-kid";

        if (usableCache) {
            assertThat(fixture.keys.lookup("known-kid")).isInstanceOf(IdpKeySet.Lookup.Found.class);
            fixture.fetches.set(0);
        }
        switch (refresh == null ? "none" : refresh) {
            case "skipped-after-success" -> fixture.advance(Duration.ofSeconds(1));
            case "skipped-after-failure" -> {
                fixture.advance(Duration.ofMinutes(10));
                fixture.idpUp.set(false);
                assertThat(fixture.keys.lookup("another-unknown-kid")).isInstanceOf(IdpKeySet.Lookup.Unavailable.class);
                fixture.advance(Duration.ofSeconds(1));
            }
            case "failed" -> {
                fixture.advance(Duration.ofMinutes(10));
                fixture.idpUp.set(false);
            }
            case "ok-kid-found" -> {
                fixture.advance(Duration.ofSeconds(30));
                fixture.publishedKid.set(asked);
            }
            case "ok-kid-missing" -> fixture.advance(Duration.ofSeconds(30));
            default -> {
            }
        }
        IdpKeySet.Lookup result = fixture.keys.lookup(asked);

        String expectedReason = vector.path("expected").path("reason").asString(null);
        if (expectedReason == null) {
            assertThat(result).as(vector.path("description").asString()).isInstanceOf(IdpKeySet.Lookup.Found.class);
        } else if ("jwks_unavailable".equals(expectedReason)) {
            assertThat(result).as(vector.path("description").asString()).isInstanceOf(IdpKeySet.Lookup.Unavailable.class);
        } else {
            assertThat(expectedReason).isEqualTo("unknown_kid");
            assertThat(result).as(vector.path("description").asString()).isInstanceOf(IdpKeySet.Lookup.UnknownKid.class);
        }
        if ("skipped-after-success".equals(refresh) || "skipped-after-failure".equals(refresh)) {
            assertThat(fixture.fetches.get()).as("no new fetch inside the interval").isLessThanOrEqualTo(
                    "skipped-after-failure".equals(refresh) ? 1 : 0);
        }
    }

    @Test
    void aFloodOfRandomKidsIsAtMostOneFetchPerInterval() {
        Fixture fixture = new Fixture();
        assertThat(fixture.keys.lookup("known-kid")).isInstanceOf(IdpKeySet.Lookup.Found.class);
        fixture.fetches.set(0);
        fixture.advance(Duration.ofSeconds(30));
        for (int i = 0; i < 200; i++) {
            fixture.keys.lookup("random-" + i);
        }
        assertThat(fixture.fetches.get()).isEqualTo(1);
        fixture.advance(INTERVAL);
        fixture.keys.lookup("random-again");
        assertThat(fixture.fetches.get()).isEqualTo(2);
    }

    @Test
    void aCopyOlderThanTheUsableLimitIsNotUsedEvenForAKnownKid() {
        Fixture fixture = new Fixture();
        fixture.keys.lookup("known-kid");
        fixture.idpUp.set(false);
        fixture.advance(USABLE.plusMinutes(1));
        assertThat(fixture.keys.lookup("known-kid")).isInstanceOf(IdpKeySet.Lookup.Unavailable.class);
    }

    @Test
    void theRetryIntervalIsOneToSixtySeconds() {
        for (Duration bad : List.of(Duration.ZERO, Duration.ofMillis(900), Duration.ofSeconds(61))) {
            assertThatThrownBy(() -> new IdpKeySet(() -> new JWKSet(), Clock.systemUTC(), bad, FRESH, USABLE))
                    .isInstanceOf(IllegalArgumentException.class);
        }
        assertThat(new IdpKeySet(() -> new JWKSet(), Clock.systemUTC(), Duration.ofSeconds(60), FRESH, USABLE).retryAfterSeconds())
                .isEqualTo(60);
    }

    @Test
    void checksThatNeedNoKeyComeBeforeTheKeyLookup() throws Exception {
        Fixture fixture = new Fixture();
        fixture.idpUp.set(false);
        JwtDecoder never = token -> {
            throw new AssertionError("claims are not read before the key is found");
        };
        ClassifyingJwtDecoder decoder = new ClassifyingJwtDecoder(fixture.keys, never);
        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("x").build();

        assertThatThrownBy(() -> decoder.decode("not-a-jwt")).isInstanceOf(ClientTokenRejection.class)
                .extracting(e -> ((ClientTokenRejection) e).reason()).isEqualTo("malformed");
        assertThatThrownBy(() -> decoder.decode(new PlainJWT(claims).serialize())).isInstanceOf(ClientTokenRejection.class)
                .extracting(e -> ((ClientTokenRejection) e).reason()).isEqualTo("alg_not_allowed");
        assertThat(fixture.fetches.get()).as("the IdP was not asked").isZero();

        ECKey stranger = new ECKeyGenerator(Curve.P_256).keyID("stranger").generate();
        SignedJWT signed = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("stranger").build(), claims);
        signed.sign(new ECDSASigner(stranger));
        assertThatThrownBy(() -> decoder.decode(signed.serialize())).isInstanceOf(ClientTokenUnavailable.class)
                .extracting(e -> ((ClientTokenUnavailable) e).retryAfterSeconds()).isEqualTo(10);
    }
}
