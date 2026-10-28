package pl.aiwcorpo.mcp.gateway.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.Test;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

class AuthenticationEventLimiterTest {

    private final AtomicLong nanos = new AtomicLong();
    private final SimpleMeterRegistry meters = new SimpleMeterRegistry();
    private final AuthenticationEventLimiter limiter = new AuthenticationEventLimiter(3, Duration.ofMinutes(1), nanos::get, meters);

    private double suppressed(String reason) {
        var counter = meters.find(AuthenticationEventLimiter.METRIC).tag("component", "gateway").tag("reason", reason).counter();
        return counter == null ? 0 : counter.count();
    }

    @Test
    void missingTokenAndMalformedHaveABudgetEachPerSecond() {
        for (int i = 0; i < 3; i++) {
            assertThat(limiter.permit("missing_token", null)).isTrue();
        }
        assertThat(limiter.permit("missing_token", null)).isFalse();
        assertThat(limiter.permit("missing_token", null)).isFalse();
        // A flood of one does not use up the other.
        for (int i = 0; i < 3; i++) {
            assertThat(limiter.permit("malformed", null)).isTrue();
        }
        assertThat(limiter.permit("malformed", null)).isFalse();
        assertThat(suppressed("missing_token")).isEqualTo(2);
        assertThat(suppressed("malformed")).isEqualTo(1);

        nanos.addAndGet(1_000_000_000L);
        assertThat(limiter.permit("missing_token", null)).isTrue();
        assertThat(limiter.permit("malformed", null)).isTrue();
    }

    @Test
    void whatCanBeSentWithoutAnyKeyHasABudgetPerReason() {
        for (String reason : new String[] {"alg_not_allowed", "unknown_kid", "bad_signature"}) {
            for (int i = 0; i < 3; i++) {
                assertThat(limiter.permit(reason, null)).as(reason).isTrue();
            }
            assertThat(limiter.permit(reason, null)).as(reason + " over the budget").isFalse();
            assertThat(suppressed(reason)).isEqualTo(1);
        }
    }

    @Test
    void reasonsOfAnAttemptAreNeverCapped() {
        for (String reason : new String[] {"wrong_audience", "wrong_issuer", "expired", "not_yet_valid", "invalid_claims",
                "jwks_unavailable"}) {
            for (int i = 0; i < 50; i++) {
                assertThat(limiter.permit(reason, null)).as(reason).isTrue();
            }
            assertThat(suppressed(reason)).isZero();
        }
    }

    @Test
    void certificateRejectionsAreSampledPerSourceAndPerInterval() {
        assertThat(limiter.permit("client_certificate_rejected", "10.0.0.1")).isTrue();
        assertThat(limiter.permit("client_certificate_rejected", "10.0.0.1")).isFalse();
        assertThat(limiter.permit("client_certificate_rejected", "10.0.0.2")).isTrue();
        assertThat(suppressed("client_certificate_rejected")).isEqualTo(1);
        nanos.addAndGet(Duration.ofMinutes(1).toNanos());
        assertThat(limiter.permit("client_certificate_rejected", "10.0.0.1")).isTrue();
    }

    @Test
    void aScanFromManyAddressesCannotGrowTheMapWithoutBound() {
        int permitted = 0;
        for (int i = 0; i < AuthenticationEventLimiter.MAX_SOURCES * 2; i++) {
            if (limiter.permit("client_certificate_rejected", "198.51.100." + i)) {
                permitted++;
            }
        }
        assertThat(permitted).isLessThanOrEqualTo(AuthenticationEventLimiter.MAX_SOURCES + 1);
        assertThat(suppressed("client_certificate_rejected")).isGreaterThan(0);
    }
}
