package pl.aiwcorpo.mcp.gateway.registry;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;

import org.junit.jupiter.api.Test;

/** When the loop looks at a server again (C5): after the interval, or after 5 s when the server could not be reached. */
class ServerChecksScheduleTest {

    private static final Instant NOW = Instant.parse("2026-11-08T12:00:00Z");

    @Test
    void aServerThatWasReadIsLookedAtAfterTheWholeInterval() {
        assertThat(ServerChecks.lookedAt(NOW, Duration.ofSeconds(60), ServerConfig.CONNECTED)).isEqualTo(NOW);
        assertThat(ServerChecks.lookedAt(NOW, Duration.ofSeconds(60), ServerConfig.PENDING_APPROVAL)).isEqualTo(NOW);
        assertThat(ServerChecks.lookedAt(NOW, Duration.ofSeconds(60), ServerConfig.CERTIFICATE_CHANGED)).isEqualTo(NOW);
    }

    @Test
    void aServerThatCouldNotBeReachedIsLookedAtAgainAfterFiveSeconds() {
        Instant counted = ServerChecks.lookedAt(NOW, Duration.ofSeconds(60), ServerConfig.UNREACHABLE);

        assertThat(Duration.between(counted, NOW.plusSeconds(5))).as("due again five seconds from now").isEqualTo(Duration.ofSeconds(60));
        assertThat(Duration.between(counted, NOW.plusSeconds(4))).isLessThan(Duration.ofSeconds(60));
    }

    @Test
    void anIntervalShorterThanTheRetryIsNotStretched() {
        Instant counted = ServerChecks.lookedAt(NOW, Duration.ofSeconds(1), ServerConfig.UNREACHABLE);

        assertThat(Duration.between(counted, NOW.plusSeconds(1))).isEqualTo(Duration.ofSeconds(1));
    }
}
