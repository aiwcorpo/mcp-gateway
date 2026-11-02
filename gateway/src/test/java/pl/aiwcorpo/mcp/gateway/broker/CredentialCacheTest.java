package pl.aiwcorpo.mcp.gateway.broker;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class CredentialCacheTest {

    private final MutableClock clock = new MutableClock();
    private final CredentialCache cache = new CredentialCache(Duration.ofSeconds(60), clock);
    private final CredentialCache.Key key = new CredentialCache.Key("sub-1", "jira", List.of());

    @AfterEach
    void stopTimer() {
        cache.close();
    }

    @Test
    void entryLivesAtMostTheBrokerTtl() {
        cache.put(key, credential(10, null), cache.generation());
        clock.advance(Duration.ofSeconds(9));
        assertThat(cache.get(key)).isNotNull();
        clock.advance(Duration.ofSeconds(1));
        assertThat(cache.get(key)).isNull();
    }

    @Test
    void entryNeverOutlivesTheCredential() {
        cache.put(key, credential(60, clock.instant().plusSeconds(5)), cache.generation());
        clock.advance(Duration.ofSeconds(5));
        assertThat(cache.get(key)).isNull();
    }

    @Test
    void invalidationRemovesOnlyThatUserAndSystem() {
        CredentialCache.Key other = new CredentialCache.Key("sub-2", "jira", List.of());
        cache.put(key, credential(60, null), cache.generation());
        cache.put(other, credential(60, null), cache.generation());
        cache.invalidate("sub-1", "jira");
        assertThat(cache.get(key)).isNull();
        assertThat(cache.get(other)).isNotNull();
    }

    @Test
    void resolveInFlightDuringInvalidationDoesNotRepopulate() {
        long before = cache.generation();
        cache.invalidate("sub-1", "jira");
        cache.put(key, credential(60, null), before);
        assertThat(cache.get(key)).isNull();
    }

    @Test
    void keysThatAreNeverReadAgainDoNotGrowTheCacheWithoutBound() {
        for (int i = 0; i < CredentialCache.MAX_ENTRIES; i++) {
            cache.put(new CredentialCache.Key("sub-" + i, "jira", List.of()), credential(10, null), cache.generation());
        }
        CredentialCache.Key late = new CredentialCache.Key("late", "jira", List.of());
        cache.put(late, credential(10, null), cache.generation());
        assertThat(cache.size()).as("full of live entries: the new one is not cached").isEqualTo(CredentialCache.MAX_ENTRIES);
        assertThat(cache.get(late)).isNull();

        clock.advance(Duration.ofSeconds(10));
        cache.put(late, credential(10, null), cache.generation());
        assertThat(cache.size()).as("expired entries made room").isEqualTo(1);
        assertThat(cache.get(late)).isNotNull();
    }

    @Test
    void expiredEntriesLeaveTheMemoryWithoutBeingReadAndBelowTheLimit() {
        for (int i = 0; i < 1000; i++) {
            cache.put(new CredentialCache.Key("sub-" + i, "jira", List.of()), credential(60, null), cache.generation());
        }
        cache.sweep();
        assertThat(cache.size()).as("live entries stay").isEqualTo(1000);
        clock.advance(Duration.ofSeconds(60));
        cache.sweep();
        assertThat(cache.size()).isZero();
    }

    @Test
    void theTimerSweepsOnItsOwnAndStopsOnClose() throws Exception {
        try (CredentialCache timed = new CredentialCache(Duration.ofSeconds(60), clock, Duration.ofMillis(20))) {
            timed.put(key, credential(10, null), timed.generation());
            clock.advance(Duration.ofSeconds(10));
            long until = System.nanoTime() + Duration.ofSeconds(5).toNanos();
            while (timed.size() > 0 && System.nanoTime() < until) {
                Thread.sleep(10);
            }
            assertThat(timed.size()).isZero();
        }
        CredentialCache closed = new CredentialCache(Duration.ofSeconds(60), clock, Duration.ofMillis(20));
        closed.close();
        closed.put(key, credential(10, null), closed.generation());
        clock.advance(Duration.ofSeconds(10));
        Thread.sleep(200);
        assertThat(closed.size()).as("a stopped timer sweeps nothing").isEqualTo(1);
    }

    @Test
    void refusalsWhenFullAreCountedAndAnExistingKeyIsStillRefreshed() {
        for (int i = 0; i < CredentialCache.MAX_ENTRIES; i++) {
            cache.put(new CredentialCache.Key("sub-" + i, "jira", List.of()), credential(10, null), cache.generation());
        }
        cache.put(new CredentialCache.Key("extra", "jira", List.of()), credential(10, null), cache.generation());
        assertThat(cache.refusedWhenFull()).isEqualTo(1);
        CredentialCache.Key existing = new CredentialCache.Key("sub-0", "jira", List.of());
        clock.advance(Duration.ofSeconds(5));
        cache.put(existing, credential(10, null), cache.generation());
        assertThat(cache.refusedWhenFull()).isEqualTo(1);
        clock.advance(Duration.ofSeconds(6));
        assertThat(cache.get(existing)).as("refreshed entry outlives the others").isNotNull();
    }

    @Test
    void aFailedSweepDoesNotEndTheTimer() throws Exception {
        java.util.concurrent.atomic.AtomicInteger calls = new java.util.concurrent.atomic.AtomicInteger();
        Clock failingOnce = new Clock() {
            @Override
            public Instant instant() {
                if (calls.getAndIncrement() == 1) {
                    throw new IllegalStateException("clock failure with secret-value");
                }
                return clock.instant();
            }

            @Override
            public java.time.ZoneId getZone() {
                return ZoneOffset.UTC;
            }

            @Override
            public Clock withZone(java.time.ZoneId zone) {
                return this;
            }
        };
        try (CredentialCache timed = new CredentialCache(Duration.ofSeconds(60), failingOnce, Duration.ofMillis(20))) {
            timed.put(key, credential(10, null), timed.generation());
            clock.advance(Duration.ofSeconds(10));
            long until = System.nanoTime() + Duration.ofSeconds(5).toNanos();
            while (timed.size() > 0 && System.nanoTime() < until) {
                Thread.sleep(10);
            }
            assertThat(calls.get()).as("the failing run happened").isGreaterThan(2);
            assertThat(timed.size()).as("and later runs still sweep").isZero();
        }
    }

    @Test
    void theSweepIntervalIsTenSeconds() {
        assertThat(CredentialCache.DEFAULT_SWEEP_INTERVAL).isEqualTo(Duration.ofSeconds(10));
    }

    @Test
    void sizeAndRefusalsAreRegisteredWithoutTags() {
        io.micrometer.core.instrument.simple.SimpleMeterRegistry meters = new io.micrometer.core.instrument.simple.SimpleMeterRegistry();
        cache.bindTo(meters);
        cache.put(key, credential(10, null), cache.generation());
        assertThat(meters.get("mcp.gateway.credential.cache.size").gauge().value()).isEqualTo(1.0);
        assertThat(meters.get("mcp.gateway.credential.cache.size").gauge().getId().getTags()).isEmpty();
        assertThat(meters.get("mcp.gateway.credential.cache.refused").functionCounter().count()).isZero();
        assertThat(meters.get("mcp.gateway.credential.cache.refused").functionCounter().getId().getTags()).isEmpty();
    }

    @Test
    void theLimitIsTenThousand() {
        assertThat(CredentialCache.MAX_ENTRIES).isEqualTo(10_000);
    }

    @Test
    void maxTtlAboveSixtySecondsIsRefused() {
        assertThatThrownBy(() -> new CredentialCache(Duration.ofSeconds(61), clock)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void toStringHidesTheValue() {
        assertThat(credential(1, null).toString()).doesNotContain("secret-value");
    }

    private static Credential credential(int ttl, Instant expiresAt) {
        return new Credential("Bearer", "secret-value", "user-secret", expiresAt, ttl);
    }

    private static final class MutableClock extends Clock {
        private Instant now = Instant.parse("2026-10-27T12:00:00Z");

        void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public Instant instant() {
            return now;
        }

        @Override
        public java.time.ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }
    }
}
