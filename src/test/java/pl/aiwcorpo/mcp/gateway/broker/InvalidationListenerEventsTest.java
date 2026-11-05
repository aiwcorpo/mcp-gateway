package pl.aiwcorpo.mcp.gateway.broker;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;

import org.junit.jupiter.api.Test;

import io.lettuce.core.RedisURI;
import tools.jackson.databind.json.JsonMapper;

class InvalidationListenerEventsTest {

    @Test
    void anUnknownConnectionEventIsALostSubscriptionAndOnlyAbandonedOnesAreIgnored() throws Exception {
        CredentialCache cache = new CredentialCache(Duration.ofSeconds(60), java.time.Clock.systemUTC());
        cache.close();
        InvalidationListener listener = new InvalidationListener(RedisURI.create("redis://localhost:1"), "credential.invalidated",
                cache, JsonMapper.builder().build(), Duration.ofSeconds(5));
        var live = InvalidationListener.class.getDeclaredField("live");
        live.setAccessible(true);
        ((java.util.concurrent.atomic.AtomicBoolean) live.get(listener)).set(true);

        Object stale = new Object();
        var abandoned = InvalidationListener.class.getDeclaredField("abandoned");
        abandoned.setAccessible(true);
        @SuppressWarnings("unchecked")
        java.util.Set<Object> set = (java.util.Set<Object>) abandoned.get(listener);
        set.add(stale);

        listener.connectionEvent(stale, "disconnected");
        assertThat(listener.live()).as("late event of a dropped connection").isTrue();

        listener.connectionEvent(new Object(), "disconnected");
        assertThat(listener.live()).as("event of a connection not known as abandoned").isFalse();
    }
}
