package pl.aiwcorpo.mcp.gateway.broker;

import java.net.SocketAddress;
import java.time.Duration;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.SmartLifecycle;

import io.lettuce.core.ClientOptions;
import io.lettuce.core.RedisChannelHandler;
import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisConnectionStateListener;
import io.lettuce.core.RedisURI;
import io.lettuce.core.SocketOptions;
import io.lettuce.core.pubsub.RedisPubSubAdapter;
import io.lettuce.core.pubsub.StatefulRedisPubSubConnection;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Subscribes to {@code credential.invalidated} (C4.3) and drops cache entries of (sub, system). While the
 * subscription is not confirmed (start-up, Redis outage, reconnect) {@link #live()} is false: the cache is
 * cleared and bypassed, because a missed event could keep a revoked credential for up to its TTL.
 * A periodic PING on the subscription connection detects half-open connections (no RST, no disconnect event):
 * a failed PING drops the connection and subscribes again on a new one.
 */
public final class InvalidationListener implements SmartLifecycle {

    private static final Logger log = LoggerFactory.getLogger(InvalidationListener.class);
    private static final Set<String> SYSTEMS = Set.of("jira", "confluence", "gitlab", "servicedesk", "opensearch");

    private final RedisURI uri;
    private final String channel;
    private final CredentialCache cache;
    private final JsonMapper json;
    private final Duration healthInterval;
    private final AtomicBoolean live = new AtomicBoolean();
    private RedisClient client;
    private volatile StatefulRedisPubSubConnection<String, String> connection;
    private volatile boolean running;

    public InvalidationListener(RedisURI uri, String channel, CredentialCache cache, JsonMapper json, Duration healthInterval) {
        this.uri = uri;
        this.channel = channel;
        this.cache = cache;
        this.json = json;
        this.healthInterval = healthInterval;
    }

    public boolean live() {
        return live.get();
    }

    @Override
    public void start() {
        client = RedisClient.create(uri);
        client.setOptions(ClientOptions.builder()
                .autoReconnect(true)
                .pingBeforeActivateConnection(false)
                .socketOptions(SocketOptions.builder().keepAlive(true).connectTimeout(Duration.ofSeconds(2)).build())
                .build());
        client.addListener(new RedisConnectionStateListener() {
            @Override
            public void onRedisConnected(RedisChannelHandler<?, ?> handler, SocketAddress address) {
                // live again only after the subscription is confirmed (subscribed callback)
            }

            @Override
            public void onRedisDisconnected(RedisChannelHandler<?, ?> handler) {
                // A late event of a connection already dropped must not clear the cache of the new subscription.
                if (handler == connection) {
                    lost("disconnected");
                }
            }

            @Override
            public void onRedisExceptionCaught(RedisChannelHandler<?, ?> handler, Throwable cause) {
                if (handler == connection) {
                    lost("error " + cause.getClass().getSimpleName());
                }
            }
        });
        running = true;
        Thread.ofVirtual().name("credential-invalidation").start(this::loop);
    }

    private void loop() {
        while (running) {
            StatefulRedisPubSubConnection<String, String> current = connection;
            if (current == null) {
                subscribe();
            } else {
                try {
                    current.sync().ping();
                    if (!live.get() && current.isOpen()) {
                        // an error event without a disconnect; subscribe again to get a fresh confirmation
                        current.sync().subscribe(channel);
                    }
                } catch (RuntimeException e) {
                    lost("ping failed: " + e.getClass().getSimpleName());
                    drop(current);
                }
            }
            sleep(connection == null ? Duration.ofSeconds(1) : healthInterval);
        }
    }

    private void subscribe() {
        StatefulRedisPubSubConnection<String, String> pubSub = null;
        try {
            pubSub = client.connectPubSub();
            pubSub.addListener(new RedisPubSubAdapter<>() {
                @Override
                public void message(String ch, String message) {
                    onMessage(message);
                }

                @Override
                public void subscribed(String ch, long count) {
                    if (channel.equals(ch)) {
                        cache.clear();
                        live.set(true);
                        log.info("Subscribed to {}; credential cache enabled", channel);
                    }
                }
            });
            pubSub.sync().subscribe(channel);
            connection = pubSub;
        } catch (RuntimeException e) {
            lost("subscribe failed: " + e.getClass().getSimpleName());
            drop(pubSub);
        }
    }

    void onMessage(String message) {
        try {
            JsonNode event = json.readTree(message);
            String sub = event.path("sub").asString(null);
            String system = event.path("system").asString(null);
            if (sub == null || sub.isEmpty() || !SYSTEMS.contains(system)) {
                log.warn("Ignoring malformed {} event", channel);
                return;
            }
            cache.invalidate(sub, system);
        } catch (JacksonException e) {
            log.warn("Ignoring unreadable {} event", channel);
        }
    }

    private void lost(String why) {
        if (live.getAndSet(false)) {
            log.warn("Invalidation subscription lost ({}); credential cache cleared and bypassed", why);
        }
        cache.clear();
    }

    private void drop(StatefulRedisPubSubConnection<String, String> pubSub) {
        if (pubSub == null) {
            return;
        }
        if (connection == pubSub) {
            connection = null;
        }
        try {
            pubSub.closeAsync();
        } catch (RuntimeException e) {
            // already closed
        }
    }

    @Override
    public void stop() {
        running = false;
        live.set(false);
        drop(connection);
        if (client != null) {
            client.shutdown(Duration.ZERO, Duration.ofSeconds(2));
        }
    }

    @Override
    public boolean isRunning() {
        return running;
    }

    private static void sleep(Duration duration) {
        try {
            Thread.sleep(duration);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
