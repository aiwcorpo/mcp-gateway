package pl.aiwcorpo.mcp.gateway.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.ssl.SslAutoConfiguration;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;
import org.springframework.boot.data.redis.autoconfigure.DataRedisAutoConfiguration;
import org.springframework.boot.data.redis.autoconfigure.DataRedisConnectionDetails;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;

import pl.aiwcorpo.mcp.gateway.broker.CredentialCache;
import pl.aiwcorpo.mcp.gateway.broker.InvalidationListener;
import pl.aiwcorpo.mcp.gateway.confirm.ConfirmationStore;
import tools.jackson.databind.json.JsonMapper;

/**
 * The connections to Redis that the gateway opens itself (the confirmation store that waits for replicas, the credential.invalidated
 * subscriber) use TLS exactly when the main connection does (spring.data.redis.ssl.*). A loopback socket stands in for Redis and records
 * what each connection sends first: a TLS client starts with a handshake record (0x16).
 */
class RedisConnectionsTlsTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final ApplicationContextRunner REDIS = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(DataRedisAutoConfiguration.class, SslAutoConfiguration.class));

    @Test
    void withTlsOnTheMainConnectionTheOthersStartWithAHandshake() throws Exception {
        firstBytesOfTheGatewaysConnections(true);
    }

    @Test
    void withoutTlsOnTheMainConnectionTheOthersAreUnchanged() throws Exception {
        firstBytesOfTheGatewaysConnections(false);
    }

    private static void firstBytesOfTheGatewaysConnections(boolean tls) throws Exception {
        try (ServerSocket fakeRedis = new ServerSocket(0, 5, InetAddress.getLoopbackAddress())) {
            REDIS.withPropertyValues("spring.data.redis.host=127.0.0.1", "spring.data.redis.port=" + fakeRedis.getLocalPort(),
                    "spring.data.redis.ssl.enabled=" + tls).run(context -> {
                assertThat(context.getBean(LettuceConnectionFactory.class).isUseSsl()).as("the main connection").isEqualTo(tls);
                DataRedisConnectionDetails redisConnection = context.getBean(DataRedisConnectionDetails.class);
                GatewayProperties properties = properties(fakeRedis.getLocalPort());

                ConfirmationStore store = new GatewayConfiguration().confirmationStore(mock(StringRedisTemplate.class), JSON, properties,
                        redisConnection);
                CompletableFuture<String> sentByStore = firstBytes(fakeRedis);
                try {
                    assertThatThrownBy(() -> store.markBurnedInEpoch("sub-a", 1, 60_000))
                            .isInstanceOf(ConfirmationStore.StoreUnavailableException.class);
                    assertThat(sentByStore.get(10, TimeUnit.SECONDS).startsWith("TLS")).as("the confirmation store").isEqualTo(tls);
                } finally {
                    ((AutoCloseable) store).close();
                }

                InvalidationListener listener = new GatewayConfiguration().invalidationListener(properties,
                        new CredentialCache(Duration.ofSeconds(60), Clock.systemUTC()), JSON, redisConnection);
                CompletableFuture<String> sentByListener = firstBytes(fakeRedis);
                listener.start();
                try {
                    assertThat(sentByListener.get(10, TimeUnit.SECONDS).startsWith("TLS")).as("the invalidation listener").isEqualTo(tls);
                } finally {
                    listener.stop();
                }
            });
        }
    }

    /** The gateway's own Redis settings as in production, with WAIT for one replica so that the store opens its own connections. */
    private static GatewayProperties properties(int port) {
        Map<String, String> values = DevstackGuardTest.production();
        values.put("gateway.redis.host", "127.0.0.1");
        values.put("gateway.redis.port", String.valueOf(port));
        values.put("gateway.redis.username", "gateway");
        values.put("gateway.redis.password", "dummy-pass");
        values.put("gateway.redis.wait-replicas", "1");
        return new Binder(new MapConfigurationPropertySource(values)).bind("gateway", GatewayProperties.class).get();
    }

    /** Accepts one connection and returns "TLS" for a handshake record, else the text it sent first; never answers. */
    private static CompletableFuture<String> firstBytes(ServerSocket server) {
        return CompletableFuture.supplyAsync(() -> {
            try (Socket socket = server.accept()) {
                socket.setSoTimeout(3000);
                InputStream in = socket.getInputStream();
                byte[] buffer = new byte[512];
                int n = in.read(buffer);
                if (n <= 0) {
                    return "";
                }
                return (buffer[0] & 0xff) == 0x16 ? "TLS" : new String(buffer, 0, n, StandardCharsets.ISO_8859_1);
            } catch (Exception e) {
                return e.getClass().getSimpleName();
            }
        });
    }
}
