package pl.aiwcorpo.mcp.gateway.confirm;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;

import tools.jackson.databind.json.JsonMapper;

/**
 * WAIT on the confirmation state (HA): with a replica attached a change is acknowledged and the gateway goes on; when no replica
 * confirms it the store fails, so that a burned code is never only on a master that can still be lost.
 */
class ReplicatedStoreTest {

    private static Network network;
    private static GenericContainer<?> master;
    private static GenericContainer<?> replica;
    private static LettuceConnectionFactory factory;
    private static StringRedisTemplate redis;

    @BeforeAll
    static void start() {
        network = Network.newNetwork();
        master = new GenericContainer<>("redis:8.8.4-alpine").withNetwork(network).withNetworkAliases("master").withExposedPorts(6379);
        master.start();
        replica = new GenericContainer<>("redis:8.8.4-alpine").withNetwork(network)
                .withCommand("redis-server", "--replicaof", "master", "6379").withExposedPorts(6379);
        replica.start();
        factory = new LettuceConnectionFactory(new RedisStandaloneConfiguration(master.getHost(), master.getMappedPort(6379)));
        factory.afterPropertiesSet();
        redis = new StringRedisTemplate(factory);
        redis.afterPropertiesSet();
        org.awaitility.Awaitility.await().atMost(Duration.ofSeconds(30)).until(() ->
                redis.execute((org.springframework.data.redis.core.RedisCallback<Long>) c -> ((io.lettuce.core.api.async.BaseRedisAsyncCommands<?, ?>) c.getNativeConnection())
                        .waitForReplication(1, 100).toCompletableFuture().join()) >= 1);
    }

    @AfterAll
    static void stop() {
        factory.destroy();
        replica.stop();
        master.stop();
        network.close();
    }

    @Test
    void aChangeIsAcknowledgedWhileAReplicaHasIt_andRefusedWhenNoneDoes() {
        RedisConfirmationStore waiting = waitingStore();
        RedisConfirmationStore notWaiting = new RedisConfirmationStore(redis, JsonMapper.builder().build(), "gw:");

        assertThatCode(() -> waiting.markBurnedInEpoch("sub-a", 1, 60_000)).doesNotThrowAnyException();
        String key = "gw:conf:eb:1:" + pl.aiwcorpo.mcp.gateway.redis.KeyHash.of("sub-a");
        String onReplica = new StringRedisTemplate(replicaFactory()).opsForValue().get(key);
        assertThat(onReplica).as("the replica has the burn when the call returns").isEqualTo("1");

        replica.getDockerClient().pauseContainerCmd(replica.getContainerId()).exec();
        try {
            assertThatThrownBy(() -> waiting.markBurnedInEpoch("sub-b", 1, 60_000))
                    .isInstanceOf(ConfirmationStore.StoreUnavailableException.class).hasMessageContaining("not acknowledged");
            assertThatCode(() -> notWaiting.markBurnedInEpoch("sub-c", 1, 60_000)).doesNotThrowAnyException();
        } finally {
            replica.getDockerClient().unpauseContainerCmd(replica.getContainerId()).exec();
        }
    }

    private static RedisConfirmationStore waitingStore() {
        LettuceConnectionFactory own = new LettuceConnectionFactory(new RedisStandaloneConfiguration(master.getHost(), master.getMappedPort(6379)));
        own.setShareNativeConnection(false);
        own.afterPropertiesSet();
        return new RedisConfirmationStore(redis, JsonMapper.builder().build(), "gw:", 1, Duration.ofMillis(300), own);
    }

    /** WAIT blocks its connection: with the replica stopped, everything else on the shared connection goes on at once. */
    @Test
    void aReplicaThatStopsAnsweringDoesNotSlowDownTheTrafficOfTheGateway() throws Exception {
        RedisConfirmationStore waiting = waitingStore();
        replica.getDockerClient().pauseContainerCmd(replica.getContainerId()).exec();
        java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(4);
        try {
            java.util.List<java.util.concurrent.Future<?>> blocked = new java.util.ArrayList<>();
            for (int i = 0; i < 4; i++) {
                int n = i;
                blocked.add(pool.submit(() -> assertThatThrownBy(() -> waiting.markBurnedInEpoch("sub-p" + n, 2, 60_000))
                        .isInstanceOf(ConfirmationStore.StoreUnavailableException.class)));
            }
            long slowest = 0;
            for (int i = 0; i < 40; i++) {
                long started = System.nanoTime();
                redis.opsForValue().set("gw:rl:probe", Integer.toString(i));
                assertThat(redis.opsForValue().get("gw:rl:probe")).isEqualTo(Integer.toString(i));
                slowest = Math.max(slowest, (System.nanoTime() - started) / 1_000_000);
                Thread.sleep(10);
            }
            assertThat(slowest).as("ms of the slowest request on the shared connection while four changes wait").isLessThan(150);
            for (java.util.concurrent.Future<?> f : blocked) {
                f.get(10, java.util.concurrent.TimeUnit.SECONDS);
            }
        } finally {
            replica.getDockerClient().unpauseContainerCmd(replica.getContainerId()).exec();
            pool.shutdownNow();
            waiting.close();
        }
    }

    private static LettuceConnectionFactory replicaFactory() {
        LettuceConnectionFactory replicaFactory = new LettuceConnectionFactory(
                new RedisStandaloneConfiguration(replica.getHost(), replica.getMappedPort(6379)));
        replicaFactory.afterPropertiesSet();
        return replicaFactory;
    }
}
