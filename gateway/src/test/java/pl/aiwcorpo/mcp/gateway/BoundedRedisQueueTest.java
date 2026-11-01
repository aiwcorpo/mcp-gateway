package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;

/** The commands waiting for the shared Redis connection have a limit; Lettuce's own default is none. */
class BoundedRedisQueueTest extends GatewayTestBase {

    @Autowired
    private LettuceConnectionFactory redisConnections;

    @Test
    void theRequestQueueOfTheSharedConnectionIsBounded() {
        int size = redisConnections.getClientConfiguration().getClientOptions().orElseThrow().getRequestQueueSize();
        assertThat(size).isEqualTo(Math.max(1024, 128 * 16));
    }
}
