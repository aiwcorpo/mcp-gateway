package pl.aiwcorpo.mcp.gateway.mcp;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;

import org.springframework.data.redis.core.StringRedisTemplate;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Legacy client sessions in Redis ({@code <prefix>session:<id>}, idle TTL), so any gateway instance can serve
 * them. The id is 192 random bits; it identifies, the bearer token authenticates, and a session is only valid
 * together with a token of the same {@code sub}.
 */
public class ClientSessionStore {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final StringRedisTemplate redis;
    private final JsonMapper json;
    private final String prefix;
    private final Duration idleTimeout;

    public ClientSessionStore(StringRedisTemplate redis, JsonMapper json, String keyPrefix, Duration idleTimeout) {
        this.redis = redis;
        this.json = json;
        this.prefix = keyPrefix + "session:";
        this.idleTimeout = idleTimeout;
    }

    public ClientSession create(String sub, String client, String protocolVersion) {
        byte[] bytes = new byte[24];
        RANDOM.nextBytes(bytes);
        String id = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        String value = json.writeValueAsString(Map.of("sub", sub, "client", client == null ? "" : client,
                "protocolVersion", protocolVersion));
        redis.opsForValue().set(prefix + id, value, idleTimeout);
        return new ClientSession(id, sub, client, protocolVersion);
    }

    /** The session, with its idle TTL extended; empty when unknown, expired or malformed. */
    public Optional<ClientSession> find(String id) {
        if (id == null || !id.matches("^[A-Za-z0-9_-]{32}$")) {
            return Optional.empty();
        }
        String value = redis.opsForValue().getAndExpire(prefix + id, idleTimeout);
        if (value == null) {
            return Optional.empty();
        }
        try {
            JsonNode node = json.readTree(value);
            return Optional.of(new ClientSession(id, node.path("sub").asString(), node.path("client").asString(),
                    node.path("protocolVersion").asString()));
        } catch (JacksonException e) {
            return Optional.empty();
        }
    }

    public void delete(String id) {
        redis.delete(prefix + id);
    }
}
