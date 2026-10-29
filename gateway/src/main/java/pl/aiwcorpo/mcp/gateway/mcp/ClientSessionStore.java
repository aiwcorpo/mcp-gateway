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
    private static final org.springframework.data.redis.core.script.DefaultRedisScript<Long> CREATE =
            new org.springframework.data.redis.core.script.DefaultRedisScript<>("""
            redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[3])
            redis.call('SADD', KEYS[2], ARGV[2])
            redis.call('PEXPIRE', KEYS[2], ARGV[4])
            return 1
            """, Long.class);

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
        // The index lets an offboarding find the sessions of a user (the gateway's Redis account has no SCAN); one script writes
        // both, so a purge cannot fall between the session and its index entry.
        redis.execute(CREATE, java.util.List.of(prefix + id, indexKey(sub)), value, id, Long.toString(idleTimeout.toMillis()),
                Long.toString(idleTimeout.plusMinutes(1).toMillis()));
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
            String sub = node.path("sub").asString();
            // A session that outlives its first index entry (it is used) stays findable by an offboarding.
            redis.opsForSet().add(indexKey(sub), id);
            redis.expire(indexKey(sub), idleTimeout.plusMinutes(1));
            return Optional.of(new ClientSession(id, sub, node.path("client").asString(), node.path("protocolVersion").asString()));
        } catch (JacksonException e) {
            return Optional.empty();
        }
    }

    public void delete(String id) {
        redis.delete(prefix + id);
    }

    /** Ends every session of the user (offboarding). Idempotent; an unreachable Redis is a DataAccessException for the caller. */
    public int deleteAllOf(String sub) {
        java.util.Set<String> ids = redis.opsForSet().members(indexKey(sub));
        int removed = 0;
        if (ids != null) {
            for (String id : ids) {
                if (Boolean.TRUE.equals(redis.delete(prefix + id))) {
                    removed++;
                }
            }
        }
        redis.delete(indexKey(sub));
        return removed;
    }

    private String indexKey(String sub) {
        return prefix + "of:" + pl.aiwcorpo.mcp.gateway.redis.KeyHash.of(sub);
    }
}
