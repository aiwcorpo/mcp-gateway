package pl.aiwcorpo.mcp.gateway.confirm;

import java.util.List;

import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.json.JsonMapper;

/**
 * Redis form of the store: one key per user holding the whole state as JSON, written by a script that compares the
 * old value first. Keys are {@code <prefix>conf:u:<sha256(sub)>}; the sub itself is not in a key name. The script is
 * sent as text (EVAL) because the gateway's ACL allows EVAL and EVALSHA but not loading scripts.
 */
public final class RedisConfirmationStore implements ConfirmationStore {

    private static final DefaultRedisScript<Long> COMPARE_AND_SET = new DefaultRedisScript<>("""
            local current = redis.call('GET', KEYS[1])
            if current == false then current = '' end
            if current ~= ARGV[1] then return 0 end
            if ARGV[2] == '' then
              redis.call('DEL', KEYS[1])
            else
              redis.call('SET', KEYS[1], ARGV[2], 'PX', ARGV[3])
            end
            return 1
            """, Long.class);

    private static final long KEEP_MARGIN_MILLIS = 30_000;

    private final StringRedisTemplate redis;
    private final JsonMapper json;
    private final String prefix;
    private final int waitReplicas;
    private final long waitMillis;

    public RedisConfirmationStore(StringRedisTemplate redis, JsonMapper json, String prefix) {
        this(redis, json, prefix, 0, java.time.Duration.ZERO);
    }

    /** With {@code waitReplicas} above 0 every change waits (Redis WAIT) until that many replicas have it; else the store fails. */
    public RedisConfirmationStore(StringRedisTemplate redis, JsonMapper json, String prefix, int waitReplicas, java.time.Duration waitTimeout) {
        this.redis = redis;
        this.json = json;
        this.prefix = prefix;
        this.waitReplicas = waitReplicas;
        this.waitMillis = Math.max(1, waitTimeout.toMillis());
    }

    /**
     * A burned code or a pending operation that only the master knows is lost when the master is: the change counts only when enough
     * replicas confirm it. The write has happened either way, so a failure here makes the caller refuse, never go on.
     */
    private void replicated() throws StoreUnavailableException {
        if (waitReplicas <= 0) {
            return;
        }
        Long acknowledged = redis.execute((org.springframework.data.redis.core.RedisCallback<Long>) connection -> {
            Object answer = connection.execute("WAIT", Integer.toString(waitReplicas).getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                    Long.toString(waitMillis).getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            return answer instanceof Long count ? count : 0L;
        });
        if (acknowledged == null || acknowledged < waitReplicas) {
            throw new StoreUnavailableException("the change was not acknowledged by " + waitReplicas + " replicas");
        }
    }

    @Override
    public Versioned read(String sub) throws StoreUnavailableException {
        try {
            String raw = redis.opsForValue().get(userKey(sub));
            if (raw == null) {
                return new Versioned(UserConfirmations.EMPTY, null);
            }
            return new Versioned(json.readValue(raw, UserConfirmations.class), raw);
        } catch (DataAccessException | JacksonException e) {
            throw new StoreUnavailableException(e);
        }
    }

    @Override
    public boolean commit(String sub, Versioned expected, UserConfirmations next, long keepUntilEpochMillis)
            throws StoreUnavailableException {
        try {
            String written = next.calls().isEmpty() ? "" : json.writeValueAsString(next);
            // A lifetime relative to Redis's own clock, with a margin: a Redis clock that runs ahead must not cut the trace short.
            long lifetime = Math.max(1000, keepUntilEpochMillis - System.currentTimeMillis()) + KEEP_MARGIN_MILLIS;
            Long done = redis.execute(COMPARE_AND_SET, List.of(userKey(sub)), expected.raw() == null ? "" : expected.raw(),
                    written, Long.toString(lifetime));
            if (done != null && done == 1L) {
                replicated();
                return true;
            }
            return false;
        } catch (DataAccessException | JacksonException e) {
            throw new StoreUnavailableException(e);
        }
    }

    @Override
    public long epochStartedAt(long nowEpochMillis) throws StoreUnavailableException {
        try {
            String key = prefix + "conf:epoch";
            if (Boolean.TRUE.equals(redis.opsForValue().setIfAbsent(key, Long.toString(nowEpochMillis)))) {
                replicated();
            }
            String value = redis.opsForValue().get(key);
            if (value == null) {
                throw new StoreUnavailableException("epoch marker vanished");
            }
            return Long.parseLong(value);
        } catch (DataAccessException | NumberFormatException e) {
            throw new StoreUnavailableException(e);
        }
    }

    @Override
    public boolean burnedInEpoch(String sub, long epoch) throws StoreUnavailableException {
        try {
            return Boolean.TRUE.equals(redis.hasKey(burnKey(sub, epoch)));
        } catch (DataAccessException e) {
            throw new StoreUnavailableException(e);
        }
    }

    @Override
    public void markBurnedInEpoch(String sub, long epoch, long ttlMillis) throws StoreUnavailableException {
        try {
            redis.opsForValue().set(burnKey(sub, epoch), "1", java.time.Duration.ofMillis(ttlMillis));
            replicated();
        } catch (DataAccessException e) {
            throw new StoreUnavailableException(e);
        }
    }

    @Override
    public void deleteUser(String sub, long currentEpoch) throws StoreUnavailableException {
        try {
            redis.delete(List.of(userKey(sub), burnKey(sub, currentEpoch)));
        } catch (DataAccessException e) {
            throw new StoreUnavailableException(e);
        }
    }

    private String userKey(String sub) {
        return prefix + "conf:u:" + hash(sub);
    }

    private String burnKey(String sub, long epoch) {
        return prefix + "conf:eb:" + epoch + ":" + hash(sub);
    }

    private static String hash(String sub) {
        return pl.aiwcorpo.mcp.gateway.redis.KeyHash.of(sub);
    }
}
