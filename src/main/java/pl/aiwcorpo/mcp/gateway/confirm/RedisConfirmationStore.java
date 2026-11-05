package pl.aiwcorpo.mcp.gateway.confirm;

import java.util.List;

import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.json.JsonMapper;

/**
 * Redis form of the store: one key per user holding the whole state as JSON, written by a script that compares the
 * old value first. Keys are {@code <prefix>conf:u:<sha256(sub)>}; the sub itself is not in a key name. The script is
 * sent as text (EVAL) because the gateway's ACL allows EVAL and EVALSHA but not loading scripts.
 */
public final class RedisConfirmationStore implements ConfirmationStore, AutoCloseable {

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
    private final LettuceConnectionFactory dedicated;

    public RedisConfirmationStore(StringRedisTemplate redis, JsonMapper json, String prefix) {
        this(redis, json, prefix, 0, java.time.Duration.ZERO, null);
    }

    /**
     * With {@code waitReplicas} above 0 every change is written on a connection of its own and followed by Redis WAIT there until that
     * many replicas have it. WAIT blocks its connection, so it must not be the connection that every request of the gateway shares: a
     * replica that stops answering would otherwise stop the limits, the sessions and everything else with it. A connection per change
     * costs a handshake, on state that changes only for DESTRUCTIVE tools.
     *
     * @param dedicated factory whose connections are not shared; closed with the store
     */
    public RedisConfirmationStore(StringRedisTemplate redis, JsonMapper json, String prefix, int waitReplicas, java.time.Duration waitTimeout,
                                  LettuceConnectionFactory dedicated) {
        if (waitReplicas > 0 && dedicated == null) {
            throw new IllegalArgumentException("WAIT needs a connection factory that does not share its connection");
        }
        this.redis = redis;
        this.json = json;
        this.prefix = prefix;
        this.waitReplicas = waitReplicas;
        this.waitMillis = Math.max(1, waitTimeout.toMillis());
        this.dedicated = dedicated;
    }

    @Override
    public void close() {
        if (dedicated != null) {
            dedicated.destroy();
        }
    }

    private static final class NotReplicated extends RuntimeException {
        private static final long serialVersionUID = 1L;

        NotReplicated(String message) {
            super(message, null, false, false);
        }
    }

    /** Runs {@code work} on one dedicated connection, then waits on that same connection for the replicas that have to confirm. */
    @SuppressWarnings("unchecked")
    private <T> T replicated(java.util.function.Function<io.lettuce.core.api.async.RedisAsyncCommands<byte[], byte[]>, T> work)
            throws StoreUnavailableException {
        try {
            return new StringRedisTemplate(dedicated).execute((org.springframework.data.redis.core.RedisCallback<T>) connection -> {
                io.lettuce.core.api.async.RedisAsyncCommands<byte[], byte[]> commands =
                        (io.lettuce.core.api.async.RedisAsyncCommands<byte[], byte[]>) connection.getNativeConnection();
                T result = work.apply(commands);
                try {
                    Long acknowledged = commands.waitForReplication(waitReplicas, waitMillis).get(waitMillis + 2000, java.util.concurrent.TimeUnit.MILLISECONDS);
                    if (acknowledged == null || acknowledged < waitReplicas) {
                        throw new NotReplicated("the change was not acknowledged by " + waitReplicas + " replicas");
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new NotReplicated("interrupted while waiting for the replicas");
                } catch (java.util.concurrent.ExecutionException | java.util.concurrent.TimeoutException e) {
                    throw new NotReplicated("the replicas did not answer");
                }
                return result;
            });
        } catch (NotReplicated e) {
            throw new StoreUnavailableException(e.getMessage());
        } catch (DataAccessException e) {
            throw new StoreUnavailableException(e);
        }
    }

    private static <V> V await(io.lettuce.core.RedisFuture<V> future) {
        try {
            return future.get(5, java.util.concurrent.TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new NotReplicated("interrupted");
        } catch (java.util.concurrent.ExecutionException | java.util.concurrent.TimeoutException e) {
            throw new NotReplicated("Redis did not answer");
        }
    }

    private static byte[] bytes(String value) {
        return value.getBytes(java.nio.charset.StandardCharsets.UTF_8);
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
            String old = expected.raw() == null ? "" : expected.raw();
            if (waitReplicas > 0) {
                Long done = replicated(commands -> await(commands.eval(COMPARE_AND_SET.getScriptAsString(),
                        io.lettuce.core.ScriptOutputType.INTEGER, new byte[][] {bytes(userKey(sub))}, bytes(old), bytes(written),
                        bytes(Long.toString(lifetime)))));
                return done != null && done == 1L;
            }
            Long done = redis.execute(COMPARE_AND_SET, List.of(userKey(sub)), old, written, Long.toString(lifetime));
            return done != null && done == 1L;
        } catch (DataAccessException | JacksonException e) {
            throw new StoreUnavailableException(e);
        }
    }

    @Override
    public long epochStartedAt(long nowEpochMillis) throws StoreUnavailableException {
        try {
            String key = prefix + "conf:epoch";
            if (waitReplicas > 0) {
                replicated(commands -> await(commands.setnx(bytes(key), bytes(Long.toString(nowEpochMillis)))));
            } else {
                redis.opsForValue().setIfAbsent(key, Long.toString(nowEpochMillis));
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
            if (waitReplicas > 0) {
                replicated(commands -> await(commands.set(bytes(burnKey(sub, epoch)), bytes("1"), io.lettuce.core.SetArgs.Builder.px(ttlMillis))));
            } else {
                redis.opsForValue().set(burnKey(sub, epoch), "1", java.time.Duration.ofMillis(ttlMillis));
            }
        } catch (DataAccessException e) {
            throw new StoreUnavailableException(e);
        }
    }

    @Override
    public void deleteUser(String sub, long currentEpoch) throws StoreUnavailableException {
        try {
            if (waitReplicas > 0) {
                replicated(commands -> await(commands.del(bytes(userKey(sub)), bytes(burnKey(sub, currentEpoch)))));
            } else {
                redis.delete(List.of(userKey(sub), burnKey(sub, currentEpoch)));
            }
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
