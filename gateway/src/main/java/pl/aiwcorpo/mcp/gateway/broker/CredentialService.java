package pl.aiwcorpo.mcp.gateway.broker;

import java.util.List;
import java.util.function.BooleanSupplier;

import io.micrometer.core.instrument.MeterRegistry;
import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.server.CredentialPolicy;

/**
 * Credential for one tool call: cache first (only while the invalidation subscription is live), then the
 * broker. A credential of a type the server configuration does not accept is treated as a broker error.
 */
public class CredentialService {

    private final BrokerClient broker;
    private final TokenExchangeClient exchange;
    private final CredentialCache cache;
    private final BooleanSupplier invalidationsLive;
    private final MeterRegistry meters;

    public CredentialService(BrokerClient broker, TokenExchangeClient exchange, CredentialCache cache,
                             BooleanSupplier invalidationsLive, MeterRegistry meters) {
        this.broker = broker;
        this.exchange = exchange;
        this.cache = cache;
        this.invalidationsLive = invalidationsLive;
        this.meters = meters;
    }

    public Resolution resolve(GatewayUser user, String system, CredentialPolicy policy, String tool, String requestId) {
        List<String> scopes = policy.scopes().stream().sorted().toList();
        CredentialCache.Key key = new CredentialCache.Key(user.sub(), system, scopes);
        boolean cacheUsable = invalidationsLive.getAsBoolean();
        long generation = cache.generation();
        if (cacheUsable) {
            Credential cached = cache.get(key);
            if (cached != null) {
                meters.counter("mcp.gateway.credential.cache", "result", "hit").increment();
                return new Resolution.Granted(cached, true);
            }
            meters.counter("mcp.gateway.credential.cache", "result", "miss").increment();
        } else {
            meters.counter("mcp.gateway.credential.cache", "result", "bypass").increment();
        }

        String subjectToken = null;
        if (policy.tokenExchange()) {
            subjectToken = exchange.exchange(user.accessToken());
            if (subjectToken == null) {
                return record(new Resolution.Unavailable("token_exchange_failed"));
            }
        }
        Resolution resolution = broker.resolve(user, system, scopes, subjectToken, tool, requestId);
        if (resolution instanceof Resolution.Granted granted) {
            if (!policy.acceptedTypes().contains(granted.credential().type())) {
                return record(new Resolution.Failed("credential_type_not_accepted"));
            }
            if (cacheUsable && granted.credential().cacheTtlSeconds() > 0) {
                cache.put(key, granted.credential(), generation);
            }
        }
        return record(resolution);
    }

    private Resolution record(Resolution resolution) {
        String outcome = switch (resolution) {
            case Resolution.Granted g -> "granted";
            case Resolution.Required r -> "credential_required";
            case Resolution.Denied d -> "denied";
            case Resolution.Unavailable u -> "unavailable";
            case Resolution.Failed f -> "failed";
        };
        meters.counter("mcp.gateway.broker.resolve", "outcome", outcome).increment();
        return resolution;
    }
}
