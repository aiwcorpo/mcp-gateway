package pl.aiwcorpo.mcp.gateway.broker;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.Test;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.server.CredentialPolicy;

class CredentialServiceTest {

    private final BrokerClient broker = mock(BrokerClient.class);
    private final TokenExchangeClient exchange = mock(TokenExchangeClient.class);
    private final CredentialCache cache = new CredentialCache(Duration.ofSeconds(60), Clock.systemUTC());
    private final AtomicBoolean live = new AtomicBoolean(true);
    private final CredentialService service = new CredentialService(broker, exchange, cache, live::get, new SimpleMeterRegistry());
    private final GatewayUser user = new GatewayUser("sub-1", "alice", "claude-code", List.of(), "raw-idp-token");
    private final CredentialPolicy secretPolicy = new CredentialPolicy(true, Set.of("user-secret"), List.of(), false, "user-secret");

    @Test
    void cacheIsBypassedWhileTheInvalidationSubscriptionIsDown() {
        grant("user-secret");
        live.set(false);
        service.resolve(user, "jira", secretPolicy, "get_issue", "rid-1");
        service.resolve(user, "jira", secretPolicy, "get_issue", "rid-2");
        verify(broker, times(2)).resolve(any(), eq("jira"), anyList(), isNull(), eq("get_issue"), anyString());
        assertThat(cache.size()).isZero();
    }

    @Test
    void credentialOfATypeOutsideTheSetIsAMismatch() {
        grant("service-account");
        assertThat(service.resolve(user, "jira", secretPolicy, "get_issue", "rid")).isEqualTo(new Resolution.TypeMismatch("service-account"));
        assertThat(cache.size()).isZero();
    }

    @Test
    void tokenExchangeSystemsSendTheExchangedTokenNeverTheRawOne() {
        CredentialPolicy exchangePolicy = new CredentialPolicy(true, Set.of("token-exchange"), List.of(), true, "token-exchange");
        when(exchange.exchange("raw-idp-token")).thenReturn("exchanged");
        when(broker.resolve(any(), eq("opensearch"), anyList(), eq("exchanged"), any(), any())).thenReturn(
                new Resolution.Granted(new Credential("Bearer", "os-token", "token-exchange", null, 30), false));
        assertThat(service.resolve(user, "opensearch", exchangePolicy, "search_logs", "rid")).isInstanceOf(Resolution.Granted.class);
        verify(broker).resolve(any(), eq("opensearch"), anyList(), eq("exchanged"), eq("search_logs"), eq("rid"));
    }

    @Test
    void failedExchangeIsUnavailableAndTheBrokerIsNotCalled() {
        CredentialPolicy exchangePolicy = new CredentialPolicy(true, Set.of("token-exchange"), List.of(), true, "token-exchange");
        when(exchange.exchange(any())).thenReturn(null);
        assertThat(service.resolve(user, "opensearch", exchangePolicy, "search_logs", "rid"))
                .isInstanceOf(Resolution.Unavailable.class);
        verify(broker, times(0)).resolve(any(), any(), anyList(), any(), any(), any());
    }

    private void grant(String type) {
        when(broker.resolve(any(), any(), anyList(), any(), any(), any())).thenReturn(
                new Resolution.Granted(new Credential("Bearer", "pat", type, null, 60), false));
    }
}
