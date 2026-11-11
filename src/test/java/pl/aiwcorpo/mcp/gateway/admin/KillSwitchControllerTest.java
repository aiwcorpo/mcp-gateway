package pl.aiwcorpo.mcp.gateway.admin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.jwt.Jwt;

import pl.aiwcorpo.mcp.gateway.audit.AuditLog;
import pl.aiwcorpo.mcp.gateway.killswitch.KillSwitchStore;
import pl.aiwcorpo.mcp.gateway.killswitch.KillSwitches;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.server.ServerRegistry;
import tools.jackson.databind.json.JsonMapper;

/** A switch that could not be stored is a 503 and nothing else happens: no 204, no event, no announcement (CC-194, fail-closed). */
class KillSwitchControllerTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    private static Jwt administrator() {
        return Jwt.withTokenValue("t").header("alg", "none").subject("sub-admin").claim("preferred_username", "a.admin")
                .claim("azp", "mcp-portal-bff").claim("groups", List.of("mcp-platform-admin")).claim("auth_time", Instant.now().getEpochSecond())
                .claim("amr", List.of("pwd", "otp")).issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60)).build();
    }

    private static FreshMfa mfa() {
        return new FreshMfa(List.of(), List.of("otp"), Clock.systemUTC(), new AuditLog(), "mcp-gateway");
    }

    private static MockHttpServletRequest body(String json) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setContent(json.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return request;
    }

    @Test
    void aFailedWriteIsA503AndLeavesNoTrace() throws Exception {
        KillSwitchStore store = mock(KillSwitchStore.class);
        doThrow(new DataAccessResourceFailureException("down")).when(store).put(any(), any(), any(), any());
        ServerRegistry servers = mock(ServerRegistry.class);
        when(servers.find("mcp-jira")).thenReturn(Optional.of(mock(McpServer.class)));
        AuditLog audit = new AuditLog();
        List<String> events = new java.util.ArrayList<>();
        audit.listen(event -> events.add(String.valueOf(event.view().get("reason"))));
        AtomicInteger announced = new AtomicInteger();
        KillSwitchController controller = new KillSwitchController(store, mock(KillSwitches.class), servers, audit, "mcp-gateway", JSON,
                announced::incrementAndGet, mfa());

        ResponseEntity<String> answer = controller.putServer("mcp-jira", administrator(), body("{\"reason\":\"incident\"}"));

        assertThat(answer.getStatusCode().value()).isEqualTo(503);
        assertThat(answer.getHeaders().getFirst("Retry-After")).isEqualTo("10");
        assertThat(JSON.readTree(answer.getBody()).path("error").asString()).isEqualTo("upstream_unavailable");
        assertThat(events).isEmpty();
        assertThat(announced.get()).isZero();
    }

    @Test
    void aFailedLiftIsA503TooAndTheSwitchStaysOn() {
        KillSwitchStore store = mock(KillSwitchStore.class);
        doThrow(new DataAccessResourceFailureException("down")).when(store).delete(any(), any());
        ServerRegistry servers = mock(ServerRegistry.class);
        when(servers.find("mcp-jira")).thenReturn(Optional.of(mock(McpServer.class)));
        KillSwitchController controller = new KillSwitchController(store, mock(KillSwitches.class), servers, new AuditLog(), "mcp-gateway", JSON, () -> { },
                mfa());

        assertThat(controller.deleteServer("mcp-jira", administrator(), new MockHttpServletRequest()).getStatusCode().value()).isEqualTo(503);
    }

    @Test
    void anUnreadableStoreIsNoEmptyList() {
        KillSwitches switches = mock(KillSwitches.class);
        when(switches.entries()).thenReturn(Optional.empty());
        KillSwitchController controller = new KillSwitchController(mock(KillSwitchStore.class), switches, mock(ServerRegistry.class),
                new AuditLog(), "mcp-gateway", JSON, () -> { }, mfa());

        ResponseEntity<String> answer = controller.list(administrator(), new MockHttpServletRequest());

        assertThat(answer.getStatusCode().value()).isEqualTo(503);
        verify(switches, never()).status(any(), any());
    }
}
