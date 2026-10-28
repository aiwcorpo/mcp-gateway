package pl.aiwcorpo.mcp.gateway.virtual;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

import pl.aiwcorpo.mcp.gateway.admin.AdminException;
import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.config.GatewayProperties;
import pl.aiwcorpo.mcp.gateway.server.ServerRegistry;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

class VirtualServerServiceTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    private final VirtualServerStore store = mock(VirtualServerStore.class);
    private final ServerRegistry registry = new ServerRegistry(Map.of(
            "mcp-jira", server("jira", "https://mcp-jira.internal:8443/mcp", Map.of("get_issue", tool("READ_ONLY"), "add_comment", tool("UPDATE"))),
            "mcp-gitlab", server("gitlab", "https://mcp-gitlab.internal:8443/mcp", Map.of("get_issue", tool("READ_ONLY")))), "static");
    private final VirtualServerService service = new VirtualServerService(store, registry, new pl.aiwcorpo.mcp.gateway.support.GroupRulesAuthorizer(), 2);
    private final GatewayUser reader = new GatewayUser("sub-reader", "reader", "mcp-portal-bff", List.of("mcp-jira-read"), "t");

    @Test
    void invalidSlugsNeverReachTheStore() {
        for (String slug : new String[] {null, "", "Upper", "-a", "a-", "a_b", "a b", "a/b", "..", "a\n", "x".repeat(64), "\u0142"}) {
            assertThat(service.usableBy(reader, slug)).as(String.valueOf(slug)).isEmpty();
            assertThatThrownBy(() -> service.delete(reader, slug)).isInstanceOfSatisfying(AdminException.class,
                    e -> assertThat(e.status()).isEqualTo(HttpStatus.NOT_FOUND));
        }
        verify(store, never()).find(any());
        verify(store, never()).delete(any(), any());
    }

    @Test
    void onlyTheOwnerCanUseALink() {
        when(store.find("mine")).thenReturn(Optional.of(new VirtualServer("mine", "sub-reader", "Mine", List.of("jira__get_issue"), Instant.now())));
        when(store.find("theirs")).thenReturn(Optional.of(new VirtualServer("theirs", "someone-else", "Theirs", List.of("jira__get_issue"), Instant.now())));
        assertThat(service.usableBy(reader, "mine")).isPresent();
        assertThat(service.usableBy(reader, "theirs")).isEmpty();
        assertThat(service.usableBy(reader, "missing")).isEmpty();
    }

    @Test
    void createRefusesEveryToolTheOwnerMayNotCallAndStoresNothing() {
        for (String tool : List.of("jira__add_comment", "gitlab__get_issue", "jira__nope", "opensearch__x")) {
            VirtualServerService.Create request = new VirtualServerService.Create("link", "Link", List.of("jira__get_issue", tool));
            assertThatThrownBy(() -> service.create(reader, request)).as(tool).isInstanceOfSatisfying(AdminException.class, e -> {
                assertThat(e.status()).isEqualTo(HttpStatus.FORBIDDEN);
                assertThat(e.code()).isEqualTo("access_denied");
            });
        }
        verify(store, never()).insert(any(), anyInt());
    }

    @Test
    void createMapsATakenSlugTo409() {
        when(store.insert(any(), anyInt())).thenReturn(VirtualServerStore.Inserted.SLUG_TAKEN);
        assertThatThrownBy(() -> service.create(reader, new VirtualServerService.Create("link", "Link", List.of("jira__get_issue"))))
                .isInstanceOfSatisfying(AdminException.class, e -> assertThat(e.code()).isEqualTo("slug_taken"));
    }

    @Test
    void createPassesTheLimitToTheStoreAndRefusesAtIt() {
        when(store.insert(any(), eq(2))).thenReturn(VirtualServerStore.Inserted.LIMIT_REACHED);
        assertThatThrownBy(() -> service.create(reader, new VirtualServerService.Create("link", "Link", List.of("jira__get_issue"))))
                .isInstanceOfSatisfying(AdminException.class, e -> {
                    assertThat(e.status()).isEqualTo(HttpStatus.CONFLICT);
                    assertThat(e.code()).isEqualTo("virtual_server_limit_reached");
                    assertThat(e.auditReason()).isEqualTo("virtual_server_limit");
                });
    }

    @Test
    void parseKeepsTheOrderOfChecks() {
        assertThat(code("{\"slug\":\"Bad\",\"resourceDefaults\":{\"Jira::Project\":[\"ABC\"]}}")).isEqualTo("resource_defaults_unsupported");
        assertThat(code("{\"slug\":\"Bad\",\"resourceDefaults\":[]}")).isEqualTo("invalid_request");
        assertThat(code("{\"slug\":\"Bad\",\"resourceDefaults\":{}}")).isEqualTo("invalid_request");
        assertThat(code("{\"slug\":\"ok\",\"displayName\":\"n\",\"tools\":[\"jira__get_issue\"],\"resourceDefaults\":null}"))
                .isEqualTo("invalid_request");
        assertThat(service.parse(JSON.readTree("{\"slug\":\"ok\",\"displayName\":\"Za\u017c\u00f3\u0142\u0107 g\u0119\u015bl\u0105\",\"tools\":[\"jira__get_issue\"],"
                + "\"resourceDefaults\":{}}"))).isEqualTo(new VirtualServerService.Create("ok", "Za\u017c\u00f3\u0142\u0107 g\u0119\u015bl\u0105", List.of("jira__get_issue")));
    }

    @Test
    void toolListIsBounded() {
        StringBuilder tools = new StringBuilder("[");
        for (int i = 0; i < 101; i++) {
            tools.append(i == 0 ? "" : ",").append("\"jira__tool_").append(i).append('"');
        }
        assertThat(code("{\"slug\":\"ok\",\"displayName\":\"n\",\"tools\":" + tools + "]}")).isEqualTo("invalid_request");
    }

    private String code(String body) {
        JsonNode node = JSON.readTree(body);
        try {
            service.parse(node);
            return "accepted";
        } catch (AdminException e) {
            return e.code();
        }
    }

    private static GatewayProperties.Server server(String system, String url, Map<String, GatewayProperties.Tool> tools) {
        return new GatewayProperties.Server(system, URI.create(url), "1.0.0", true, "static",
                new GatewayProperties.Credential(true, List.copyOf(Set.of("user-secret")), List.of(), false), tools);
    }

    private static GatewayProperties.Tool tool(String risk) {
        return new GatewayProperties.Tool(risk, "A tool.", null, null, false, List.of());
    }
}
