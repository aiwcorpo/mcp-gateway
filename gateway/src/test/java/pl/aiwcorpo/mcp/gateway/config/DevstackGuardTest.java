package pl.aiwcorpo.mcp.gateway.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;
import org.springframework.mock.env.MockEnvironment;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

/** Every relaxation of the production rules needs the devstack profile, acknowledged twice; without it the start is refused. */
class DevstackGuardTest {

    /** A production-shaped configuration: https everywhere, state directory, no test keys, manifests required. */
    private static Map<String, String> production() {
        Map<String, String> m = new HashMap<>();
        m.put("gateway.public-url", "https://mcp.aiwcorpo.pl");
        m.put("gateway.oidc.issuer", "https://idp.aiwcorpo.pl/realms/corp");
        m.put("gateway.oidc.jwks-uri", "https://idp.aiwcorpo.pl/realms/corp/certs");
        m.put("gateway.oidc.token-uri", "https://idp.aiwcorpo.pl/realms/corp/token");
        m.put("gateway.tls.keystore", "/k.p12");
        m.put("gateway.tls.truststore", "/t.p12");
        m.put("gateway.tls.store-password", "x");
        m.put("gateway.broker.url", "https://broker.internal:8443");
        m.put("gateway.broker.tls-name", "broker.internal");
        m.put("gateway.redis.host", "redis");
        m.put("gateway.policy.main-url", "https://policies.aiwcorpo.pl/policies/main/");
        m.put("gateway.policy.overrides-url", "https://policies.aiwcorpo.pl/policies/overrides/");
        m.put("gateway.policy.main-key-id", "policies-main-2026");
        m.put("gateway.policy.main-key-file", "/main.pem");
        m.put("gateway.policy.state-dir", "/app/state");
        m.put("gateway.registry.mode", "required");
        m.put("gateway.internal-jwt.allow-test-keys", "false");
        m.put("gateway.internal-endpoint.port", "8443");
        m.put("gateway.admin.audience", "mcp-gateway-admin");
        m.put("gateway.sessions.client-idle-timeout", "1h");
        m.put("gateway.upstream.timeout", "30s");
        m.put("gateway.virtual-servers.max-per-user", "50");
        m.put("gateway.metrics.allowed-client-cns[0]", "mcp-prometheus");
        m.put("gateway.servers.mcp-jira.system", "jira");
        m.put("gateway.servers.mcp-jira.internal-url", "https://mcp-jira.internal:8443/mcp");
        m.put("gateway.servers.mcp-jira.credential.required", "true");
        m.put("gateway.servers.mcp-jira.credential.accepted-types[0]", "user-secret");
        m.put("gateway.servers.mcp-jira.tools.get_issue.risk", "READ_ONLY");
        m.put("gateway.servers.mcp-jira.tools.get_issue.description", "Gets.");
        return m;
    }

    private static GatewayProperties bind(Map<String, String> values) {
        return new Binder(new MapConfigurationPropertySource(values)).bind("gateway", GatewayProperties.class).get();
    }

    /** One relaxation each: the setting and the text that names it in the refusal. */
    private static final Map<String, Map<String, String>> RELAXATIONS = Map.of(
            "gateway.internal-jwt.allow-test-keys", Map.of("gateway.internal-jwt.allow-test-keys", "true"),
            "gateway.policy.allow-test-keys", Map.of("gateway.policy.allow-test-keys", "true"),
            "gateway.registry.bootstrap-from-server", Map.of("gateway.registry.bootstrap-from-server", "true"),
            "static", Map.of("gateway.registry.mode", "static"),
            "gateway.allow-plain-http", Map.of("gateway.allow-plain-http", "true"),
            "gateway.public-url is not https", Map.of("gateway.public-url", "http://localhost:18700"),
            "gateway.oidc.jwks-uri is not https", Map.of("gateway.oidc.jwks-uri", "http://keycloak:8080/certs"),
            "gateway.oidc.token-uri is not https", Map.of("gateway.oidc.token-uri", "http://keycloak:8080/token"),
            "gateway.policy.main-url is not https", Map.of("gateway.policy.main-url", "http://policies.internal:8080/policies/main/"),
            "gateway.policy.overrides-url is not https",
            Map.of("gateway.policy.overrides-url", "http://policies.internal:8080/policies/overrides/"));

    private static MockEnvironment environment(boolean profile, boolean property, boolean variable) {
        MockEnvironment env = new MockEnvironment();
        if (profile) {
            env.setActiveProfiles("devstack");
        }
        env.setProperty(DevstackGuard.ACK_PROPERTY, Boolean.toString(property));
        env.setProperty(DevstackGuard.ACK_ENVIRONMENT, Boolean.toString(variable));
        return env;
    }

    @Test
    void aProductionConfigurationStartsWithoutAnyProfile() {
        assertThat(DevstackGuard.relaxations(bind(production()))).isEmpty();
        DevstackGuard.check(bind(production()), environment(false, false, false), new SimpleMeterRegistry());
    }

    @Test
    void everyRelaxationIsRefusedWithoutTheProfile() {
        RELAXATIONS.forEach((name, change) -> {
            Map<String, String> values = production();
            values.putAll(change);
            assertThat(DevstackGuard.relaxations(bind(values))).as(name).isNotEmpty();
            assertThatThrownBy(() -> DevstackGuard.check(bind(values), environment(false, false, false), new SimpleMeterRegistry()))
                    .as(name).isInstanceOf(IllegalStateException.class).hasMessageContaining("devstack");
            // Even with both acknowledgements: they mean nothing without the profile.
            assertThatThrownBy(() -> DevstackGuard.check(bind(values), environment(false, true, true), new SimpleMeterRegistry()))
                    .as(name + " with the acknowledgements only").isInstanceOf(IllegalStateException.class);
        });
    }

    @Test
    void everyRelaxationNeedsBothAcknowledgements() {
        RELAXATIONS.forEach((name, change) -> {
            Map<String, String> values = production();
            values.putAll(change);
            for (boolean[] acks : new boolean[][] {{false, false}, {true, false}, {false, true}}) {
                assertThatThrownBy(() -> DevstackGuard.check(bind(values), environment(true, acks[0], acks[1]), new SimpleMeterRegistry()))
                        .as(name + " acknowledged " + acks[0] + "/" + acks[1]).isInstanceOf(IllegalStateException.class)
                        .hasMessageContaining(DevstackGuard.ACK_ENVIRONMENT);
            }
        });
    }

    @Test
    void everyRelaxationIsAllowedWithTheProfileAcknowledgedTwiceAndIsCounted() {
        RELAXATIONS.forEach((name, change) -> {
            Map<String, String> values = production();
            values.putAll(change);
            SimpleMeterRegistry meters = new SimpleMeterRegistry();
            DevstackGuard.check(bind(values), environment(true, true, true), meters);
            assertThat(meters.get("mcp_gateway_devstack_active").gauge().value()).as(name).isEqualTo(1.0);
        });
    }

    @Test
    void aMissingStateDirectoryIsARelaxation() {
        Map<String, String> values = production();
        values.remove("gateway.policy.state-dir");
        assertThat(DevstackGuard.relaxations(bind(values))).containsExactly("gateway.policy.state-dir is empty");
        assertThatThrownBy(() -> DevstackGuard.check(bind(values), environment(false, false, false), new SimpleMeterRegistry()))
                .hasMessageContaining("state-dir");
        DevstackGuard.check(bind(values), environment(true, true, true), new SimpleMeterRegistry());
    }

    @Test
    void aServerInStaticModeIsARelaxationToo() {
        Map<String, String> values = production();
        values.put("gateway.servers.mcp-jira.manifest", "static");
        assertThat(DevstackGuard.relaxations(bind(values))).hasSize(1);
    }

    @Test
    void theProfileMustBeTheOnlyOneAndNeverStandsAloneWithoutTheAcknowledgements() {
        assertThat(DevstackGuard.problems(List.of("devstack", "prod"), true, true, List.of())).anyMatch(p -> p.contains("only active profile"));
        assertThat(DevstackGuard.problems(List.of("devstack"), true, false, List.of())).isNotEmpty();
        assertThat(DevstackGuard.problems(List.of("devstack"), true, true, List.of("x"))).isEmpty();
        assertThat(DevstackGuard.problems(List.of(), true, true, List.of("x"))).hasSize(1);
        assertThat(DevstackGuard.problems(List.of("prod"), true, true, List.of())).isEmpty();
    }

    @Test
    void theProductionConfigurationDoesNotAcceptTestKeyIdsEither() {
        // A bundle key named test-* is refused by the bundle library unless allow-test-keys is on, which needs the profile.
        Map<String, String> values = production();
        values.put("gateway.policy.main-key-id", "test-policies-main-dev");
        assertThat(DevstackGuard.relaxations(bind(values))).as("the id alone is no relaxation: the library refuses it").isEmpty();
    }
}
