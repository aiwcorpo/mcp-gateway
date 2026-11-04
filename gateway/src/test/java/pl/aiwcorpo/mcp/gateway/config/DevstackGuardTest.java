package pl.aiwcorpo.mcp.gateway.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;
import org.springframework.mock.env.MockEnvironment;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

/** Every relaxation of the production rules needs the devstack profile, acknowledged twice; without it the start is refused. */
class DevstackGuardTest {

    /** A production-shaped configuration: https everywhere, state directory, no test keys, manifests required. */
    static Map<String, String> production() {
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
        m.put("gateway.internal-jwt.keys-file", "/keys/internal-jwt.jwks");
        m.put("gateway.activity.cursor-key", "a-key-shared-by-every-instance");
        m.put("gateway.mcp.list-cursor-key", "another-key-shared-by-every-instance");
        m.put("gateway.redis.wait-replicas", "1");
        m.put("gateway.internal-endpoint.port", "8443");
        m.put("gateway.admin.audience", "mcp-gateway-admin");
        m.put("gateway.sessions.client-idle-timeout", "1h");
        m.put("gateway.upstream.timeout", "30s");
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

    private static MockEnvironment environment(boolean profile, boolean property) {
        MockEnvironment env = new MockEnvironment();
        if (profile) {
            env.setActiveProfiles("devstack");
        }
        env.setProperty(DevstackGuard.ACK_PROPERTY, Boolean.toString(property));
        return env;
    }

    /** The variables of the process, as the guard reads them. */
    private static Map<String, String> processEnvironment(boolean acknowledged) {
        return acknowledged ? Map.of(DevstackGuard.ACK_ENVIRONMENT, "true") : Map.of();
    }

    private static void check(Map<String, String> values, boolean profile, boolean property, boolean variable) {
        DevstackGuard.check(bind(values), environment(profile, property), processEnvironment(variable));
    }

    @Test
    void aProductionConfigurationStartsWithoutAnyProfile() {
        assertThat(DevstackGuard.relaxations(bind(production()))).isEmpty();
        check(production(), false, false, false);
    }

    @Test
    void everyRelaxationIsRefusedWithoutTheProfile() {
        RELAXATIONS.forEach((name, change) -> {
            Map<String, String> values = production();
            values.putAll(change);
            assertThat(DevstackGuard.relaxations(bind(values))).as(name).isNotEmpty();
            assertThatThrownBy(() -> check(values, false, false, false))
                    .as(name).isInstanceOf(IllegalStateException.class).hasMessageContaining("devstack");
            // Even with both acknowledgements: they mean nothing without the profile.
            assertThatThrownBy(() -> check(values, false, true, true))
                    .as(name + " with the acknowledgements only").isInstanceOf(IllegalStateException.class);
        });
    }

    @Test
    void everyRelaxationNeedsBothAcknowledgements() {
        RELAXATIONS.forEach((name, change) -> {
            Map<String, String> values = production();
            values.putAll(change);
            for (boolean[] acks : new boolean[][] {{false, false}, {true, false}, {false, true}}) {
                assertThatThrownBy(() -> check(values, true, acks[0], acks[1]))
                        .as(name + " acknowledged " + acks[0] + "/" + acks[1]).isInstanceOf(IllegalStateException.class)
                        .hasMessageContaining(DevstackGuard.ACK_ENVIRONMENT);
            }
        });
    }

    @Test
    void everyRelaxationIsAllowedWithTheProfileAcknowledgedTwice() {
        RELAXATIONS.forEach((name, change) -> {
            Map<String, String> values = production();
            values.putAll(change);
            check(values, true, true, true);
        });
    }

    @Test
    void theVariableCountsOnlyWhenItIsAVariableOfTheProcess() {
        Map<String, String> values = production();
        values.put("gateway.allow-plain-http", "true");
        // The same name as a property (a command line argument, a JSON in SPRING_APPLICATION_JSON, a file) is no variable.
        MockEnvironment env = environment(true, true);
        env.setProperty(DevstackGuard.ACK_ENVIRONMENT, "true");
        assertThatThrownBy(() -> DevstackGuard.check(bind(values), env, Map.of())).isInstanceOf(IllegalStateException.class)
                .hasMessageContaining(DevstackGuard.ACK_ENVIRONMENT);
        DevstackGuard.check(bind(values), environment(true, true), processEnvironment(true));
    }

    @Test
    void theMetricShowsWhetherTheProfileIsInForce() {
        SimpleMeterRegistry on = new SimpleMeterRegistry();
        DevstackGuard.bindMetric(environment(true, true), on);
        assertThat(on.get("mcp_gateway_devstack_active").gauge().value()).isEqualTo(1.0);
        SimpleMeterRegistry off = new SimpleMeterRegistry();
        DevstackGuard.bindMetric(environment(false, false), off);
        assertThat(off.get("mcp_gateway_devstack_active").gauge().value()).isEqualTo(0.0);
    }

    @Test
    void keysThatAreGeneratedPerProcessAreRefusedOutsideTheDevstackBecauseASecondInstanceCouldNotUseThem() {
        for (String key : List.of("gateway.internal-jwt.keys-file", "gateway.activity.cursor-key", "gateway.mcp.list-cursor-key",
                "gateway.redis.wait-replicas")) {
            Map<String, String> values = production();
            values.remove(key);
            assertThat(DevstackGuard.relaxations(bind(values))).as(key).hasSize(1).first().asString().contains(key);
            assertThatThrownBy(() -> check(values, false, false, false)).as(key).hasMessageContaining("devstack");
            check(values, true, true, true);
        }
    }

    @Test
    void aMissingStateDirectoryIsARelaxation() {
        Map<String, String> values = production();
        values.remove("gateway.policy.state-dir");
        assertThat(DevstackGuard.relaxations(bind(values))).containsExactly("gateway.policy.state-dir is empty");
        assertThatThrownBy(() -> check(values, false, false, false)).hasMessageContaining("state-dir");
        check(values, true, true, true);
    }

    @Test
    void aServerInStaticModeIsARelaxationToo() {
        Map<String, String> values = production();
        values.put("gateway.servers.mcp-jira.manifest", "static");
        assertThat(DevstackGuard.relaxations(bind(values))).hasSize(1);
        assertThatThrownBy(() -> check(values, false, true, true)).hasMessageContaining("static");
        check(values, true, true, true);
    }

    @Test
    void theProfileMustBeTheOnlyOneAndNeverStandsAloneWithoutTheAcknowledgements() {
        assertThat(DevstackGuard.problems(List.of("devstack", "prod"), true, true, List.of())).anyMatch(p -> p.contains("only active profile"));
        assertThat(DevstackGuard.problems(List.of("devstack"), true, false, List.of())).isNotEmpty();
        assertThat(DevstackGuard.problems(List.of("devstack"), true, true, List.of("x"))).isEmpty();
        assertThat(DevstackGuard.problems(List.of(), true, true, List.of("x"))).hasSize(1);
        assertThat(DevstackGuard.problems(List.of("prod"), true, true, List.of())).isEmpty();
    }

    private static Map<String, String> publicTls(Path directory, String keyMode) throws Exception {
        Path certificate = Files.writeString(directory.resolve("public.crt"), "certificate");
        Path key = Files.writeString(directory.resolve("public.key"), "key");
        Files.setPosixFilePermissions(key, PosixFilePermissions.fromString(keyMode));
        Map<String, String> values = production();
        values.put("gateway.public-tls.enabled", "true");
        values.put("gateway.public-tls.certificate", certificate.toString());
        values.put("gateway.public-tls.private-key", key.toString());
        return values;
    }

    @Test
    void publicTlsIsOffByDefaultAndNeedsNothingThen() {
        assertThat(bind(production()).publicTls().enabled()).isFalse();
        assertThat(DevstackGuard.publicTlsProblems(bind(production()))).isEmpty();
    }

    @Test
    void publicTlsWithAPrivateKeyStartsWithoutAnyProfile(@TempDir Path directory) throws Exception {
        Map<String, String> values = publicTls(directory, "rw-------");
        assertThat(DevstackGuard.relaxations(bind(values))).isEmpty();
        check(values, false, false, false);
        check(publicTls(directory, "r--r-----"), false, false, false);
    }

    @Test
    void publicTlsWithoutACertificateOrKeyIsRefusedEvenInTheDevstack(@TempDir Path directory) throws Exception {
        for (String setting : List.of("gateway.public-tls.certificate", "gateway.public-tls.private-key")) {
            Map<String, String> blank = publicTls(directory, "rw-------");
            blank.remove(setting);
            assertThatThrownBy(() -> check(blank, true, true, true)).as(setting + " blank")
                    .isInstanceOf(IllegalStateException.class).hasMessageContaining(setting);
            Map<String, String> missing = publicTls(directory, "rw-------");
            missing.put(setting, directory.resolve("absent.pem").toString());
            assertThatThrownBy(() -> check(missing, true, true, true)).as(setting + " missing file")
                    .isInstanceOf(IllegalStateException.class).hasMessageContaining("not a readable file");
        }
    }

    @Test
    void aPublicTlsKeyReadableByAllIsARelaxation(@TempDir Path directory) throws Exception {
        for (String mode : List.of("rw-r--r--", "rw-rw-r--", "rw------x")) {
            Map<String, String> values = publicTls(directory, mode);
            assertThat(DevstackGuard.relaxations(bind(values))).as(mode).containsExactly("gateway.public-tls.private-key is readable by all users");
            assertThatThrownBy(() -> check(values, false, false, false)).as(mode).hasMessageContaining("readable by all users");
            assertThatThrownBy(() -> check(values, true, true, false)).as(mode).hasMessageContaining(DevstackGuard.ACK_ENVIRONMENT);
            check(values, true, true, true);
        }
    }

    @Test
    void aDisabledPublicTlsIgnoresItsFiles(@TempDir Path directory) throws Exception {
        Map<String, String> values = publicTls(directory, "rw-rw-rw-");
        values.put("gateway.public-tls.enabled", "false");
        assertThat(DevstackGuard.relaxations(bind(values))).isEmpty();
        check(values, false, false, false);
    }
}
