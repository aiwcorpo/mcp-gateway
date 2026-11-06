package pl.aiwcorpo.mcp.gateway.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;

import pl.aiwcorpo.mcp.gateway.GatewayApplication;
import pl.aiwcorpo.mcp.gateway.support.TestIdp;

/**
 * The refusal in a real Spring start (SpringApplication with the initializer of spring.factories), not on a map of properties:
 * with relaxed settings and without the devstack profile the context does not come up, and before it refuses nothing was asked of
 * the IdP. The process of these tests has MCP_DEVSTACK_ACKNOWLEDGED=true (surefire), so every refusal
 * below is the profile's or the property's doing.
 */
class DevstackContextTest {

    private TestIdp idp;
    private Map<String, String> relaxed;

    @BeforeEach
    void setUp() throws Exception {
        idp = new TestIdp();
        relaxed = DevstackGuardTest.production();
        relaxed.put("gateway.internal-jwt.allow-test-keys", "true");
        relaxed.put("gateway.oidc.jwks-uri", idp.jwksUri());
        relaxed.put("spring.main.banner-mode", "off");
        // The placeholders of application.yml that have no default: a deployment sets them, the initializer needs them to bind.
        for (String name : new String[] {"MCP_BROKER_TLS_NAME", "MCP_DB_PASSWORD", "MCP_OIDC_ISSUER", "MCP_REDIS_HOST", "MCP_TLS_KEYSTORE",
                "MCP_TLS_STORE_PASSWORD", "MCP_TLS_TRUSTSTORE"}) {
            relaxed.put(name, "x");
        }
        relaxed.put("MCP_BROKER_URL", "https://broker.internal:8443");
        relaxed.put("MCP_DB_URL", "jdbc:postgresql://localhost:1/none");
        relaxed.put("MCP_OIDC_JWKS_URI", idp.jwksUri());
        relaxed.put("MCP_PUBLIC_URL", "https://mcp.aiwcorpo.pl");
    }

    @AfterEach
    void tearDown() {
        idp.close();
    }

    private Throwable start(Map<String, Object> extra) {
        Map<String, Object> all = new java.util.HashMap<>(relaxed);
        all.putAll(extra);
        return run(all);
    }

    private Throwable run(Map<String, Object> all) {
        try {
            // Command line arguments: they win over application.yml, whose placeholders need the variables of a deployment.
            String[] arguments = all.entrySet().stream().map(e -> "--" + e.getKey() + "=" + e.getValue()).toArray(String[]::new);
            new SpringApplicationBuilder(GatewayApplication.class).web(WebApplicationType.NONE).run(arguments).close();
            return null;
        } catch (Throwable failure) {
            return failure;
        }
    }

    private static boolean refusedByTheGuard(Throwable failure, String... fragments) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (cause instanceof IllegalStateException && cause.getMessage() != null && cause.getMessage().startsWith("refusing to start")) {
                for (String fragment : fragments) {
                    if (!cause.getMessage().contains(fragment)) {
                        return false;
                    }
                }
                return true;
            }
        }
        return false;
    }

    /** The refusal came from the initializer, which runs before any bean: nothing else could have stopped the start this early. */
    private static boolean raisedByTheInitializer(Throwable failure) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (java.util.Arrays.stream(cause.getStackTrace()).anyMatch(f -> f.getClassName().endsWith("DevstackInitializer"))) {
                return true;
            }
        }
        return false;
    }

    private void assertNothingWasAsked() {
        assertThat(idp.jwksRequests()).as("requests for the IdP keys before the refusal").isZero();
    }

    @Test
    void relaxedSettingsWithoutAProfileDoNotStartAndAskForNothing() {
        Throwable failure = start(Map.of());
        assertThat(refusedByTheGuard(failure, "gateway.internal-jwt.allow-test-keys", "gateway.oidc.jwks-uri is not https")).as(String.valueOf(failure)).isTrue();
        assertThat(raisedByTheInitializer(failure)).as("raised before the first bean").isTrue();
        assertNothingWasAsked();
    }

    @Test
    void theProfileAloneWithoutThePropertyDoesNotStart() {
        Throwable failure = start(Map.of("spring.profiles.active", "devstack"));
        assertThat(refusedByTheGuard(failure, DevstackGuard.ACK_PROPERTY)).as(String.valueOf(failure)).isTrue();
        assertNothingWasAsked();
    }

    @Test
    void theProfileMustBeTheOnlyOneAlsoWhenAnotherProfileBringsItIn() {
        Throwable included = start(Map.of("spring.profiles.active", "devstack", "spring.profiles.include", "other",
                DevstackGuard.ACK_PROPERTY, "true"));
        assertThat(refusedByTheGuard(included, "only active profile")).as(String.valueOf(included)).isTrue();
        Throwable grouped = start(Map.of("spring.profiles.active", "custom", "spring.profiles.group.custom", "devstack",
                DevstackGuard.ACK_PROPERTY, "true"));
        assertThat(refusedByTheGuard(grouped, "only active profile")).as(String.valueOf(grouped)).isTrue();
        assertNothingWasAsked();
    }

    @Test
    void aDefaultProfileIsNoActiveProfile() {
        Throwable failure = start(Map.of("spring.profiles.default", "devstack", DevstackGuard.ACK_PROPERTY, "true"));
        assertThat(refusedByTheGuard(failure, "allowed only with the 'devstack' profile")).as(String.valueOf(failure)).isTrue();
        assertNothingWasAsked();
    }

    @Test
    void withTheProfileAndBothAcknowledgementsTheGuardLetsTheStartGoOn() {
        // The start fails later (there is no database, no Redis in this test), but not because of the guard.
        Throwable failure = start(Map.of("spring.profiles.active", "devstack", DevstackGuard.ACK_PROPERTY, "true"));
        assertThat(failure).isNotNull();
        assertThat(refusedByTheGuard(failure)).as(String.valueOf(failure)).isFalse();
    }

    /** In production mode (no profile, no relaxation) a signing key named dev- stops the start: the guard passes, the key loader refuses. */
    @Test
    void aDevKeyStopsAProductionStartAtTheKeyLoader() throws Exception {
        Path keys = Files.createTempDirectory("prod-keys");
        String a = new String(getClass().getClassLoader().getResourceAsStream(
                "mcp-contracts/test-vectors/keys/test-gateway-jwt-a.NOT-FOR-PRODUCTION.private.jwk.json").readAllBytes());
        Files.writeString(keys.resolve("keys.json"), "{\"keys\":[" + a.replace("test-gw-2026-10-a", "dev-gw-2026-10-a") + "]}");
        Map<String, Object> production = new java.util.HashMap<>();
        relaxed.keySet().stream().filter(k -> k.startsWith("MCP_") || k.startsWith("spring.")).forEach(k -> production.put(k, relaxed.get(k)));
        production.putAll(DevstackGuardTest.production());
        production.put("gateway.internal-jwt.keys-file", keys.resolve("keys.json").toString());
        production.put("gateway.internal-jwt.active-kid", "dev-gw-2026-10-a");
        production.put("gateway.oidc.jwks-uri", "https://127.0.0.1:9/certs");
        Throwable failure = run(production);
        assertThat(failure).isNotNull();
        boolean refusedByLoader = false;
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            refusedByLoader |= cause.getMessage() != null && cause.getMessage().contains("dev- keys need dev mode");
        }
        assertThat(refusedByLoader).as(String.valueOf(failure)).isTrue();
    }
}
