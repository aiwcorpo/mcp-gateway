package pl.aiwcorpo.mcp.gateway.config;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;

import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;

/**
 * Refuses to start with a relaxation of the production rules unless the {@code devstack} profile is the only active profile and
 * is acknowledged twice, by a property and by an environment variable, so that a copied configuration does not carry a
 * development setting into production. The relaxations are: signing keys named {@code test-*} (internal JWT and policy bundles),
 * a bootstrap of the registry from the manifest a server serves itself, tools from the configuration instead of an approved
 * manifest, plain http for the public URL, the IdP and the policy bundles, and no state directory for the rollback protection.
 * The pattern is the one of the server starter (profile {@code devstack}, {@code aiwcorpo.mcp.platform.devstack.acknowledged}).
 */
public final class DevstackGuard {

    public static final String PROFILE = "devstack";
    public static final String ACK_PROPERTY = "aiwcorpo.mcp.platform.devstack.acknowledged";
    public static final String ACK_ENVIRONMENT = "MCP_DEVSTACK_ACKNOWLEDGED";

    private static final Logger log = LoggerFactory.getLogger(DevstackGuard.class);

    /** What the configuration asks for beyond production; each item names the setting. */
    public static List<String> relaxations(GatewayProperties p) {
        List<String> used = new ArrayList<>();
        if (p.internalJwt().allowTestKeys()) {
            used.add("gateway.internal-jwt.allow-test-keys");
        }
        if (p.policy().allowTestKeys()) {
            used.add("gateway.policy.allow-test-keys");
        }
        if (p.registry().bootstrapFromServer()) {
            used.add("gateway.registry.bootstrap-from-server");
        }
        if (ServerRegistryModes.anyStatic(p)) {
            used.add("gateway.registry.mode / gateway.servers.*.manifest = static");
        }
        if (p.allowPlainHttp()) {
            used.add("gateway.allow-plain-http");
        }
        if (!https(p.publicUrl())) {
            used.add("gateway.public-url is not https");
        }
        if (!https(p.oidc().jwksUri())) {
            used.add("gateway.oidc.jwks-uri is not https");
        }
        if (present(p.oidc().tokenUri()) && !https(p.oidc().tokenUri())) {
            used.add("gateway.oidc.token-uri is not https");
        }
        if (!https(p.policy().mainUrl())) {
            used.add("gateway.policy.main-url is not https");
        }
        if (present(p.policy().overridesUrl()) && !https(p.policy().overridesUrl())) {
            used.add("gateway.policy.overrides-url is not https");
        }
        if (p.policy().stateDir() == null || p.policy().stateDir().isBlank()) {
            used.add("gateway.policy.state-dir is empty");
        }
        return used;
    }

    /**
     * Problems with the combination of profiles, acknowledgements and relaxations; empty means the start may go on.
     *
     * @param activeProfiles the active profiles of the environment
     * @param acknowledgedByProperty value of {@link #ACK_PROPERTY}
     * @param acknowledgedByEnvironment value of {@link #ACK_ENVIRONMENT}
     */
    public static List<String> problems(List<String> activeProfiles, boolean acknowledgedByProperty, boolean acknowledgedByEnvironment,
                                        List<String> relaxations) {
        List<String> problems = new ArrayList<>();
        boolean devstack = activeProfiles.equals(List.of(PROFILE));
        if (activeProfiles.contains(PROFILE) && !devstack) {
            problems.add("the 'devstack' profile must be the only active profile (active: " + activeProfiles + ")");
        }
        if (devstack && !(acknowledgedByProperty && acknowledgedByEnvironment)) {
            problems.add("the 'devstack' profile relaxes production rules and needs two acknowledgements, so that a copied "
                    + "configuration does not carry it to production: " + ACK_PROPERTY + "=true and the environment variable "
                    + ACK_ENVIRONMENT + "=true");
        }
        boolean allowed = devstack && acknowledgedByProperty && acknowledgedByEnvironment;
        if (!allowed) {
            relaxations.forEach(r -> problems.add(r + " is allowed only with the 'devstack' profile (acknowledged twice)"));
        }
        return problems;
    }

    /** Checks the configuration at start; throws with every problem at once, or warns and counts when the profile is in force. */
    public static DevstackGuard check(GatewayProperties properties, Environment environment, MeterRegistry meters) {
        List<String> used = relaxations(properties);
        List<String> problems = problems(List.of(environment.getActiveProfiles()),
                "true".equalsIgnoreCase(environment.getProperty(ACK_PROPERTY, "")),
                "true".equalsIgnoreCase(environment.getProperty(ACK_ENVIRONMENT, "")), used);
        if (!problems.isEmpty()) {
            throw new IllegalStateException("refusing to start: " + String.join("; ", problems));
        }
        boolean devstack = List.of(environment.getActiveProfiles()).equals(List.of(PROFILE));
        Gauge.builder("mcp_gateway_devstack_active", () -> devstack ? 1 : 0).description("1 when the gateway runs with the devstack profile")
                .register(meters);
        if (devstack) {
            // The environment has no field in the manifest or the audit, so every start says it, and the gauge shows it.
            log.warn("event=devstack_profile detail=\"development relaxations are in force: {}; this gateway must not run in production\"",
                    used);
        }
        return new DevstackGuard();
    }

    private static boolean https(URI uri) {
        return uri != null && "https".equals(uri.getScheme());
    }

    private static boolean present(URI uri) {
        return uri != null && !uri.toString().isBlank();
    }

    /** The registry mode of a server, as the registry reads it. */
    private static final class ServerRegistryModes {
        static boolean anyStatic(GatewayProperties p) {
            if ("static".equals(p.registry().mode())) {
                return true;
            }
            for (Map.Entry<String, GatewayProperties.Server> e : p.servers().entrySet()) {
                if ("static".equals(e.getValue().manifest())) {
                    return true;
                }
            }
            return false;
        }
    }
}
