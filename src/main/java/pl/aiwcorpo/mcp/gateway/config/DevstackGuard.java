package pl.aiwcorpo.mcp.gateway.config;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
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
 * is acknowledged twice, by a property and by an environment variable of the process (the variable is read from the process
 * environment only, never from a property source). The acknowledgements live in the configuration of the deployment, not in the
 * image: a deployment block that carries both of them with the profile is carried as a whole, so this protects against a
 * setting that slips in alone, not against copying the whole block (the gauge and the WARN make it visible). The relaxations are: signing keys named {@code test-*} (internal JWT and policy bundles),
 * a bootstrap of the registry from the manifest a server serves itself, tools from the configuration instead of an approved
 * manifest, plain http for the public URL, the IdP and the policy bundles, and no state directory for the rollback protection, and keys or cursor keys that are not shared (generated per process), and a private key of the public TLS port that every user of the host can read.
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
        // Keys that every instance must share: a random one per process breaks a second instance (tokens for the servers that the
        // other instance cannot sign for, cursors that the other instance refuses).
        if (blank(p.internalJwt().keysFile())) {
            used.add("gateway.internal-jwt.keys-file is empty (keys generated per process)");
        }
        if (blank(p.activity().cursorKey())) {
            used.add("gateway.activity.cursor-key is empty (a key per process)");
        }
        if (blank(p.mcp().listCursorKey())) {
            used.add("gateway.mcp.list-cursor-key is empty (a key per process)");
        }
        if (p.redis().waitReplicas() < 1) {
            used.add("gateway.redis.wait-replicas is 0 (a burned code is not confirmed by a replica)");
        }
        if (p.policy().stateDir() == null || p.policy().stateDir().isBlank()) {
            used.add("gateway.policy.state-dir is empty");
        }
        if (p.publicTls().enabled() && keyReadableByOthers(p.publicTls().privateKey())) {
            used.add("gateway.public-tls.private-key is readable by all users");
        }
        return used;
    }

    /**
     * Public TLS that cannot work: enabled without a certificate or key, or with files that are not there. Never a relaxation,
     * because the devstack profile does not make a missing file usable.
     */
    public static List<String> publicTlsProblems(GatewayProperties p) {
        List<String> problems = new ArrayList<>();
        GatewayProperties.PublicTls tls = p.publicTls();
        if (!tls.enabled()) {
            return problems;
        }
        requireFile(problems, "gateway.public-tls.certificate (MCP_PUBLIC_TLS_CERTIFICATE)", tls.certificate());
        requireFile(problems, "gateway.public-tls.private-key (MCP_PUBLIC_TLS_PRIVATE_KEY)", tls.privateKey());
        return problems;
    }

    private static void requireFile(List<String> problems, String setting, String file) {
        if (blank(file)) {
            problems.add("public TLS is enabled but " + setting + " is empty");
        } else if (!Files.isRegularFile(Path.of(PublicTlsEnvironment.path(file))) || !Files.isReadable(Path.of(PublicTlsEnvironment.path(file)))) {
            problems.add("public TLS is enabled but " + setting + " is not a readable file: " + file);
        }
    }

    /** Any permission bit for "others"; on a file system without POSIX permissions nothing can be judged and the key passes. */
    private static boolean keyReadableByOthers(String file) {
        if (blank(file)) {
            return false;
        }
        try {
            return Files.getPosixFilePermissions(Path.of(PublicTlsEnvironment.path(file))).stream().anyMatch(
                    permission -> permission == PosixFilePermission.OTHERS_READ || permission == PosixFilePermission.OTHERS_WRITE
                            || permission == PosixFilePermission.OTHERS_EXECUTE);
        } catch (IOException | UnsupportedOperationException e) {
            return false;
        }
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

    /**
     * Checks the configuration; throws with every problem at once, or warns when the profile is in force.
     *
     * @param processEnvironment the environment variables of the process (the acknowledgement variable is read from here only)
     */
    public static void enforce(GatewayProperties properties, Environment environment, Map<String, String> processEnvironment) {
        List<String> used = relaxations(properties);
        List<String> problems = problems(List.of(environment.getActiveProfiles()),
                "true".equalsIgnoreCase(environment.getProperty(ACK_PROPERTY, "")),
                "true".equalsIgnoreCase(processEnvironment.getOrDefault(ACK_ENVIRONMENT, "")), used);
        problems.addAll(publicTlsProblems(properties));
        if (!problems.isEmpty()) {
            throw new IllegalStateException("refusing to start: " + String.join("; ", problems));
        }
        if (devstackActive(environment)) {
            // The environment has no field in the manifest or the audit, so every start says it, and the gauge shows it.
            log.warn("event=devstack_profile detail=\"development relaxations are in force: {}; this gateway must not run in production\"",
                    used);
        }
    }

    /** The second line of defence, as a bean: the same check on the validated properties, before the beans that need it. */
    public static DevstackGuard check(GatewayProperties properties, Environment environment, Map<String, String> processEnvironment) {
        enforce(properties, environment, processEnvironment);
        return new DevstackGuard();
    }

    public static boolean devstackActive(Environment environment) {
        return List.of(environment.getActiveProfiles()).equals(List.of(PROFILE));
    }

    /** {@code mcp_gateway_devstack_active}: 1 when the devstack profile is in force. */
    public static void bindMetric(Environment environment, MeterRegistry meters) {
        boolean devstack = devstackActive(environment);
        Gauge.builder("mcp_gateway_devstack_active", () -> devstack ? 1 : 0)
                .description("1 when the gateway runs with the devstack profile").register(meters);
    }

    private static boolean https(URI uri) {
        return uri != null && "https".equals(uri.getScheme());
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
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
