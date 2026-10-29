package pl.aiwcorpo.mcp.gateway.registry;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import com.networknt.schema.Schema;
import com.networknt.schema.SchemaLocation;
import com.networknt.schema.SchemaRegistry;
import com.networknt.schema.SpecificationVersion;

import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.manifest.ManifestRules;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * What the gateway checks before it takes a manifest (C5 registerServer, C6): the JSON Schema (a title in every definition, a
 * closed and bounded inputSchema), the semantic rules of {@code mcp-manifest} (names, resource references, the hash recomputed
 * from the definition), the binding of the server to the gateway's own configuration (serverId, system, address), the
 * environment the server was built for (CC-138) and the credential types the gateway asks the broker for (CC-159).
 */
public final class ManifestValidator {

    private static final Schema SCHEMA = SchemaRegistry.withDefaultDialect(SpecificationVersion.DRAFT_2020_12)
            .getSchema(SchemaLocation.of("classpath:mcp-contracts/schemas/server-manifest.schema.json"));

    public static final String ENVIRONMENT_MISMATCH = "environment_mismatch";
    public static final String CREDENTIAL_TYPE_MISMATCH = "credential_type_mismatch";

    /** A refusal; {@code reason} is a value of {@code ManifestRejected.reason} or null for the older kinds (schema, rule, binding). */
    public record Rejection(String reason, String message) {
    }

    private final JsonMapper json;
    private final boolean devMode;

    /** @param devMode the devstack profile is in force: a manifest of environment dev is accepted only then */
    public ManifestValidator(JsonMapper json, boolean devMode) {
        this.json = json;
        this.devMode = devMode;
    }

    /** Why the manifest is refused for {@code configured}; empty when it is acceptable. Never quotes manifest values. */
    public List<Rejection> check(JsonNode manifest, McpServer configured) {
        List<Rejection> out = new ArrayList<>();
        if (!SCHEMA.validate(manifest).isEmpty()) {
            out.add(new Rejection(null, "schema"));
            return out;
        }
        ManifestRules.violations(json.writeValueAsString(manifest)).forEach(rule -> out.add(new Rejection(
                "credential-types-not-mixed".equals(rule) ? CREDENTIAL_TYPE_MISMATCH : null, rule)));
        if (!configured.serverId().equals(manifest.path("serverId").asString())) {
            out.add(new Rejection(null, "serverId does not match the gateway configuration"));
        }
        if (!configured.system().equals(manifest.path("system").asString())) {
            out.add(new Rejection(null, "system does not match the gateway configuration"));
        }
        if (!addressMatches(manifest.path("internalUrl").asString(), configured)) {
            out.add(new Rejection(null, "internalUrl does not match the gateway configuration"));
        }
        if ("dev".equals(manifest.path("environment").asString("production")) && !devMode) {
            out.add(new Rejection(ENVIRONMENT_MISMATCH, "the manifest of " + configured.serverId() + " declares environment dev"));
        }
        credentialMismatch(manifest, configured).ifPresent(out::add);
        return out;
    }

    /**
     * Every credential type the configuration allows for the system must be one the server's manifest accepts, or a credential the
     * broker may return would be refused by the server (CC-159 as amended by CC-166). A system that needs no credential is not checked.
     */
    private static Optional<Rejection> credentialMismatch(JsonNode manifest, McpServer configured) {
        Set<String> asked = new java.util.TreeSet<>(configured.credential().acceptedTypes());
        if (!configured.credential().required() || asked.isEmpty()) {
            return Optional.empty();
        }
        JsonNode credential = manifest.path("credential");
        Set<String> accepted = new java.util.TreeSet<>();
        credential.path("acceptedTypes").forEach(type -> accepted.add(type.asString()));
        if (credential.path("required").asBoolean(false) && accepted.containsAll(asked)) {
            return Optional.empty();
        }
        return Optional.of(new Rejection(CREDENTIAL_TYPE_MISMATCH, "the gateway allows " + String.join(", ", asked) + " for "
                + configured.system() + ", the manifest accepts " + (accepted.isEmpty() ? "none" : String.join(", ", accepted))));
    }

    /** The manifest names the server by the configured address or by the TLS name the gateway checks, on the configured port. */
    static boolean addressMatches(String manifestUrl, McpServer configured) {
        try {
            URI declared = URI.create(manifestUrl);
            URI actual = configured.internalUrl();
            boolean hostOk = declared.getHost() != null
                    && (declared.getHost().equalsIgnoreCase(actual.getHost()) || declared.getHost().equalsIgnoreCase(configured.tlsName()));
            return hostOk && port(declared) == port(actual);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static int port(URI uri) {
        return uri.getPort() == -1 ? 443 : uri.getPort();
    }

    /** The credential object of a manifest as it enters every hash of its tools; an absent object is JSON null. */
    public String credentialJson(JsonNode manifest) {
        return manifest.has("credential") ? json.writeValueAsString(manifest.get("credential")) : "null";
    }
}
