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

import pl.aiwcorpo.mcp.cedar.entities.PolicyFragments;
import pl.aiwcorpo.mcp.cedar.entities.ResourceTypes;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.manifest.ManifestRules;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * What the gateway checks before it takes a manifest (C5 registerServer, C6): the JSON Schema (a title in every definition, a
 * closed and bounded inputSchema), the semantic rules of {@code mcp-manifest} (names, resource references, the hash recomputed
 * from the definition, the resource type declarations and the hash of the policies), the policy fragment of the server composed with
 * the base schema (PolicyFragments), the binding of the server to its entry in the registry of servers (serverId, system, address),
 * the environment the server was built for (CC-138) and the credential types the gateway asks the broker for (CC-159).
 */
public final class ManifestValidator {

    private static final Schema SCHEMA = SchemaRegistry.withDefaultDialect(SpecificationVersion.DRAFT_2020_12)
            .getSchema(SchemaLocation.of("classpath:mcp-contracts/schemas/server-manifest.schema.json"));

    public static final String ENVIRONMENT_MISMATCH = "environment_mismatch";
    public static final String CREDENTIAL_TYPE_MISMATCH = "credential_type_mismatch";
    public static final String POLICIES_INVALID = "policies_invalid";
    public static final String RESOURCE_TYPES_INVALID = "resource_types_invalid";
    public static final String NAMESPACE_CONFLICT = "namespace_conflict";

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
        ManifestRules.violations(json.writeValueAsString(manifest)).forEach(rule -> out.add(new Rejection(reasonOf(rule), rule)));
        if (out.isEmpty() && manifest.has("policies")) {
            out.addAll(fragmentErrors(manifest));
        }
        if (!configured.serverId().equals(manifest.path("serverId").asString())) {
            out.add(new Rejection(null, "serverId does not match the registry of servers"));
        }
        if (!configured.system().equals(manifest.path("system").asString())) {
            out.add(new Rejection(null, "system does not match the registry of servers"));
        }
        if (!addressMatches(manifest.path("internalUrl").asString(), configured)) {
            out.add(new Rejection(null, "internalUrl does not match the registry of servers"));
        }
        if ("dev".equals(manifest.path("environment").asString("production")) && !devMode) {
            out.add(new Rejection(ENVIRONMENT_MISMATCH, "the manifest of " + configured.serverId() + " declares environment dev"));
        }
        credentialMismatch(manifest, configured).ifPresent(out::add);
        return out;
    }

    /**
     * The hash of the policies and resource types of a manifest, recomputed from them; empty when the manifest has none or claims another
     * hash. This is what is compared with the approved hash (a hash the manifest merely names would prove nothing).
     */
    public Optional<String> policiesHashOf(JsonNode manifest) {
        if (!manifest.has("policies") || !manifest.has("resourceTypes") || !manifest.path("policiesHash").isString()) {
            return Optional.empty();
        }
        try {
            String computed = pl.aiwcorpo.mcp.manifest.PoliciesHash.of(json.writeValueAsString(manifest.get("policies")),
                    json.writeValueAsString(manifest.get("resourceTypes")));
            return computed.equals(manifest.get("policiesHash").asString()) ? Optional.of(computed) : Optional.empty();
        } catch (RuntimeException e) {
            return Optional.empty();
        }
    }

    /** Whether the fragment and the declarations of a manifest compose with the base schema and validate (C7); empty when they do. */
    public List<Rejection> policiesProblems(JsonNode manifest) {
        return manifest.has("policies") ? fragmentErrors(manifest) : List.of(new Rejection(POLICIES_INVALID, "no policies"));
    }

    private static String reasonOf(String rule) {
        return switch (rule) {
            case "credential-types-not-mixed" -> CREDENTIAL_TYPE_MISMATCH;
            case ManifestRules.RESOURCE_TYPES_VALID, ManifestRules.RESOURCE_TYPES_NAMESPACE, ManifestRules.RESOURCE_TYPES_DECLARED -> RESOURCE_TYPES_INVALID;
            case ManifestRules.POLICIES_HASH_MATCHES, ManifestRules.POLICIES_FILES_SORTED_UNIQUE -> POLICIES_INVALID;
            default -> null;
        };
    }

    /** The fragment and the declarations compose with the base schema in strict mode (C6, C7); the cause stays in the log, not in the answer. */
    private List<Rejection> fragmentErrors(JsonNode manifest) {
        JsonNode policies = manifest.path("policies");
        try {
            ResourceTypes types = ResourceTypes.fromJson(json.writeValueAsString(manifest.path("resourceTypes")));
            java.util.Map<String, String> files = new java.util.LinkedHashMap<>();
            policies.path("files").forEach(file -> files.put(file.path("name").asString(), file.path("text").asString()));
            PolicyFragments.Result result = PolicyFragments.validateFragment(policies.path("namespace").asString(),
                    policies.path("schema").asString(), files, types);
            if (!result.ok()) {
                return List.of(new Rejection(POLICIES_INVALID, "policies: " + String.join("; ", result.errors())));
            }
            return List.of();
        } catch (IllegalArgumentException e) {
            return List.of(new Rejection(RESOURCE_TYPES_INVALID, "resourceTypes: " + e.getMessage()));
        }
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
