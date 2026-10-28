package pl.aiwcorpo.mcp.gateway.registry;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import com.networknt.schema.Schema;
import com.networknt.schema.SchemaLocation;
import com.networknt.schema.SchemaRegistry;
import com.networknt.schema.SpecificationVersion;

import pl.aiwcorpo.mcp.cedar.entities.ResourceRef;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.manifest.ManifestRules;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * What the gateway checks before it takes a manifest (C5 registerServer, C6): the JSON Schema (a title in every definition, a
 * closed and bounded inputSchema), the semantic rules of {@code mcp-manifest} (names, resource references, the hash recomputed
 * from the definition) and the binding of the server to the gateway's own configuration (serverId, system, address).
 */
public final class ManifestValidator {

    private static final Schema SCHEMA = SchemaRegistry.withDefaultDialect(SpecificationVersion.DRAFT_2020_12)
            .getSchema(SchemaLocation.of("classpath:mcp-contracts/schemas/server-manifest.schema.json"));

    private final JsonMapper json;

    public ManifestValidator(JsonMapper json) {
        this.json = json;
    }

    /** Reasons the manifest is refused; empty when it is acceptable for {@code configured}. Never quotes manifest values. */
    public List<String> violations(JsonNode manifest, McpServer configured) {
        List<String> out = new ArrayList<>();
        if (!SCHEMA.validate(manifest).isEmpty()) {
            out.add("schema");
            return out;
        }
        out.addAll(ManifestRules.violations(json.writeValueAsString(manifest)));
        if (!configured.serverId().equals(manifest.path("serverId").asString())) {
            out.add("serverId does not match the gateway configuration");
        }
        if (!configured.system().equals(manifest.path("system").asString())) {
            out.add("system does not match the gateway configuration");
        }
        if (!addressMatches(manifest.path("internalUrl").asString(), configured)) {
            out.add("internalUrl does not match the gateway configuration");
        }
        return out;
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

    /** The approved view of an accepted manifest. */
    public ApprovedServer approved(JsonNode manifest) {
        java.util.Map<String, ApprovedTool> tools = new java.util.LinkedHashMap<>();
        for (JsonNode tool : manifest.path("tools")) {
            List<ResourceRef> refs = new ArrayList<>();
            tool.path("resourceRefs").forEach(ref -> refs.add(new ResourceRef(ref.path("argument").asString(), ref.path("type").asString())));
            JsonNode definition = tool.path("definition");
            String name = tool.path("name").asString();
            tools.put(name, new ApprovedTool(name, tool.path("risk").asString(), tool.path("action").asString(), List.copyOf(refs),
                    definition.path("title").asString(null), definition.path("description").asString(""), definition,
                    tool.path("definitionHash").asString(), tool));
        }
        return new ApprovedServer(manifest.path("serverId").asString(), manifest.path("system").asString(),
                manifest.path("version").asString(), json.writeValueAsString(manifest.path("credential")), java.util.Map.copyOf(tools), manifest);
    }
}
