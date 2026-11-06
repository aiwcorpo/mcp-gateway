package pl.aiwcorpo.mcp.gateway.support;

import java.util.List;

import pl.aiwcorpo.mcp.manifest.DefinitionHash;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/** Manifests of mcp-jira (C6) with correct hashes, built for the tests of the registry. */
public final class Manifests {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    public static final String USER_SECRET = "user-secret";

    /** A tool of a test manifest; {@code description} is the text a change of the definition is made with. */
    public record Tool(String name, String risk, String description) {
        public static Tool readOnly(String name) {
            return new Tool(name, "READ_ONLY", "Reads " + name + ".");
        }

        public static Tool update(String name) {
            return new Tool(name, "UPDATE", "Changes " + name + ".");
        }

        public static Tool destructive(String name) {
            return new Tool(name, "DESTRUCTIVE", "Deletes " + name + ".");
        }

        public Tool described(String text) {
            return new Tool(name, risk, text);
        }

        public Tool withRisk(String next) {
            return new Tool(name, next, description);
        }
    }

    private Manifests() {
    }

    public static ObjectNode jira(String version, Tool... tools) {
        return manifest("mcp-jira", "jira", version, List.of(USER_SECRET), tools);
    }

    public static ObjectNode manifest(String serverId, String system, String version, List<String> credentialTypes, Tool... tools) {
        ObjectNode manifest = JSON.createObjectNode();
        manifest.put("serverId", serverId);
        manifest.put("version", version);
        manifest.put("system", system);
        manifest.put("internalUrl", "https://" + serverId + ".internal:8443/mcp");
        ObjectNode credential = manifest.putObject("credential");
        credential.put("required", true);
        ArrayNode types = credential.putArray("acceptedTypes");
        credentialTypes.forEach(types::add);
        Fragments.apply(manifest, system);
        ArrayNode list = manifest.putArray("tools");
        for (Tool tool : tools) {
            ObjectNode entry = list.addObject();
            entry.put("name", tool.name());
            entry.put("risk", tool.risk());
            entry.put("action", switch (tool.risk()) {
                case "READ_ONLY" -> "read";
                case "UPDATE" -> "update";
                default -> "delete";
            });
            entry.putArray("resourceRefs");
            entry.set("definition", definition(tool));
            entry.put("definitionHash", DefinitionHash.compute(JSON.writeValueAsString(entry.get("definition")),
                    JSON.writeValueAsString(entry), system, JSON.writeValueAsString(credential)));
        }
        return manifest;
    }

    /**
     * The manifest an adapter submits (C6, CC-193): {@code source: adapter}, no risk and no action in the entries, no resource references.
     * The risk of a {@link Tool} is only what the foreign tool looks like; it is not written.
     */
    public static ObjectNode adapter(String serverId, String system, String version, Tool... tools) {
        ObjectNode manifest = JSON.createObjectNode();
        manifest.put("serverId", serverId);
        manifest.put("version", version);
        manifest.put("system", system);
        manifest.put("source", "adapter");
        manifest.put("internalUrl", "https://" + serverId + ".internal:8443/mcp");
        ObjectNode credential = manifest.putObject("credential");
        credential.put("required", true);
        credential.putArray("acceptedTypes").add(USER_SECRET);
        manifest.putArray("resourceTypes");
        ArrayNode list = manifest.putArray("tools");
        for (Tool tool : tools) {
            ObjectNode entry = list.addObject();
            entry.put("name", tool.name());
            entry.putArray("resourceRefs");
            entry.set("definition", definition(tool));
            entry.put("definitionHash", DefinitionHash.compute(JSON.writeValueAsString(entry.get("definition")),
                    JSON.writeValueAsString(entry), system, JSON.writeValueAsString(credential)));
        }
        return manifest;
    }

    public static ObjectNode definition(Tool tool) {
        ObjectNode definition = JSON.createObjectNode();
        definition.put("name", tool.name());
        definition.put("title", tool.name());
        definition.put("description", tool.description());
        ObjectNode schema = definition.putObject("inputSchema");
        schema.put("type", "object");
        schema.putObject("properties").putObject("key").put("type", "string").put("maxLength", 32);
        schema.putArray("required").add("key");
        schema.put("additionalProperties", false);
        definition.putObject("annotations").put("readOnlyHint", "READ_ONLY".equals(tool.risk()));
        return definition;
    }

    /** The hash a manifest tool entry must declare after the test changed its definition or risk. */
    public static void rehash(ObjectNode manifest, String tool) {
        for (JsonNode entry : manifest.path("tools")) {
            if (tool.equals(entry.path("name").asString())) {
                ((ObjectNode) entry).put("definitionHash", DefinitionHash.ofManifestTool(JSON.writeValueAsString(manifest), tool));
            }
        }
    }

    public static ObjectNode tool(ObjectNode manifest, String name) {
        for (JsonNode entry : manifest.path("tools")) {
            if (name.equals(entry.path("name").asString())) {
                return (ObjectNode) entry;
            }
        }
        throw new AssertionError("no tool " + name);
    }
}
