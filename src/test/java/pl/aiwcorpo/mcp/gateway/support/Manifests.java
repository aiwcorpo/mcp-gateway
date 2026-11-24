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

    /**
     * Resources, templates and prompts of a test manifest (CC-258), with the hash of their kind. Each call replaces the entry of that name,
     * so a test changes one by calling it again with another text. The scheme of the URI is the system, as the manifest rules want.
     */
    public static ObjectNode addResource(ObjectNode manifest, String name, String description) {
        ObjectNode definition = JSON.createObjectNode();
        definition.put("name", name);
        definition.put("title", name);
        definition.put("description", description);
        boolean adapter = "adapter".equals(manifest.path("source").asString(null));
        definition.put("uri", manifest.path("system").asString() + (adapter ? "+file:///docs/" : "://docs/") + name);
        definition.put("mimeType", "text/markdown");
        return put(manifest, "resources", "resource", name, definition, null);
    }

    /** A template with one variable of the type {@code <System>::Project} that {@link Fragments} declares. */
    public static ObjectNode addProjectTemplate(ObjectNode manifest, String name, String description) {
        String system = manifest.path("system").asString();
        ObjectNode definition = JSON.createObjectNode();
        definition.put("name", name);
        definition.put("title", name);
        definition.put("description", description);
        definition.put("uriTemplate", system + "://projects/{project}");
        ObjectNode extra = JSON.createObjectNode();
        extra.putArray("variables").addObject().put("name", "project").put("type", Fragments.namespace(system) + "::Project");
        return put(manifest, "resourceTemplates", "resourceTemplate", name, definition, extra);
    }

    /** A template of an adapter: no resource types, so the variable carries its own bound and pattern. */
    public static ObjectNode addAdapterTemplate(ObjectNode manifest, String name, String description) {
        String system = manifest.path("system").asString();
        ObjectNode definition = JSON.createObjectNode();
        definition.put("name", name);
        definition.put("title", name);
        definition.put("description", description);
        definition.put("uriTemplate", system + "+file:///issues/{issueKey}");
        ObjectNode extra = JSON.createObjectNode();
        extra.putArray("variables").addObject().put("name", "issueKey").put("maxLength", 32).put("pattern", "^[A-Z][A-Z0-9]+-[0-9]+$");
        return put(manifest, "resourceTemplates", "resourceTemplate", name, definition, extra);
    }

    public static ObjectNode addPrompt(ObjectNode manifest, String name, String messageText) {
        ObjectNode definition = JSON.createObjectNode();
        definition.put("name", name);
        definition.put("title", name);
        definition.put("description", "Prompt " + name + ".");
        definition.putArray("arguments").addObject().put("name", "ticketId").put("required", true);
        ObjectNode extra = JSON.createObjectNode();
        extra.putArray("argumentRules").addObject().put("name", "ticketId").put("maxLength", 32).put("pattern", "^[A-Z]{2,8}-[0-9]{1,6}$");
        extra.putArray("messages").addObject().put("role", "user").put("text", messageText + " <ticket_id>{{ticketId}}</ticket_id>");
        return put(manifest, "prompts", "prompt", name, definition, extra);
    }

    private static ObjectNode put(ObjectNode manifest, String field, String kind, String name, ObjectNode definition, ObjectNode extra) {
        ObjectNode entry = JSON.createObjectNode();
        entry.put("name", name);
        entry.set("definition", definition);
        if (extra != null) {
            extra.properties().forEach(member -> entry.set(member.getKey(), member.getValue()));
        }
        entry.put("definitionHash", DefinitionHash.computePrimitive(kind, JSON.writeValueAsString(definition), JSON.writeValueAsString(entry),
                manifest.path("system").asString(), JSON.writeValueAsString(manifest.path("credential"))));
        ArrayNode list = manifest.has(field) ? (ArrayNode) manifest.get(field) : manifest.putArray(field);
        for (int i = list.size() - 1; i >= 0; i--) {
            if (name.equals(list.get(i).path("name").asString())) {
                list.remove(i);
            }
        }
        list.add(entry);
        return manifest;
    }

    public static String entryHash(ObjectNode manifest, String field, String name) {
        for (JsonNode entry : manifest.path(field)) {
            if (name.equals(entry.path("name").asString())) {
                return entry.path("definitionHash").asString();
            }
        }
        throw new AssertionError("no " + field + " entry " + name);
    }
}
