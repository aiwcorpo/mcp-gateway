package pl.aiwcorpo.mcp.gateway.registry;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import pl.aiwcorpo.mcp.cedar.entities.ResourceTypes;
import pl.aiwcorpo.mcp.cedar.entities.ScopeMapping;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * Takes the scopes of the types of some namespaces out of the scope mapping: when a server is deleted, and when an approval changes or frees
 * a namespace, so that whoever takes the namespace next does not inherit grants given for the old owner; and the scopes an approval makes
 * invalid (CC-252). A group that has no scope left because of it leaves the document.
 */
final class MappingCleanup {

    /** One scope that was taken out, with the group that had it; {@code scope} is {@code <Type>/<local>}. */
    record Removed(String group, String scope) {
        String type() {
            return scope.substring(0, scope.indexOf('/'));
        }

        String local() {
            return scope.substring(scope.indexOf('/') + 1);
        }
    }

    record Result(ArrayNode mapping, List<Removed> removed) {
    }

    private MappingCleanup() {
    }

    /**
     * Takes out the scopes of {@code namespace} that the approved declarations {@code types} no longer accept ({@code undeclared_type},
     * {@code invalid_scope}), with the reason of each (CC-252). Scopes of other namespaces stay whatever {@code types} says of them.
     */
    static Invalid stripInvalid(JsonMapper json, JsonNode mapping, String namespace, ResourceTypes types) {
        String prefix = namespace + "::";
        List<ScopeMapping.Ignored> invalid = ScopeMapping.fromJson(types, json.writeValueAsString(mapping), true).ignored().stream()
                .filter(entry -> entry.scope().startsWith(prefix))
                .filter(entry -> "undeclared_type".equals(entry.reason()) || "invalid_scope".equals(entry.reason()))
                .toList();
        Set<Removed> drop = new java.util.HashSet<>();
        invalid.forEach(entry -> drop.add(new Removed(entry.group(), entry.scope())));
        List<Removed> removed = new ArrayList<>();
        ArrayNode kept = json.createArrayNode();
        for (JsonNode entry : mapping) {
            String group = entry.path("group").asString();
            ArrayNode scopes = json.createArrayNode();
            boolean touched = false;
            for (JsonNode scope : entry.path("scopes")) {
                Removed candidate = new Removed(group, scope.asString());
                if (drop.contains(candidate)) {
                    touched = true;
                    removed.add(candidate);
                } else {
                    scopes.add(scope);
                }
            }
            if (!touched) {
                kept.add(entry);
            } else if (!scopes.isEmpty()) {
                ObjectNode rewritten = json.createObjectNode();
                rewritten.put("group", group);
                rewritten.set("scopes", scopes);
                kept.add(rewritten);
            }
        }
        return new Invalid(new Result(kept, removed), invalid);
    }

    record Invalid(Result result, List<ScopeMapping.Ignored> entries) {
    }

    static Result strip(JsonMapper json, JsonNode mapping, Set<String> namespaces) {
        List<String> prefixes = namespaces.stream().map(namespace -> namespace + "::").toList();
        List<Removed> removed = new ArrayList<>();
        ArrayNode kept = json.createArrayNode();
        for (JsonNode entry : mapping) {
            ArrayNode scopes = json.createArrayNode();
            boolean touched = false;
            for (JsonNode scope : entry.path("scopes")) {
                String id = scope.asString();
                if (prefixes.stream().anyMatch(id::startsWith)) {
                    touched = true;
                    removed.add(new Removed(entry.path("group").asString(), id));
                } else {
                    scopes.add(scope);
                }
            }
            if (!touched) {
                kept.add(entry);
            } else if (!scopes.isEmpty()) {
                ObjectNode rewritten = json.createObjectNode();
                rewritten.put("group", entry.path("group").asString());
                rewritten.set("scopes", scopes);
                kept.add(rewritten);
            }
        }
        return new Result(kept, removed);
    }
}
