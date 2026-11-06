package pl.aiwcorpo.mcp.gateway.registry;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * Takes the scopes of the types of some namespaces out of the scope mapping: when a server is deleted, and when an approval changes or frees
 * a namespace, so that whoever takes the namespace next does not inherit grants given for the old owner. A group that has no scope left
 * because of it leaves the document.
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
