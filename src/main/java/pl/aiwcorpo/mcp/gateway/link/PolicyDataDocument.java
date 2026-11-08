package pl.aiwcorpo.mcp.gateway.link;

import pl.aiwcorpo.mcp.gateway.policy.PolicyService;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * The body of {@code POST /.well-known/mcp-policy-data} (C14 {@code PolicyData}): the revision, the hash of the policies approved for the
 * server, the scope mapping reduced to the namespace of the server, the allowed clients and the overrides aimed at the server or at all servers.
 */
public final class PolicyDataDocument {

    private PolicyDataDocument() {
    }

    public static ObjectNode of(JsonMapper json, PolicyService.ServerData data) {
        ObjectNode body = json.createObjectNode();
        body.put("revision", data.revision());
        if (data.approvedPoliciesHash() != null) {
            body.put("approvedPoliciesHash", data.approvedPoliciesHash());
        }
        ArrayNode mapping = body.putArray("scopeMapping");
        data.scopeMapping().asMap().forEach((group, scopes) -> {
            ObjectNode entry = mapping.addObject();
            entry.put("group", group);
            ArrayNode list = entry.putArray("scopes");
            scopes.forEach(list::add);
        });
        ArrayNode clients = body.putArray("allowedClients");
        data.allowedClients().forEach(clients::add);
        ArrayNode overrides = body.putArray("overrides");
        data.overrides().forEach(override -> overrides.addObject().put("id", override.id()).put("text", override.text()));
        return body;
    }
}
