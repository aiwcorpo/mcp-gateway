package pl.aiwcorpo.mcp.gateway.admin;

import java.time.temporal.ChronoUnit;

import pl.aiwcorpo.mcp.gateway.registry.RegisteredServer;
import pl.aiwcorpo.mcp.gateway.registry.RegisteredTool;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/** The registry as C5 shows it: {@code RegistryServer} to the portal, {@code AdapterRegistryServer} to an adapter (CC-207). */
public final class RegistryViews {

    private RegistryViews() {
    }

    /**
     * One row per tool. A tool with a pending entry shows that entry (status pending_approval, with the change and its source); the
     * definition in force is available through the pending endpoint for the diff. An adapter does not see who classified a tool and when:
     * that is the identity of administrators and none of its business.
     */
    public static ObjectNode server(JsonMapper json, RegisteredServer server, boolean forAdapter) {
        ObjectNode view = json.createObjectNode();
        view.put("serverId", server.serverId());
        view.put("system", server.system());
        view.put("version", server.version());
        ArrayNode tools = view.putArray("tools");
        server.tools().values().forEach(tool -> {
            RegisteredTool.Approved approved = tool.approved();
            RegisteredTool.Pending pending = tool.pending();
            ObjectNode entry = ((ObjectNode) (pending != null ? pending.entry() : approved.entry())).deepCopy();
            if (pending != null) {
                entry.put("status", "pending_approval");
                entry.put("change", pending.change());
                entry.put("source", pending.source());
                if (pending.riskLowered()) {
                    entry.put("riskLowered", true);
                }
            } else {
                entry.put("status", "approved");
                if (!forAdapter && approved.classifiedBy() != null) {
                    entry.put("classifiedBy", approved.classifiedBy());
                    entry.put("classifiedAt", approved.classifiedAt().truncatedTo(ChronoUnit.SECONDS).toString());
                }
            }
            if (approved != null) {
                entry.put("approvedInVersion", approved.version());
            } else {
                entry.putNull("approvedInVersion");
            }
            tools.add(entry);
        });
        return view;
    }
}
