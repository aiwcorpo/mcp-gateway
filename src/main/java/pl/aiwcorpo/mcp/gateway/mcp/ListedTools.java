package pl.aiwcorpo.mcp.gateway.mcp;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Which tools a {@code tools/list} of the aggregate endpoint shows (CC-169): those that are approved, enabled, served by their server
 * with the approved definition and allowed by Cedar at the level of the tool, of the servers that are available for this list;
 * ordered by system (by {@code ServerId}) and then by tool name, bytewise. The connection of the user's account takes no part: a system
 * without a connection keeps its tools, the call answers {@code credential_required}.
 */
public final class ListedTools {

    private ListedTools() {
    }

    /** One tool as the checks see it; {@code risk} is the approved one. */
    public record Candidate(String name, String risk, boolean approved, boolean enabled, boolean served, boolean definitionMatches,
                            boolean allowedByPolicy) {
    }

    public record ServerTools(String serverId, boolean available, List<Candidate> tools) {
    }

    public record Listed(String name, String risk) {
    }

    public static boolean listed(Candidate tool) {
        return tool.approved() && tool.enabled() && tool.served() && tool.definitionMatches() && tool.allowedByPolicy();
    }

    public static List<Listed> visible(List<ServerTools> servers) {
        List<Listed> out = new ArrayList<>();
        servers.stream().sorted(Comparator.comparing(ServerTools::serverId)).filter(ServerTools::available).forEach(server ->
                server.tools().stream().filter(ListedTools::listed).sorted(Comparator.comparing(Candidate::name))
                        .forEach(tool -> out.add(new Listed(tool.name(), tool.risk()))));
        return out;
    }
}
