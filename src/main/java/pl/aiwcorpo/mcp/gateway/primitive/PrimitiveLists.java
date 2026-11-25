package pl.aiwcorpo.mcp.gateway.primitive;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import pl.aiwcorpo.mcp.manifest.EndpointFilter;

/**
 * Which entries a {@code resources/list}, {@code resources/templates/list} or {@code prompts/list} shows (CC-259). A server that is not
 * served (pending approval, connection or policies not approved, disabled, a switch on it) shows nothing. Resources and templates follow the
 * server like tools: one that does not answer is skipped whole, and a definition that differs from the approved one hides its entry.
 * Prompts are composed from the manifest, so an unreachable server does not hide them and there is no definition to compare. An entry is
 * shown when it is approved, enabled and Cedar allows it for the caller. The order is system by {@code ServerId}, then the name, bytewise.
 */
public final class PrimitiveLists {

    private PrimitiveLists() {
    }

    public enum Kind { RESOURCES, TEMPLATES, PROMPTS }

    /** One entry as the checks see it. */
    public record Entry(String name, boolean approved, boolean enabled, boolean definitionMatches, boolean allowedByPolicy) {
    }

    /** {@code served}: the state of the server lets its entries be shown; {@code available}: it answered the reading of its lists. */
    public record ServerEntries(String serverId, String system, boolean served, boolean available, List<Entry> entries) {
    }

    public record Listed(String system, String name) {

        public String qualifiedName() {
            return system + "__" + name;
        }
    }

    public static List<Listed> visible(Kind kind, List<ServerEntries> servers) {
        List<Listed> out = new ArrayList<>();
        servers.stream().sorted(Comparator.comparing(ServerEntries::serverId)).forEach(server -> {
            if (!server.served() || kind != Kind.PROMPTS && !server.available()) {
                return;
            }
            server.entries().stream()
                    .filter(e -> e.approved() && e.enabled() && (kind == Kind.PROMPTS || e.definitionMatches()) && e.allowedByPolicy())
                    .sorted(Comparator.comparing(Entry::name))
                    .forEach(e -> out.add(new Listed(server.system(), e.name())));
        });
        return out;
    }

    /**
     * What the address leaves of the entries of a system: {@code tools} narrows and adds nothing, so it hides every one of them;
     * {@code systems} and a system entry of {@code exclude} apply; {@code access=write} hides them (they are read only), {@code access=read}
     * keeps them; a tool entry of {@code exclude} does not concern them.
     */
    public static boolean throughFilter(EndpointFilter filter, String system) {
        if (filter.tools().isPresent()) {
            return false;
        }
        if (filter.systems().isPresent() && !filter.systems().get().contains(system)) {
            return false;
        }
        if (filter.access().filter(access -> access == EndpointFilter.Access.WRITE).isPresent()) {
            return false;
        }
        return filter.exclude().map(excluded -> !excluded.contains(system)).orElse(true);
    }
}
