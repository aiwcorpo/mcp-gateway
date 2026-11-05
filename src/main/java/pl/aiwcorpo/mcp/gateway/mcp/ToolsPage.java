package pl.aiwcorpo.mcp.gateway.mcp;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

/**
 * One page of the {@code tools/list} of the aggregate endpoint (CC-181): the list is sorted by system (by {@code ServerId}) and
 * then by tool name, bytewise, and a cursor names the last tool of the previous page, so that a tool added or removed between two
 * requests neither repeats nor skips a tool that stays. The page size is fixed by the contract.
 */
public final class ToolsPage {

    public static final int SIZE = 100;

    private static final Comparator<String> BYTEWISE = Comparator.naturalOrder();

    private ToolsPage() {
    }

    /** One tool of the list: {@code name} is {@code <system>__<tool>}. */
    public record Entry<T>(String name, T value) {
    }

    /** {@code nextAfter} is the name of the last tool of the page when more follow, else empty. */
    public record Page<T>(List<Entry<T>> entries, Optional<String> nextAfter) {
    }

    /** Position of a tool: its server id and then its name, so that system {@code a} comes before {@code a1} whatever the names say. */
    static String key(String qualifiedName) {
        int separator = qualifiedName.indexOf("__");
        return "mcp-" + (separator < 0 ? qualifiedName : qualifiedName.substring(0, separator)) + "\u0000" + qualifiedName;
    }

    public static <T> List<Entry<T>> sorted(List<Entry<T>> entries) {
        List<Entry<T>> copy = new ArrayList<>(entries);
        copy.sort(Comparator.comparing(entry -> key(entry.name()), BYTEWISE));
        return copy;
    }

    public static <T> Page<T> of(List<Entry<T>> entries, String afterName, int pageSize) {
        List<Entry<T>> sorted = sorted(entries);
        List<Entry<T>> rest = afterName == null ? sorted : sorted.stream()
                .filter(entry -> BYTEWISE.compare(key(entry.name()), key(afterName)) > 0).toList();
        List<Entry<T>> page = rest.stream().limit(pageSize).toList();
        Optional<String> next = rest.size() > pageSize ? Optional.of(page.getLast().name()) : Optional.empty();
        return new Page<>(page, next);
    }
}
