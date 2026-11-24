package pl.aiwcorpo.mcp.gateway.registry;

/**
 * The kinds of manifest entry that C6 has next to tools since 8.0.0 (CC-258). {@code column} is the value of {@code registry_primitives.kind}
 * and {@code field} the array of the manifest that holds the entries.
 */
public enum PrimitiveKind {
    RESOURCE("resource", "resources", "resources"),
    RESOURCE_TEMPLATE("resource_template", "resourceTemplates", "resource-templates"),
    PROMPT("prompt", "prompts", "prompts");

    private final String column;
    private final String field;
    private final String path;

    PrimitiveKind(String column, String field, String path) {
        this.column = column;
        this.field = field;
        this.path = path;
    }

    public String column() {
        return column;
    }

    public String field() {
        return field;
    }

    /** The segment of the admin path ({@code /servers/{serverId}/resource-templates/{name}/pending}). */
    public String path() {
        return path;
    }

    public static PrimitiveKind ofColumn(String column) {
        for (PrimitiveKind kind : values()) {
            if (kind.column.equals(column)) {
                return kind;
            }
        }
        throw new IllegalArgumentException("unknown kind of registry entry: " + column);
    }
}
