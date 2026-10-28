package pl.aiwcorpo.mcp.gateway.virtual;

import java.time.Instant;
import java.util.List;
import java.util.regex.Pattern;

/** A link (C5): a named subset of tools, usable only by its owner and never wider than the owner's rights. */
public record VirtualServer(String slug, String ownerSub, String displayName, List<String> tools, Instant createdAt) {

    /** {@code VirtualServerSlug} of common.schema.json; matched against the whole string. */
    public static final Pattern SLUG = Pattern.compile("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$");

    public static boolean validSlug(String value) {
        return value != null && SLUG.matcher(value).matches();
    }

    public boolean allows(String qualifiedToolName) {
        return tools.contains(qualifiedToolName);
    }
}
