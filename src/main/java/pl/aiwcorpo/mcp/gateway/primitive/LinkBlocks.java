package pl.aiwcorpo.mcp.gateway.primitive;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;

/**
 * The blocks of a {@code tools/call} or {@code resources/read} result that point at a URI (CC-259): a {@code resource_link} or an embedded
 * resource whose scheme is not the system of the server is removed (an adapter: {@code <system>+<foreign scheme>}), and the audit says
 * {@code link_scheme_refused}. The scheme is read as RFC 3986 says and compared exactly, case included, as the URI match of
 * {@code resources/read} does; a URI without a scheme is refused.
 */
public final class LinkBlocks {

    public static final String REFUSED = "link_scheme_refused";

    private static final Pattern SCHEME = Pattern.compile("^([A-Za-z][A-Za-z0-9+.-]*):");

    private LinkBlocks() {
    }

    /** @param refused whether anything was removed */
    public record Filtered(ArrayNode blocks, boolean refused) {
    }

    public static Filtered filter(JsonMapper json, String system, boolean adapter, JsonNode blocks) {
        ArrayNode kept = json.createArrayNode();
        boolean refused = false;
        for (JsonNode block : blocks) {
            String type = block.path("type").asString("");
            String uri = "resource_link".equals(type) ? block.path("uri").asString(null)
                    : "resource".equals(type) ? block.path("resource").path("uri").asString(null) : null;
            boolean pointsAtUri = "resource_link".equals(type) || "resource".equals(type);
            if (!pointsAtUri || schemeAllowed(system, adapter, uri)) {
                kept.add(block);
            } else {
                refused = true;
            }
        }
        return new Filtered(kept, refused);
    }

    static boolean schemeAllowed(String system, boolean adapter, String uri) {
        String scheme = schemeOf(uri);
        if (scheme == null) {
            return false;
        }
        if (!adapter) {
            return scheme.equals(system);
        }
        if (!scheme.startsWith(system + "+")) {
            return false;
        }
        String foreign = scheme.substring(system.length() + 1);
        return foreign.equals(schemeOf(foreign + ":"));
    }

    private static String schemeOf(String uri) {
        if (uri == null) {
            return null;
        }
        Matcher found = SCHEME.matcher(uri);
        return found.find() ? found.group(1) : null;
    }
}
