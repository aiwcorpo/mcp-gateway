package pl.aiwcorpo.mcp.gateway.confirm;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import pl.aiwcorpo.mcp.cedar.entities.ResourceIds;
import pl.aiwcorpo.mcp.cedar.entities.ResourceRef;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * The operation as the gateway computes it from the arguments it received (C11): the arguments sorted by name, JSON
 * serialized and cut to a limit, the main resource from {@code resourceRefs}, and the one-line {@code description}
 * of {@code confirmation_required}. It is not model text; the client is untrusted and the portal preview is the
 * reference.
 */
public final class OperationDescription {

    static final int MAX_VALUE_CHARS = 200;
    static final int MAX_ARGUMENTS = 50;
    static final int MAX_DESCRIPTION = 1000;
    private static final Pattern JIRA_ISSUE = Pattern.compile("^([A-Z][A-Z0-9_]*)-[0-9]+$");

    private OperationDescription() {
    }

    /** SHA-256 of the canonical (RFC 8785) arguments without {@code confirmation_code}: the key of a pending call. */
    public static String argumentsHash(JsonNode argumentsWithoutCode) {
        try {
            String canonical = pl.aiwcorpo.mcp.manifest.CanonicalJson.canonicalize(argumentsWithoutCode.toString());
            byte[] digest = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(canonical.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return "sha256:" + java.util.HexFormat.of().formatHex(digest);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static PendingCall.Display of(JsonMapper json, String qualifiedTool, String system, JsonNode arguments,
                                         List<ResourceRef> refs) {
        Map<String, JsonNode> sorted = new TreeMap<>();
        arguments.properties().forEach(e -> {
            if (!"confirmation_code".equals(e.getKey())) {
                sorted.put(e.getKey(), e.getValue());
            }
        });
        List<PendingCall.Argument> shown = new ArrayList<>();
        StringBuilder description = new StringBuilder(qualifiedTool).append(" (").append(system).append("):");
        boolean first = true;
        for (Map.Entry<String, JsonNode> entry : sorted.entrySet()) {
            if (shown.size() >= MAX_ARGUMENTS) {
                break;
            }
            String full = TextHygiene.escape(json.writeValueAsString(entry.getValue()));
            boolean cut = full.codePointCount(0, full.length()) > MAX_VALUE_CHARS;
            String value = cut ? full.substring(0, full.offsetByCodePoints(0, MAX_VALUE_CHARS)) : full;
            String name = TextHygiene.escape(entry.getKey());
            shown.add(new PendingCall.Argument(name, value, cut));
            description.append(first ? " " : ", ").append(name).append('=').append(value).append(cut ? "..." : "");
            first = false;
        }
        String text = description.codePointCount(0, description.length()) > MAX_DESCRIPTION
                ? description.substring(0, description.offsetByCodePoints(0, MAX_DESCRIPTION - 3)) + "..." : description.toString();
        return new PendingCall.Display(qualifiedTool, system, resourceOf(arguments, refs), List.copyOf(shown), text);
    }

    /** The first reference whose argument is a single valid identifier; null when the tool names no resource. */
    static PendingCall.Resource resourceOf(JsonNode arguments, List<ResourceRef> refs) {
        for (ResourceRef ref : refs) {
            JsonNode value = arguments.get(ref.argument());
            if (value == null || !(value.isString() || value.isIntegralNumber())) {
                continue;
            }
            String id = value.asString();
            if (id.length() > 512 || !ResourceIds.isValid(ref.type(), ResourceIds.Kind.RESOURCE, id)) {
                continue;
            }
            String parent = null;
            if ("Jira::Issue".equals(ref.type())) {
                Matcher m = JIRA_ISSUE.matcher(id);
                if (m.matches()) {
                    parent = "Jira::Project::" + m.group(1);
                }
            }
            return new PendingCall.Resource(ref.type(), id, parent);
        }
        return null;
    }
}
