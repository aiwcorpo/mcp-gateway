package pl.aiwcorpo.mcp.gateway.primitive;

import java.nio.charset.StandardCharsets;

import tools.jackson.databind.JsonNode;

/**
 * Step 10 of {@code resources/read} (CC-259): the result of the server is checked for its shape and never rewritten. Exactly one item of
 * {@code contents} with the requested {@code uri} and a {@code text}; a {@code blob} is refused; more bytes than the limit of the gateway is
 * refused. Every refusal reaches the client as -32603 {@code upstream_unavailable}; the reason is for the audit.
 */
public final class ResourceContents {

    private ResourceContents() {
    }

    /** {@code reason} is null for a result that passes. */
    public record Check(String reason, long bytes) {

        public boolean passes() {
            return reason == null;
        }
    }

    /** @param bytes the size of the text of the item as the server sent it, UTF-8; the vectors give it, a live result is measured by {@link #measure} */
    public static Check check(JsonNode contents, String requestedUri, long bytes, long maxBytes) {
        if (!contents.isArray() || contents.size() != 1 || !requestedUri.equals(contents.get(0).path("uri").asString(null))) {
            return new Check("result_invalid", bytes);
        }
        JsonNode item = contents.get(0);
        if (item.has("blob")) {
            return new Check("blob_not_supported", bytes);
        }
        if (!item.path("text").isString()) {
            return new Check("result_invalid", bytes);
        }
        if (bytes > maxBytes) {
            return new Check("result_too_large", bytes);
        }
        return new Check(null, bytes);
    }

    public static long measure(JsonNode contents) {
        return contents.isArray() && contents.size() == 1 && contents.get(0).path("text").isString()
                ? contents.get(0).path("text").asString().getBytes(StandardCharsets.UTF_8).length : 0;
    }
}
