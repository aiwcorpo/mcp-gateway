package pl.aiwcorpo.mcp.gateway.auth;

import java.util.regex.Pattern;

/**
 * RFC 9728 URLs of the gateway: the protected resource is the MCP endpoint the client called (without the filter of its query)
 * and its metadata lives at the root of the public origin ({@code /.well-known/oauth-protected-resource/<path>}).
 */
public final class ResourceMetadata {

    public static final String WELL_KNOWN = "/.well-known/oauth-protected-resource";
    /**
     * MCP endpoints that have metadata: {@code /mcp} and the route of one system. The resource is the path without a query (CC-171,
     * variant V2): the filter is part of the address of a request, never of the identifier of the resource.
     */
    public static final Pattern RESOURCE_PATH = Pattern.compile("^/(?:mcp|s/mcp-[a-z][a-z0-9]{1,31}/mcp)$");

    private final PublicUrls urls;

    public ResourceMetadata(PublicUrls urls) {
        this.urls = urls;
    }

    /** Replaces scheme and authority of a URL derived from the request with the configured public URL. */
    public String rebase(String url) {
        String path = java.net.URI.create(url).getRawPath();
        return urls.base() + (path == null ? "" : path);
    }

    /**
     * Metadata URL for the requested path (without its query). A path that is not an MCP endpoint gets the root document, so
     * nothing of the request (parameters, quotes) lands in the challenge header.
     */
    public String metadataUrl(String resourcePath) {
        boolean known = resourcePath != null && RESOURCE_PATH.matcher(resourcePath).matches();
        return urls.base() + WELL_KNOWN + (known ? resourcePath : "");
    }

    public boolean isMetadataPath(String requestPath) {
        if (WELL_KNOWN.equals(requestPath)) {
            return true;
        }
        return requestPath != null && requestPath.startsWith(WELL_KNOWN + "/")
                && RESOURCE_PATH.matcher(requestPath.substring(WELL_KNOWN.length())).matches();
    }
}
