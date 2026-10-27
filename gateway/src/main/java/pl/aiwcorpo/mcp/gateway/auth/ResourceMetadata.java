package pl.aiwcorpo.mcp.gateway.auth;

import java.net.URI;

import jakarta.servlet.http.HttpServletRequest;

/** Public URLs of the gateway as the client sees them: RFC 9728 resource and its metadata document. */
public final class ResourceMetadata {

    public static final String WELL_KNOWN = "/.well-known/oauth-protected-resource";

    private final URI publicUrl;

    public ResourceMetadata(URI publicUrl) {
        this.publicUrl = publicUrl;
    }

    /**
     * Base URL: the configured public URL, otherwise the request's own scheme and authority. A forged Host only
     * changes the metadata URL in the forger's own 401 response.
     */
    public String baseUrl(HttpServletRequest request) {
        if (publicUrl != null) {
            String value = publicUrl.toString();
            return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
        }
        String scheme = request.getScheme();
        int port = request.getServerPort();
        boolean defaultPort = ("http".equals(scheme) && port == 80) || ("https".equals(scheme) && port == 443);
        return scheme + "://" + request.getServerName() + (defaultPort ? "" : ":" + port);
    }

    /** Replaces scheme and authority of a URL derived from the request with the configured public URL. */
    public String rebase(String url) {
        if (publicUrl == null) {
            return url;
        }
        URI derived = URI.create(url);
        String base = publicUrl.toString().endsWith("/")
                ? publicUrl.toString().substring(0, publicUrl.toString().length() - 1) : publicUrl.toString();
        return base + (derived.getRawPath() == null ? "" : derived.getRawPath());
    }

    public String metadataUrl(HttpServletRequest request, String resourcePath) {
        return baseUrl(request) + WELL_KNOWN + resourcePath;
    }
}
