package pl.aiwcorpo.mcp.gateway.auth;

import java.net.URI;

/**
 * Public address of the gateway and of the portal behind the same reverse proxy (CC-089). It comes from
 * configuration only; the Host and X-Forwarded-* headers of a request never reach a URL we hand out.
 */
public final class PublicUrls {

    private final String base;

    public PublicUrls(URI publicUrl, boolean allowPlainHttp) {
        String scheme = publicUrl.getScheme();
        boolean httpsOk = "https".equals(scheme);
        boolean httpOk = "http".equals(scheme) && allowPlainHttp;
        if (!(httpsOk || httpOk) || publicUrl.getHost() == null || publicUrl.getRawUserInfo() != null
                || publicUrl.getRawQuery() != null || publicUrl.getRawFragment() != null
                || (publicUrl.getRawPath() != null && !publicUrl.getRawPath().isEmpty() && !"/".equals(publicUrl.getRawPath()))) {
            throw new IllegalStateException("gateway.public-url must be an https origin without path, query or user info"
                    + " (http only with gateway.allow-plain-http)");
        }
        String value = publicUrl.toString();
        this.base = value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
    }

    public String base() {
        return base;
    }

    public String serverUrl(String serverId) {
        return base + "/s/" + serverId + "/mcp";
    }

    public String aggregateUrl() {
        return base + "/mcp";
    }

    /** Portal page where the user connects the account in {@code system} (C10 credential_required). */
    public String connectUrl(String system) {
        return base + "/connections?system=" + system;
    }

    /** Read-only preview of a pending confirmation (C10 confirmation_required, previewUrl). */
    public String confirmationPreviewUrl(String confirmationId) {
        return base + "/confirm/" + confirmationId;
    }

    /** Portal page where the user registers the authenticator (C10 confirmation_required, registerUrl). */
    public String authenticatorUrl() {
        return base + "/authenticator";
    }
}
