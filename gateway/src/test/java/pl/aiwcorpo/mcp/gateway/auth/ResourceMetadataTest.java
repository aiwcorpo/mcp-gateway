package pl.aiwcorpo.mcp.gateway.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;

import org.junit.jupiter.api.Test;

class ResourceMetadataTest {

    private final ResourceMetadata metadata = new ResourceMetadata(new PublicUrls(URI.create("https://mcp.aiwcorpo.pl"), false));
    private static final String WELL_KNOWN = "https://mcp.aiwcorpo.pl/.well-known/oauth-protected-resource";

    @Test
    void metadataUrlNamesOnlyShapesOfMcpEndpoints() {
        assertThat(metadata.metadataUrl("/s/mcp-jira/mcp")).isEqualTo(WELL_KNOWN + "/s/mcp-jira/mcp");
        assertThat(metadata.metadataUrl("/mcp")).isEqualTo(WELL_KNOWN + "/mcp");
        for (String other : new String[] {null, "", "/", "/v/team-a-dev/mcp", "/f/systems=jira/mcp", "/mcp/x", "/mcp;x", "/s/mcp-jira/mcp;x",
                "/admin/v1/catalog", "/s/mcp-jira\n/mcp", "/s/mcp-jira/mcp/x"}) {
            assertThat(metadata.metadataUrl(other)).as(String.valueOf(other)).isEqualTo(WELL_KNOWN);
        }
    }

    @Test
    void metadataPathsAreTheRootAndTheEndpointShapesOnly() {
        assertThat(metadata.isMetadataPath("/.well-known/oauth-protected-resource")).isTrue();
        assertThat(metadata.isMetadataPath("/.well-known/oauth-protected-resource/s/mcp-gitlab/mcp")).isTrue();
        assertThat(metadata.isMetadataPath("/.well-known/oauth-protected-resource/mcp")).isTrue();
        assertThat(metadata.isMetadataPath("/.well-known/oauth-protected-resource/v/a/mcp")).isFalse();
        assertThat(metadata.isMetadataPath("/.well-known/oauth-protected-resource/mcp/")).isFalse();
        assertThat(metadata.isMetadataPath("/.well-known/oauth-protected-resource/")).isFalse();
        assertThat(metadata.isMetadataPath("/.well-known/oauth-protected-resourcex")).isFalse();
        assertThat(metadata.isMetadataPath("/.well-known/oauth-protected-resource/v/a/mcp/")).isFalse();
        assertThat(metadata.isMetadataPath("/.well-known/oauth-protected-resource/s/mcp-jira/mcp/extra")).isFalse();
    }

    @Test
    void rebaseReplacesSchemeAndAuthority() {
        assertThat(metadata.rebase("http://evil.test:1/s/mcp-jira/mcp")).isEqualTo("https://mcp.aiwcorpo.pl/s/mcp-jira/mcp");
    }
}
