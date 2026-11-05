package pl.aiwcorpo.mcp.gateway.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;

import org.junit.jupiter.api.Test;

class PublicUrlsTest {

    @Test
    void buildsEndpointsAndPortalLinksFromTheConfiguredOrigin() {
        PublicUrls urls = new PublicUrls(URI.create("https://mcp.aiwcorpo.pl/"), false);
        assertThat(urls.serverUrl("mcp-jira")).isEqualTo("https://mcp.aiwcorpo.pl/s/mcp-jira/mcp");
        assertThat(urls.aggregateUrl()).isEqualTo("https://mcp.aiwcorpo.pl/mcp");
        assertThat(urls.connectUrl("jira")).isEqualTo("https://mcp.aiwcorpo.pl/connections?system=jira");
    }

    @Test
    void plainHttpOnlyInDevAndOnlyAnOriginIsAccepted() {
        assertThatThrownBy(() -> new PublicUrls(URI.create("http://localhost:18700"), false)).isInstanceOf(IllegalStateException.class);
        assertThat(new PublicUrls(URI.create("http://localhost:18700"), true).base()).isEqualTo("http://localhost:18700");
        for (String bad : new String[] {"https://mcp.aiwcorpo.pl/gateway", "https://u:p@mcp.aiwcorpo.pl", "https://mcp.aiwcorpo.pl?x=1",
                "https://mcp.aiwcorpo.pl#f", "ftp://mcp.aiwcorpo.pl", "mcp.aiwcorpo.pl"}) {
            assertThatThrownBy(() -> new PublicUrls(URI.create(bad), true)).as(bad).isInstanceOf(IllegalStateException.class);
        }
    }
}
