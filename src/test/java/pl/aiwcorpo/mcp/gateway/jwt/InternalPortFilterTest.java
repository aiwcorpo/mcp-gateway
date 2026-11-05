package pl.aiwcorpo.mcp.gateway.jwt;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class InternalPortFilterTest {

    private static final int INTERNAL = 8443;
    private static final int PUBLIC = 8080;

    private final InternalPortFilter filter = new InternalPortFilter(INTERNAL);

    @Test
    void internalPathsAreNotFoundOnThePublicPortWhateverTheMethod() throws Exception {
        for (String method : new String[] {"GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"}) {
            for (String path : new String[] {"/admin/v1/catalog", "/admin/v1", "/.well-known/jwks.json", "/actuator/health",
                    "/actuator/prometheus", "/actuator", "/actuator/env"}) {
                assertThat(run(method, path, path, PUBLIC)).as(method + " " + path).isEqualTo(404);
            }
        }
    }

    @Test
    void thePathIsJudgedAfterNormalisationNotByTheRawUri() throws Exception {
        assertThat(run("GET", "/%61dmin/v1/catalog", "/admin/v1/catalog", PUBLIC)).isEqualTo(404);
        assertThat(run("GET", "//admin/v1/catalog", "/admin/v1/catalog", PUBLIC)).isEqualTo(404);
        assertThat(run("GET", "/s/%2e%2e/admin/v1/catalog", "/admin/v1/catalog", PUBLIC)).isEqualTo(404);
        assertThat(run("GET", "/admin/v1/catalog", "/s/mcp-jira/mcp", INTERNAL)).as("and the other way round").isEqualTo(404);
    }

    @Test
    void publicPathsPassOnThePublicPortAndOnlyInternalOnesOnTheInternalPort() throws Exception {
        assertThat(run("POST", "/s/mcp-jira/mcp", "/s/mcp-jira/mcp", PUBLIC)).isEqualTo(200);
        assertThat(run("GET", "/.well-known/oauth-protected-resource/s/mcp-jira/mcp",
                "/.well-known/oauth-protected-resource/s/mcp-jira/mcp", PUBLIC)).isEqualTo(200);

        assertThat(run("POST", "/s/mcp-jira/mcp", "/s/mcp-jira/mcp", INTERNAL)).isEqualTo(404);
        assertThat(run("GET", "/admin/v1/catalog", "/admin/v1/catalog", INTERNAL)).isEqualTo(200);
        assertThat(run("PATCH", "/admin/v1/catalog", "/admin/v1/catalog", INTERNAL)).isEqualTo(200);
        assertThat(run("GET", "/.well-known/jwks.json", "/.well-known/jwks.json", INTERNAL)).isEqualTo(200);
        assertThat(run("GET", "/actuator/health", "/actuator/health", INTERNAL)).isEqualTo(200);
        assertThat(run("GET", "/actuator/prometheus", "/actuator/prometheus", INTERNAL)).isEqualTo(200);
        assertThat(run("GET", "/actuator/env", "/actuator/env", INTERNAL)).isEqualTo(404);
        assertThat(run("POST", "/.well-known/jwks.json", "/.well-known/jwks.json", INTERNAL)).isEqualTo(404);
    }

    private int run(String method, String requestUri, String servletPath, int port) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest(method, requestUri);
        request.setServletPath(servletPath);
        request.setLocalPort(port);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, response, chain);
        return chain.getRequest() != null ? 200 : response.getStatus();
    }
}
