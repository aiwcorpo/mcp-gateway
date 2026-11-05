package pl.aiwcorpo.mcp.gateway.edge;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Collections;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

class PublicEdgeFilterTest {

    private final PublicEdgeFilter filter = new PublicEdgeFilter();

    @Test
    void clientCookieIsInvisibleInEveryAccessor() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/s/mcp-jira/mcp");
        request.addHeader("Cookie", "__Host-session=value");
        request.addHeader("cookie", "second=value");
        request.setCookies(new Cookie("__Host-session", "value"));
        request.addHeader("Authorization", "Bearer token");
        AtomicReference<HttpServletRequest> seen = new AtomicReference<>();

        filter.doFilter(request, new MockHttpServletResponse(), (FilterChain) (req, res) -> seen.set((HttpServletRequest) req));

        HttpServletRequest wrapped = seen.get();
        assertThat(wrapped.getHeader("Cookie")).isNull();
        assertThat(wrapped.getHeader("COOKIE")).isNull();
        assertThat(Collections.list(wrapped.getHeaders("cookie"))).isEmpty();
        assertThat(Collections.list(wrapped.getHeaderNames())).noneMatch(n -> n.equalsIgnoreCase("cookie"));
        assertThat(wrapped.getCookies()).isNull();
        assertThat(wrapped.getHeader("Authorization")).isEqualTo("Bearer token");
    }

    @Test
    void securityHeadersAreSetBeforeTheChainRunsAndSetCookieIsDropped() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(new MockHttpServletRequest("GET", "/x"), response, (FilterChain) (req, res) -> {
            HttpServletResponse out = (HttpServletResponse) res;
            out.addHeader("Set-Cookie", "JSESSIONID=1");
            out.setHeader("set-cookie", "a=b");
            out.addCookie(new Cookie("c", "d"));
            out.addHeader("X-Other", "kept");
            out.sendError(404);
        });

        assertThat(response.getHeader("X-Content-Type-Options")).isEqualTo("nosniff");
        assertThat(response.getHeader("Content-Security-Policy")).isEqualTo("default-src 'none'; sandbox");
        assertThat(response.getHeaders("Set-Cookie")).isEmpty();
        assertThat(response.getCookies()).isEmpty();
        assertThat(response.getHeader("X-Other")).isEqualTo("kept");
    }
}
