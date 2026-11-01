package pl.aiwcorpo.mcp.gateway.edge;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import jakarta.servlet.ServletException;
import tools.jackson.databind.json.JsonMapper;

class ConcurrencyLimitFilterTest {

    private final SimpleMeterRegistry meters = new SimpleMeterRegistry();
    private final ConcurrencyLimitFilter filter = new ConcurrencyLimitFilter(2, Duration.ofMillis(20), 3, meters, System::nanoTime);

    private MockHttpServletRequest request(String method, String path) {
        MockHttpServletRequest request = new MockHttpServletRequest(method, path);
        request.setServletPath(path);
        return request;
    }

    @Test
    void aRequestOverTheLimitIsRefusedWith503RetryAfterAndTheCodeOfUpstreamUnavailable() throws Exception {
        CountDownLatch inside = new CountDownLatch(2);
        CountDownLatch release = new CountDownLatch(1);
        Runnable hold = () -> {
            try {
                filter.doFilter(request("POST", "/mcp"), new MockHttpServletResponse(), new MockFilterChain() {
                    @Override
                    public void doFilter(jakarta.servlet.ServletRequest req, jakarta.servlet.ServletResponse res) {
                        inside.countDown();
                        try {
                            release.await(10, TimeUnit.SECONDS);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                        }
                    }
                });
            } catch (ServletException | java.io.IOException e) {
                throw new IllegalStateException(e);
            }
        };
        Thread first = Thread.ofVirtual().start(hold);
        Thread second = Thread.ofVirtual().start(hold);
        assertThat(inside.await(5, TimeUnit.SECONDS)).isTrue();

        MockHttpServletResponse refused = new MockHttpServletResponse();
        filter.doFilter(request("POST", "/s/mcp-jira/mcp"), refused, new MockFilterChain());
        assertThat(refused.getStatus()).isEqualTo(503);
        assertThat(refused.getHeader("Retry-After")).isEqualTo("3");
        assertThat(refused.getHeader("X-Request-Id")).matches("^[0-9a-f-]{36}$");
        assertThat(JsonMapper.builder().build().readTree(refused.getContentAsString()).path("error").asString()).isEqualTo("upstream_unavailable");
        assertThat(meters.get("mcp_gateway_requests_shed_total").counter().count()).isEqualTo(1.0);

        MockHttpServletResponse get = new MockHttpServletResponse();
        filter.doFilter(request("GET", "/mcp"), get, new MockFilterChain());
        assertThat(get.getStatus()).as("a GET takes no place").isEqualTo(200);
        MockHttpServletResponse elsewhere = new MockHttpServletResponse();
        filter.doFilter(request("POST", "/admin/v1/catalog"), elsewhere, new MockFilterChain());
        assertThat(elsewhere.getStatus()).as("only the MCP routes are limited").isEqualTo(200);

        release.countDown();
        first.join();
        second.join();
        MockHttpServletResponse after = new MockHttpServletResponse();
        filter.doFilter(request("POST", "/mcp"), after, new MockFilterChain());
        assertThat(after.getStatus()).as("the places are free again").isEqualTo(200);
    }

    @Test
    void aPlaceIsGivenBackWhenTheRequestFails() throws Exception {
        for (int i = 0; i < 5; i++) {
            try {
                filter.doFilter(request("POST", "/mcp"), new MockHttpServletResponse(), new MockFilterChain() {
                    @Override
                    public void doFilter(jakarta.servlet.ServletRequest req, jakarta.servlet.ServletResponse res) {
                        throw new IllegalStateException("boom");
                    }
                });
            } catch (IllegalStateException expected) {
                // the place must be released all the same
            }
        }
        MockHttpServletResponse after = new MockHttpServletResponse();
        filter.doFilter(request("POST", "/mcp"), after, new MockFilterChain());
        assertThat(after.getStatus()).isEqualTo(200);
    }
}
