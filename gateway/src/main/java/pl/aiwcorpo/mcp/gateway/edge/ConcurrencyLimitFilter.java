package pl.aiwcorpo.mcp.gateway.edge;

import java.io.IOException;
import java.time.Duration;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.filter.OncePerRequestFilter;

import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import pl.aiwcorpo.mcp.gateway.jwt.UuidV7;
import pl.aiwcorpo.mcp.gateway.ratelimit.RateLimitResponse;

/**
 * The most MCP requests ({@code POST} and {@code DELETE} on {@code /mcp} and {@code /s/<serverId>/mcp}) the gateway serves at the same
 * time. Every request runs on a virtual thread, so nothing else bounds them: a stalled system, database or Redis would let the requests
 * pile up, each holding its buffers, until the process runs out of memory. A request that finds no free place within
 * {@code queueWait} is refused with {@code 503} and {@code Retry-After} (fail-closed: nothing is served without the checks). The filter
 * runs after the authentication, so a request without a valid token never takes a place (and gets its {@code 401}); it counts the
 * refusals in {@code mcp_gateway_requests_shed_total} and writes at most one log line a second.
 */
public final class ConcurrencyLimitFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(ConcurrencyLimitFilter.class);

    private final Semaphore places;
    private final Duration queueWait;
    private final int retryAfterSeconds;
    private final MeterRegistry meters;
    private final AtomicInteger inFlight = new AtomicInteger();
    private final AtomicLong lastLogged = new AtomicLong(Long.MIN_VALUE);
    private final LongSupplier nanoTime;

    public ConcurrencyLimitFilter(int maxConcurrent, Duration queueWait, int retryAfterSeconds, MeterRegistry meters, LongSupplier nanoTime) {
        this.places = new Semaphore(maxConcurrent);
        this.queueWait = queueWait;
        this.retryAfterSeconds = retryAfterSeconds;
        this.meters = meters;
        this.nanoTime = nanoTime;
        Gauge.builder("mcp_gateway_requests_in_flight", inFlight, AtomicInteger::get)
                .description("MCP requests being served now").register(meters);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String method = request.getMethod();
        if (!"POST".equals(method) && !"DELETE".equals(method)) {
            return true;
        }
        String path = request.getServletPath();
        return !("/mcp".equals(path) || (path.startsWith("/s/") && path.endsWith("/mcp")));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        boolean admitted;
        try {
            admitted = places.tryAcquire(queueWait.toNanos(), TimeUnit.NANOSECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            admitted = false;
        }
        if (!admitted) {
            shed(response);
            return;
        }
        inFlight.incrementAndGet();
        try {
            chain.doFilter(request, response);
        } finally {
            inFlight.decrementAndGet();
            places.release();
        }
    }

    private void shed(HttpServletResponse response) throws IOException {
        meters.counter("mcp_gateway_requests_shed_total").increment();
        long now = nanoTime.getAsLong();
        long before = lastLogged.get();
        if ((before == Long.MIN_VALUE || now - before >= 1_000_000_000L) && lastLogged.compareAndSet(before, now)) {
            log.warn("MCP requests over the limit of concurrent requests are refused with 503 ({} in flight)", inFlight.get());
        }
        ResponseEntity<String> refusal = RateLimitResponse.overloaded(UuidV7.next(), retryAfterSeconds);
        response.setStatus(refusal.getStatusCode().value());
        refusal.getHeaders().forEach((name, values) -> response.setHeader(name, values.getFirst()));
        response.getWriter().write(refusal.getBody());
    }
}
