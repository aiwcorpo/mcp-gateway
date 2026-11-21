package pl.aiwcorpo.mcp.gateway.tracing;

import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;

/**
 * The public port is open to any client, so the trace context a client sends is not trusted: the request starts a trace of its own and
 * the gateway's sampler decides about it. The client's {@code traceparent} is kept as a request attribute for a span link
 * ({@link ClientLinkingReceiverHandler}); {@code traceparent}, {@code tracestate} and {@code baggage} are hidden from everything behind
 * this filter, so none of them is continued, logged or passed on. The internal port (callers authenticated by mTLS) is left alone and
 * keeps inheriting the parent context. Runs before the observation filter of Spring Boot.
 */
public final class PublicEdgeTraceFilter extends OncePerRequestFilter {

    static final String CLIENT_TRACEPARENT = PublicEdgeTraceFilter.class.getName() + ".clientTraceparent";

    private static final Set<String> TRACE_HEADERS = Set.of("traceparent", "tracestate", "baggage");

    private final int internalPort;

    public PublicEdgeTraceFilter(int internalPort) {
        this.internalPort = internalPort;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (request.getLocalPort() == internalPort) {
            chain.doFilter(request, response);
            return;
        }
        String traceparent = request.getHeader("traceparent");
        if (traceparent != null) {
            request.setAttribute(CLIENT_TRACEPARENT, traceparent);
        }
        chain.doFilter(new WithoutTraceHeaders(request), response);
    }

    private static boolean hidden(String name) {
        return name != null && TRACE_HEADERS.contains(name.toLowerCase(Locale.ROOT));
    }

    private static final class WithoutTraceHeaders extends HttpServletRequestWrapper {

        WithoutTraceHeaders(HttpServletRequest request) {
            super(request);
        }

        @Override
        public String getHeader(String name) {
            return hidden(name) ? null : super.getHeader(name);
        }

        @Override
        public Enumeration<String> getHeaders(String name) {
            return hidden(name) ? Collections.emptyEnumeration() : super.getHeaders(name);
        }

        @Override
        public Enumeration<String> getHeaderNames() {
            List<String> kept = Collections.list(super.getHeaderNames()).stream().filter(name -> !hidden(name)).toList();
            return Collections.enumeration(kept);
        }
    }
}
