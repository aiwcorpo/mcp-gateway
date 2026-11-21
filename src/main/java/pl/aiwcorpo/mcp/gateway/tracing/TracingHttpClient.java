package pl.aiwcorpo.mcp.gateway.tracing;

import java.io.IOException;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.ProxySelector;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandler;
import java.net.http.HttpResponse.PushPromiseHandler;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

import io.micrometer.tracing.Span;
import io.micrometer.tracing.Tracer;
import io.micrometer.tracing.propagation.Propagator;

/**
 * Wraps the client of one outbound hop (the broker, an MCP server) so that a call made while a trace is current becomes a client span
 * and carries W3C {@code traceparent} / {@code tracestate} to the peer, also when the trace is not sampled (sampled bit of the flags clear). A call made
 * with no current trace (start-up checks, background pushes) is sent unchanged, so the gateway never starts a trace of its own for it.
 *
 * <p>Recorded on the span: the peer's service name, HTTP method, host, port, response status and, for a failure, the class name of the
 * exception or the status. No URL path or query, header, body, token or credential is recorded. The span ends when the response headers
 * arrive; reading a body (an event stream may stay open) is not part of it.
 */
public final class TracingHttpClient extends HttpClient {

    private final HttpClient delegate;
    private final Tracer tracer;
    private final Propagator propagator;
    private final String peer;

    public TracingHttpClient(HttpClient delegate, Tracer tracer, Propagator propagator, String peer) {
        this.delegate = delegate;
        this.tracer = tracer;
        this.propagator = propagator;
        this.peer = peer;
    }

    @Override
    public <T> HttpResponse<T> send(HttpRequest request, BodyHandler<T> handler) throws IOException, InterruptedException {
        Span span = start(request);
        if (span == null) {
            return delegate.send(request, handler);
        }
        try {
            HttpResponse<T> response = delegate.send(inject(request, span), handler);
            finish(span, response.statusCode(), null);
            return response;
        } catch (IOException | InterruptedException | RuntimeException e) {
            finish(span, 0, e);
            throw e;
        }
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request, BodyHandler<T> handler) {
        return sendAsync(request, handler, null);
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request, BodyHandler<T> handler, PushPromiseHandler<T> push) {
        Span span = start(request);
        if (span == null) {
            return delegate.sendAsync(request, handler, push);
        }
        return delegate.sendAsync(inject(request, span), handler, push).whenComplete((response, failure) ->
                finish(span, response == null ? 0 : response.statusCode(), failure));
    }

    private Span start(HttpRequest request) {
        Span parent = tracer.currentSpan();
        if (parent == null || !hasTrace(parent)) {
            return null;
        }
        return tracer.spanBuilder().setParent(parent.context()).kind(Span.Kind.CLIENT).name(request.method())
                .remoteServiceName(peer)
                .tag("http.request.method", request.method())
                .tag("server.address", request.uri().getHost())
                .tag("server.port", request.uri().getPort())
                .start();
    }

    /**
     * A span that is not recorded (the request was not sampled) still has a trace id and must be passed on with flags {@code 00}, or the
     * peer starts a trace of its own and samples it again. {@code isNoop()} is true for such a span, so it cannot be used here; only the
     * no-op tracer's empty context means "no trace".
     */
    private static boolean hasTrace(Span span) {
        String traceId = span.context().traceId();
        return traceId != null && !traceId.isEmpty() && !traceId.chars().allMatch(c -> c == '0');
    }

    private HttpRequest inject(HttpRequest request, Span span) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(request, (name, value) -> true);
        propagator.inject(span.context(), builder, (carrier, name, value) -> carrier.setHeader(name, value));
        return builder.build();
    }

    private static void finish(Span span, int status, Throwable failure) {
        if (status > 0) {
            span.tag("http.response.status_code", status);
        }
        if (failure != null) {
            span.tag("error.type", failure.getClass().getSimpleName());
        } else if (status >= 500) {
            span.tag("error.type", Integer.toString(status));
        }
        span.end();
    }

    @Override
    public Optional<CookieHandler> cookieHandler() {
        return delegate.cookieHandler();
    }

    @Override
    public Optional<Duration> connectTimeout() {
        return delegate.connectTimeout();
    }

    @Override
    public Redirect followRedirects() {
        return delegate.followRedirects();
    }

    @Override
    public Optional<ProxySelector> proxy() {
        return delegate.proxy();
    }

    @Override
    public SSLContext sslContext() {
        return delegate.sslContext();
    }

    @Override
    public SSLParameters sslParameters() {
        return delegate.sslParameters();
    }

    @Override
    public Optional<Authenticator> authenticator() {
        return delegate.authenticator();
    }

    @Override
    public Version version() {
        return delegate.version();
    }

    @Override
    public Optional<Executor> executor() {
        return delegate.executor();
    }

    @Override
    public void shutdown() {
        delegate.shutdown();
    }

    @Override
    public boolean awaitTermination(Duration duration) throws InterruptedException {
        return delegate.awaitTermination(duration);
    }

    @Override
    public boolean isTerminated() {
        return delegate.isTerminated();
    }

    @Override
    public void shutdownNow() {
        delegate.shutdownNow();
    }

    @Override
    public void close() {
        delegate.close();
    }
}
