package pl.aiwcorpo.mcp.gateway.tracing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpServer;

import io.micrometer.tracing.Span;
import io.micrometer.tracing.Tracer;
import io.micrometer.tracing.propagation.Propagator;
import io.micrometer.tracing.test.simple.SimpleSpan;
import io.micrometer.tracing.otel.bridge.OtelCurrentTraceContext;
import io.micrometer.tracing.otel.bridge.OtelPropagator;
import io.micrometer.tracing.otel.bridge.OtelTracer;
import io.micrometer.tracing.test.simple.SimpleTracer;
import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.api.trace.propagation.W3CTraceContextPropagator;
import io.opentelemetry.context.propagation.ContextPropagators;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import io.opentelemetry.sdk.trace.samplers.Sampler;

class TracingHttpClientTest {

    private final SimpleTracer tracer = new SimpleTracer();
    private final Propagator propagator = new Propagator() {
        @Override
        public java.util.List<String> fields() {
            return java.util.List.of("traceparent");
        }

        @Override
        public <C> void inject(io.micrometer.tracing.TraceContext context, C carrier, Setter<C> setter) {
            setter.set(carrier, "traceparent", "00-" + context.traceId() + "-" + context.spanId() + "-01");
        }

        @Override
        public <C> Span.Builder extract(C carrier, Getter<C> getter) {
            throw new UnsupportedOperationException();
        }
    };
    private final AtomicReference<String> seenTraceparent = new AtomicReference<>();
    private final AtomicReference<String> seenAuthorization = new AtomicReference<>();
    private HttpServer server;
    private HttpClient plain;

    @BeforeEach
    void start() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/boom", exchange -> {
            exchange.sendResponseHeaders(503, -1);
            exchange.close();
        });
        server.createContext("/", exchange -> {
            seenTraceparent.set(exchange.getRequestHeaders().getFirst("traceparent"));
            seenAuthorization.set(exchange.getRequestHeaders().getFirst("Authorization"));
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
        });
        server.start();
        plain = HttpClient.newHttpClient();
    }

    @AfterEach
    void stop() {
        server.stop(0);
        plain.close();
    }

    private HttpRequest request(String path) {
        return HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + server.getAddress().getPort() + path))
                .header("Authorization", "Bearer secret-token-value").POST(HttpRequest.BodyPublishers.ofString("{\"arguments\":\"top secret\"}")).build();
    }

    private TracingHttpClient client() {
        return new TracingHttpClient(plain, tracer, propagator, "mcp-credential-broker");
    }

    @Test
    void aCallInsideATraceCarriesTheTraceIdAndANewSpanIdOfItsOwn() throws Exception {
        Span parent = tracer.nextSpan().name("inbound").start();
        try (Tracer.SpanInScope ignored = tracer.withSpan(parent)) {
            assertThat(client().send(request("/"), HttpResponse.BodyHandlers.discarding()).statusCode()).isEqualTo(200);
        }
        String[] parts = seenTraceparent.get().split("-");
        assertThat(parts[1]).isEqualTo(parent.context().traceId());
        assertThat(parts[2]).isNotEqualTo(parent.context().spanId());
        SimpleSpan client = tracer.getSpans().stream().filter(s -> "POST".equals(s.getName())).findFirst().orElseThrow();
        assertThat(client.context().spanId()).isEqualTo(parts[2]);
        assertThat(client.getParentId()).isEqualTo(parent.context().spanId());
        assertThat(client.getKind()).isEqualTo(Span.Kind.CLIENT);
        assertThat(client.getRemoteServiceName()).isEqualTo("mcp-credential-broker");
        assertThat(client.getTags()).containsEntry("http.response.status_code", "200");
        assertThat(client.getEndTimestamp()).isNotNull();
    }

    @Test
    void theSpanRecordsNoPathHeaderOrBodyValue() throws Exception {
        Span parent = tracer.nextSpan().name("inbound").start();
        try (Tracer.SpanInScope ignored = tracer.withSpan(parent)) {
            client().send(request("/v1/credentials/resolve"), HttpResponse.BodyHandlers.discarding());
        }
        SimpleSpan client = tracer.getSpans().stream().filter(s -> "POST".equals(s.getName())).findFirst().orElseThrow();
        assertThat(client.getTags().keySet()).containsExactlyInAnyOrder("http.request.method", "server.address", "server.port",
                "http.response.status_code");
        assertThat(client.getTags().values()).noneMatch(v -> v.contains("secret") || v.contains("resolve"));
        assertThat(client.getEvents()).isEmpty();
    }

    @Test
    void aCallWithNoCurrentTraceIsSentUnchangedAndStartsNoSpan() throws Exception {
        client().send(request("/"), HttpResponse.BodyHandlers.discarding());
        assertThat(seenTraceparent.get()).isNull();
        assertThat(tracer.getSpans()).isEmpty();
    }

    @Test
    void aNoOpTracerAddsNoHeader() throws Exception {
        TracingHttpClient off = new TracingHttpClient(plain, Tracer.NOOP, Propagator.NOOP, "mcp-server");
        off.send(request("/"), HttpResponse.BodyHandlers.discarding());
        assertThat(seenTraceparent.get()).isNull();
    }

    @Test
    void theCallersOwnHeadersReachThePeerUnchanged() throws Exception {
        Span parent = tracer.nextSpan().name("inbound").start();
        try (Tracer.SpanInScope ignored = tracer.withSpan(parent)) {
            client().send(request("/"), HttpResponse.BodyHandlers.discarding());
        }
        assertThat(seenAuthorization.get()).isEqualTo("Bearer secret-token-value");
    }

    @Test
    void aServerErrorMarksTheSpanWithItsStatus() throws Exception {
        Span parent = tracer.nextSpan().name("inbound").start();
        try (Tracer.SpanInScope ignored = tracer.withSpan(parent)) {
            client().send(request("/boom"), HttpResponse.BodyHandlers.discarding());
        }
        SimpleSpan client = tracer.getSpans().stream().filter(s -> "POST".equals(s.getName())).findFirst().orElseThrow();
        assertThat(client.getTags()).containsEntry("error.type", "503");
    }

    @Test
    void aFailedConnectionEndsTheSpanWithTheExceptionClassOnly() throws Exception {
        int closed = server.getAddress().getPort();
        server.stop(0);
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + closed + "/")).GET().build();
        Span parent = tracer.nextSpan().name("inbound").start();
        try (Tracer.SpanInScope ignored = tracer.withSpan(parent)) {
            assertThatThrownBy(() -> client().send(request, HttpResponse.BodyHandlers.discarding())).isInstanceOf(IOException.class);
        }
        SimpleSpan client = tracer.getSpans().stream().filter(s -> "GET".equals(s.getName())).findFirst().orElseThrow();
        assertThat(client.getTags().get("error.type")).isNotBlank().doesNotContain(" ");
        assertThat(client.getError()).isNull();
        assertThat(client.getEndTimestamp()).isNotNull();
    }

    @Test
    void anUnsampledTraceIsPassedOnWithTheSampledBitClearAndTheSameTraceId() throws Exception {
        SdkTracerProvider provider = SdkTracerProvider.builder().setSampler(Sampler.alwaysOff()).build();
        OpenTelemetry otel = OpenTelemetrySdk.builder().setTracerProvider(provider)
                .setPropagators(ContextPropagators.create(W3CTraceContextPropagator.getInstance())).build();
        io.opentelemetry.api.trace.Tracer otelTracer = otel.getTracer("test");
        OtelTracer unsampled = new OtelTracer(otelTracer, new OtelCurrentTraceContext(), event -> { });
        OtelPropagator w3c = new OtelPropagator(otel.getPropagators(), otelTracer);
        TracingHttpClient client = new TracingHttpClient(plain, unsampled, w3c, "mcp-server");
        Span parent = unsampled.nextSpan().name("inbound").start();
        assertThat(parent.isNoop()).as("the bridge reports an unsampled span as no-op").isTrue();
        try (Tracer.SpanInScope ignored = unsampled.withSpan(parent)) {
            client.send(request("/"), HttpResponse.BodyHandlers.discarding());
        }
        String[] parts = seenTraceparent.get().split("-");
        assertThat(parts).hasSize(4);
        assertThat(parts[1]).isEqualTo(parent.context().traceId());
        assertThat(Integer.parseInt(parts[3], 16) & 1).as("sampled bit of flags " + parts[3]).isZero();
        provider.close();
    }
}
