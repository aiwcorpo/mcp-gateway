package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;

import javax.net.ssl.SSLContext;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.trace.SpanKind;
import io.opentelemetry.sdk.trace.data.SpanData;
import pl.aiwcorpo.mcp.gateway.support.RecordedSpansConfiguration;

class HealthProbeTracingTest extends GatewayTestBase {

    private static final AttributeKey<String> PROBE = AttributeKey.stringKey("mcp.health.probe");

    @Autowired
    MeterRegistry meters;

    private SpanData requestSpan(String url, SSLContext tls) throws Exception {
        int before = RecordedSpansConfiguration.spans().size();
        HttpClient.Builder client = HttpClient.newBuilder();
        if (tls != null) {
            client.sslContext(tls);
        }
        client.build().send(HttpRequest.newBuilder(URI.create(url)).GET().build(), java.net.http.HttpResponse.BodyHandlers.ofString());
        await().atMost(Duration.ofSeconds(10)).until(() -> serverSpansSince(before).size() >= 1);
        return serverSpansSince(before).getFirst();
    }

    private static List<SpanData> serverSpansSince(int before) {
        return RecordedSpansConfiguration.spans().stream().skip(before).filter(span -> span.getKind() == SpanKind.SERVER).toList();
    }

    private static boolean exported(SpanData span) {
        byte[] traceId = HexFormat.of().parseHex(span.getTraceId());
        String all = new String(env.collector.bodies().stream().reduce(new byte[0], (a, b) -> {
            byte[] joined = java.util.Arrays.copyOf(a, a.length + b.length);
            System.arraycopy(b, 0, joined, a.length, b.length);
            return joined;
        }), StandardCharsets.ISO_8859_1);
        return all.contains(new String(traceId, StandardCharsets.ISO_8859_1));
    }

    private void assertExportedLater(SpanData span, boolean expected) throws Exception {
        if (expected) {
            await().atMost(Duration.ofSeconds(15)).until(() -> exported(span));
            return;
        }
        // The span of a traced request that follows travels in the same batches; once that one is out, a withheld span would be too.
        SpanData later = requestSpan("http://localhost:" + port + "/mcp", null);
        await().atMost(Duration.ofSeconds(15)).until(() -> exported(later));
        assertThat(exported(span)).isFalse();
    }

    private double requests() {
        return meters.find("http.server.requests").timers().stream().mapToDouble(Timer::count).sum();
    }

    private String internal(String path) {
        return "https://localhost:" + env.internalPort + path;
    }

    private String publicUrl(String path) {
        return "http://localhost:" + port + path;
    }

    @Test
    void theHealthProbeOnTheInternalPortIsNotExportedButIsCountedByTheMetric() throws Exception {
        double before = requests();
        SpanData span = requestSpan(internal("/actuator/health"), env.bffTls);
        assertThat(span.getAttributes().get(PROBE)).isEqualTo("true");
        assertThat(meters.find("http.server.requests").tag("uri", "/actuator/health").timers()).isNotEmpty();
        await().atMost(Duration.ofSeconds(10)).until(() -> requests() > before);
        assertExportedLater(span, false);
    }

    @Test
    void aProbeThatBringsATraceparentIsNotExportedEither() throws Exception {
        String traceId = "0af7651916cd43dd8448eb211c80319c";
        int before = RecordedSpansConfiguration.spans().size();
        HttpClient.newBuilder().sslContext(env.bffTls).build().send(HttpRequest.newBuilder(URI.create(internal("/actuator/health")))
                .header("traceparent", "00-" + traceId + "-b7ad6b7169203331-01").GET().build(),
                java.net.http.HttpResponse.BodyHandlers.ofString());
        await().atMost(Duration.ofSeconds(10)).until(() -> serverSpansSince(before).size() >= 1);
        SpanData span = serverSpansSince(before).getFirst();
        assertThat(span.getTraceId()).isEqualTo(traceId);
        assertThat(span.getAttributes().get(PROBE)).isEqualTo("true");
        assertExportedLater(span, false);
    }

    @Test
    void aHealthPathOnThePublicPortLeavesNoSpanToExport() throws Exception {
        int before = RecordedSpansConfiguration.spans().size();
        for (String path : List.of("/actuator/health", "/actuator/health/liveness")) {
            HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI.create(publicUrl(path))).GET().build(),
                    java.net.http.HttpResponse.BodyHandlers.ofString());
        }
        Thread.sleep(1000);
        assertThat(serverSpansSince(before)).allSatisfy(span -> assertThat(span.getAttributes().get(PROBE)).isEqualTo("true"));
    }

    @Test
    void requestsOnTheSameRoutesAsAProbeThatAreNotProbesAreStillExported() throws Exception {
        for (String url : List.of(publicUrl("/mcp"), publicUrl("/s/x/mcp/actuator/health"), publicUrl("/.well-known/mcp-jwks.json"))) {
            SpanData span = requestSpan(url, null);
            assertThat(span.getAttributes().get(PROBE)).as(url).isNull();
            assertExportedLater(span, true);
        }
        SpanData jwks = requestSpan(internal("/.well-known/jwks.json"), env.bffTls);
        assertThat(jwks.getAttributes().get(PROBE)).isNull();
        assertExportedLater(jwks, true);
    }

    @Test
    void aNormalToolCallIsStillExported() throws Exception {
        assertThat(callGetIssue(aliceToken()).statusCode()).isEqualTo(200);
        SpanData span = RecordedSpansConfiguration.spans().stream().filter(s -> s.getKind() == SpanKind.SERVER)
                .reduce((first, second) -> second).orElseThrow();
        assertThat(span.getAttributes().get(PROBE)).isNull();
        assertExportedLater(span, true);
    }
}
