package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

import pl.aiwcorpo.mcp.gateway.support.BrokerStub;
import pl.aiwcorpo.mcp.gateway.support.RecordedSpansConfiguration;

class TracePropagationTest extends GatewayTestBase {

    private static final Pattern TRACEPARENT = Pattern.compile("^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$");
    private static final String CLIENT_TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736";
    private static final String CLIENT_SPAN_ID = "00f067aa0ba902b7";

    private HttpResponse<String> callWithTraceparent(String traceparent, Map<String, String> extra) throws Exception {
        Map<String, String> headers = new java.util.LinkedHashMap<>(extra);
        headers.put("MCP-Protocol-Version", "2026-07-28");
        headers.put("Mcp-Method", "tools/call");
        headers.put("Mcp-Name", "jira__get_issue");
        if (traceparent != null) {
            headers.put("traceparent", traceparent);
        }
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"jira__get_issue\","
                + "\"arguments\":{\"issueKey\":\"ABC-1\"},\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\","
                + "\"io.modelcontextprotocol/clientCapabilities\":{}}}}";
        return send(aliceToken(), "/s/mcp-jira/mcp", body, headers);
    }

    private static Matcher parsed(String traceparent) {
        assertThat(traceparent).isNotNull();
        Matcher matcher = TRACEPARENT.matcher(traceparent);
        assertThat(matcher.matches()).as(traceparent).isTrue();
        return matcher;
    }

    @Test
    void aPublicRequestStartsANewTraceAndTheClientsContextIsOnlyALink() throws Exception {
        HttpResponse<String> response = callWithTraceparent("00-" + CLIENT_TRACE_ID + "-" + CLIENT_SPAN_ID + "-01",
                Map.of("tracestate", "vendor=client-value", "baggage", "user=secret-user"));
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(toolError(response).isEmpty()).as(response.body()).isTrue();

        BrokerStub.Received resolve = env.broker.received().stream().filter(r -> r.path().equals("/v1/credentials/resolve"))
                .reduce((first, second) -> second).orElseThrow();
        Matcher atBroker = parsed(resolve.traceparent());
        var atServerRequest = lastToolCall(env.jira);
        Matcher atServer = parsed(atServerRequest.header("traceparent"));
        assertThat(atBroker.group(1)).isNotEqualTo(CLIENT_TRACE_ID);
        assertThat(atServer.group(1)).isEqualTo(atBroker.group(1)).isNotEqualTo(CLIENT_TRACE_ID);
        assertThat(resolve.tracestate()).isNull();
        assertThat(atServerRequest.header("tracestate")).isNull();
        assertThat(atServerRequest.header("baggage")).isNull();

        String gatewayTrace = atBroker.group(1);
        org.awaitility.Awaitility.await().atMost(java.time.Duration.ofSeconds(15)).untilAsserted(() -> assertThat(
                RecordedSpansConfiguration.spans().stream().anyMatch(span -> span.getTraceId().equals(gatewayTrace)
                        && span.getKind() == io.opentelemetry.api.trace.SpanKind.SERVER)).isTrue());
        var request = RecordedSpansConfiguration.spans().stream().filter(span -> span.getTraceId().equals(gatewayTrace)
                && span.getKind() == io.opentelemetry.api.trace.SpanKind.SERVER).findFirst().orElseThrow();
        assertThat(request.getParentSpanContext().isValid()).isFalse();
        assertThat(request.getLinks()).hasSize(1);
        assertThat(request.getLinks().getFirst().getSpanContext().getTraceId()).isEqualTo(CLIENT_TRACE_ID);
        assertThat(request.getLinks().getFirst().getSpanContext().getSpanId()).isEqualTo(CLIENT_SPAN_ID);
        assertThat(request.getSpanContext().getTraceState().isEmpty()).isTrue();
    }

    @Test
    void aClientSayingUnsampledDoesNotDecideWhetherThePublicRequestIsSampled() throws Exception {
        assertThat(callWithTraceparent("00-" + CLIENT_TRACE_ID + "-" + CLIENT_SPAN_ID + "-00", Map.of()).statusCode()).isEqualTo(200);
        BrokerStub.Received resolve = env.broker.received().stream().filter(r -> r.path().equals("/v1/credentials/resolve"))
                .reduce((first, second) -> second).orElseThrow();
        Matcher atBroker = parsed(resolve.traceparent());
        Matcher atServer = parsed(lastToolCall(env.jira).header("traceparent"));
        assertThat(atBroker.group(1)).isNotEqualTo(CLIENT_TRACE_ID);
        assertThat(atServer.group(1)).isEqualTo(atBroker.group(1));
        assertThat(Integer.parseInt(atBroker.group(3), 16) & 1).as("the sampler of the test context keeps every trace").isEqualTo(1);
    }

    @Test
    void aRequestOnTheInternalPortKeepsTheTraceOfItsCaller() throws Exception {
        String traceId = "0af7651916cd43dd8448eb211c80319c";
        String spanId = "b7ad6b7169203331";
        HttpRequest request = HttpRequest.newBuilder(URI.create("https://localhost:" + env.internalPort + "/actuator/health"))
                .header("traceparent", "00-" + traceId + "-" + spanId + "-01").GET().build();
        HttpResponse<String> response = HttpClient.newBuilder().sslContext(env.bffTls).build().send(request,
                HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(200);
        org.awaitility.Awaitility.await().atMost(java.time.Duration.ofSeconds(15)).untilAsserted(() -> assertThat(
                RecordedSpansConfiguration.spans().stream().anyMatch(span -> span.getTraceId().equals(traceId))).isTrue());
        var inherited = RecordedSpansConfiguration.spans().stream().filter(span -> span.getTraceId().equals(traceId)).findFirst()
                .orElseThrow();
        assertThat(inherited.getParentSpanId()).isEqualTo(spanId);
        assertThat(inherited.getLinks()).isEmpty();
    }

    @Test
    void aCallWithoutATraceparentStillStartsOneThatReachesTheServer() throws Exception {
        assertThat(callWithTraceparent(null, Map.of()).statusCode()).isEqualTo(200);
        Matcher atServer = parsed(lastToolCall(env.jira).header("traceparent"));
        assertThat(atServer.group(1)).isNotEqualTo(CLIENT_TRACE_ID);
    }

    @Test
    void aMalformedTraceparentIsNotForwarded() throws Exception {
        assertThat(callWithTraceparent("not-a-trace", Map.of()).statusCode()).isEqualTo(200);
        Matcher atServer = parsed(lastToolCall(env.jira).header("traceparent"));
        assertThat(atServer.group(1)).isNotEqualTo("not");
    }

    @Test
    void exportedSpansNameTheHopsAndHoldNoTokenOrArgument() throws Exception {
        String token = aliceToken();
        int before = env.collector.bodies().size();
        HttpResponse<String> response = send(token, "/s/mcp-jira/mcp", toolCallBody(), Map.of("MCP-Protocol-Version", "2026-07-28",
                "Mcp-Method", "tools/call", "Mcp-Name", "jira__get_issue",
                "traceparent", "00-" + CLIENT_TRACE_ID + "-" + CLIENT_SPAN_ID + "-01"));
        assertThat(response.statusCode()).isEqualTo(200);
        org.awaitility.Awaitility.await().atMost(java.time.Duration.ofSeconds(15)).untilAsserted(() -> {
            String exported = exportedSince(before);
            assertThat(exported).contains("mcp-credential-broker").contains("mcp-server");
        });
        String exported = exportedSince(before);
        assertThat(exported).doesNotContain(token).doesNotContain("ABC-1").doesNotContain("alice-pat")
                .doesNotContain("/s/mcp-jira/mcp");
    }

    private static String exportedSince(int before) {
        StringBuilder all = new StringBuilder();
        env.collector.bodies().stream().skip(before).forEach(b -> all.append(new String(b, java.nio.charset.StandardCharsets.ISO_8859_1)));
        return all.toString();
    }

    private static String toolCallBody() {
        return "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"jira__get_issue\","
                + "\"arguments\":{\"issueKey\":\"ABC-1\"},\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\","
                + "\"io.modelcontextprotocol/clientCapabilities\":{}}}}";
    }
}
