package pl.aiwcorpo.mcp.gateway.support;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

import io.opentelemetry.context.Context;
import io.opentelemetry.sdk.trace.ReadWriteSpan;
import io.opentelemetry.sdk.trace.ReadableSpan;
import io.opentelemetry.sdk.trace.SpanProcessor;
import io.opentelemetry.sdk.trace.data.SpanData;

/** Keeps the spans the gateway exports, so a test can read their parents, links and attributes. */
@TestConfiguration
public class RecordedSpansConfiguration {

    private static final List<SpanData> SPANS = new CopyOnWriteArrayList<>();

    public static List<SpanData> spans() {
        return List.copyOf(SPANS);
    }

    @Bean
    SpanProcessor recordingSpanProcessor() {
        return new SpanProcessor() {
            @Override
            public void onStart(Context parentContext, ReadWriteSpan span) {
            }

            @Override
            public boolean isStartRequired() {
                return false;
            }

            @Override
            public void onEnd(ReadableSpan span) {
                SPANS.add(span.toSpanData());
            }

            @Override
            public boolean isEndRequired() {
                return true;
            }
        };
    }
}
