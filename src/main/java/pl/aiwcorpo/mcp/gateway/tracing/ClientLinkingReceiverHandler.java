package pl.aiwcorpo.mcp.gateway.tracing;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import io.micrometer.observation.transport.ReceiverContext;
import io.micrometer.tracing.Link;
import io.micrometer.tracing.Span;
import io.micrometer.tracing.TraceContext;
import io.micrometer.tracing.Tracer;
import io.micrometer.tracing.handler.PropagatingReceiverTracingObservationHandler;
import io.micrometer.tracing.propagation.Propagator;
import jakarta.servlet.http.HttpServletRequest;

/** Adds the span link to the client's context that {@link PublicEdgeTraceFilter} kept, when the request came in on the public port. */
public final class ClientLinkingReceiverHandler extends PropagatingReceiverTracingObservationHandler<ReceiverContext<?>> {

    private static final Pattern TRACEPARENT = Pattern.compile("^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$");

    public ClientLinkingReceiverHandler(Tracer tracer, Propagator propagator) {
        super(tracer, propagator);
    }

    @Override
    public Span.Builder customizeExtractedSpan(ReceiverContext<?> context, Span.Builder builder) {
        if (context.getCarrier() instanceof HttpServletRequest request
                && request.getAttribute(PublicEdgeTraceFilter.CLIENT_TRACEPARENT) instanceof String header) {
            Matcher parsed = TRACEPARENT.matcher(header.trim());
            boolean zero = parsed.matches() && (parsed.group(1).chars().allMatch(c -> c == '0') || parsed.group(2).chars().allMatch(c -> c == '0'));
            if (parsed.matches() && !zero) {
                TraceContext client = getTracer().traceContextBuilder().traceId(parsed.group(1)).spanId(parsed.group(2))
                        .sampled((Integer.parseInt(parsed.group(3), 16) & 1) == 1).build();
                return builder.addLink(new Link(client));
            }
        }
        return builder;
    }
}
