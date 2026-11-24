package pl.aiwcorpo.mcp.gateway.tracing;

import java.net.http.HttpClient;

import io.micrometer.tracing.Tracer;
import io.micrometer.tracing.propagation.Propagator;

/** Wraps the HTTP clients of the hops the gateway makes on behalf of a request; with tracing off the tracer is a no-op and nothing is added. */
public final class OutboundTracing {

    public static final String BROKER = "mcp-credential-broker";
    public static final String MCP_SERVER = "mcp-server";

    private final Tracer tracer;
    private final Propagator propagator;

    public OutboundTracing(Tracer tracer, Propagator propagator) {
        this.tracer = tracer;
        this.propagator = propagator;
    }

    public HttpClient wrap(HttpClient client, String peer) {
        return new TracingHttpClient(client, tracer, propagator, peer);
    }
}
