package pl.aiwcorpo.mcp.gateway.tracing;

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationFilter;

/**
 * Spring Boot records the literal request path as {@code http.url}. Paths here carry identifiers (a user's {@code sub}, a confirmation
 * id), so only the route template ({@code /s/{serverId}/mcp}, tag {@code uri}) stays on the span.
 */
public final class RequestUrlFilter implements ObservationFilter {

    @Override
    public Observation.Context map(Observation.Context context) {
        context.removeHighCardinalityKeyValue("http.url");
        return context;
    }
}
