package pl.aiwcorpo.mcp.gateway.policy;

import java.time.Instant;

/** One emergency override (C5 {@code Override}): one forbid policy and where it applies; {@code target} is gateway, all-servers or a serverId. */
public record PolicyOverride(String id, String target, String text, String setBy, Instant setAt) {

    public static final String GATEWAY = "gateway";
    public static final String ALL_SERVERS = "all-servers";
}
