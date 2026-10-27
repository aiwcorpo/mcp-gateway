package pl.aiwcorpo.mcp.gateway.authz;

import java.util.List;

/** Allow or deny of one tool for one user; {@code reason} uses the C8 vocabulary. */
public record ToolDecision(boolean allowed, String reason, List<String> requiredEntitlements) {

    public static ToolDecision allow() {
        return new ToolDecision(true, null, List.of());
    }

    public static ToolDecision deny(String reason, List<String> requiredEntitlements) {
        return new ToolDecision(false, reason, List.copyOf(requiredEntitlements));
    }
}
