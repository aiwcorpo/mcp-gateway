package pl.aiwcorpo.mcp.gateway.mcp;

import java.util.List;

/**
 * Protocol versions the gateway serves to clients. Modern (2026-07-28): per-request {@code _meta}, no
 * initialize and no sessions. Legacy (2025-03-26 .. 2025-11-25): initialize and Mcp-Session-Id.
 */
public final class ProtocolVersions {

    public static final String MODERN = "2026-07-28";
    public static final List<String> MODERN_VERSIONS = List.of(MODERN);
    public static final List<String> LEGACY_VERSIONS = List.of("2025-11-25", "2025-06-18", "2025-03-26");
    /** A request without MCP-Protocol-Version and without other means is 2025-03-26 (2025-06-18 transport). */
    public static final String LEGACY_DEFAULT = "2025-03-26";
    public static final List<String> ALL = List.of(MODERN, "2025-11-25", "2025-06-18", "2025-03-26");

    private ProtocolVersions() {
    }

    public static String negotiateLegacy(String requested) {
        return LEGACY_VERSIONS.contains(requested) ? requested : LEGACY_VERSIONS.getFirst();
    }

    public static boolean isModern(String version) {
        return MODERN_VERSIONS.contains(version);
    }
}
