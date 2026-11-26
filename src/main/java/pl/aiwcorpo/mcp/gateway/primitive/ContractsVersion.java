package pl.aiwcorpo.mcp.gateway.primitive;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The condition under which the gateway sends a receiver the claims that 8.0.0 added (CC-260): the contractsVersion of the approved manifest
 * of a server, or the version of the broker an operator confirmed, is at least 8.0.0. Absent and malformed values do not qualify, and a
 * pre-release of 8.0.0 is older than 8.0.0 (SemVer), so a receiver that only has a release candidate is not sent a claim it may reject.
 */
public final class ContractsVersion {

    public static final String MINIMUM = "8.0.0";

    private static final Pattern SEMVER = Pattern.compile("^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\\+[0-9A-Za-z.-]+)?$");
    private static final long[] MINIMUM_PARTS = {8, 0, 0};

    private ContractsVersion() {
    }

    /** True when {@code version} is a well-formed SemVer that is not older than {@link #MINIMUM}. */
    public static boolean supportsNewClaims(String version) {
        if (version == null) {
            return false;
        }
        Matcher parsed = SEMVER.matcher(version);
        if (!parsed.matches()) {
            return false;
        }
        for (int i = 0; i < MINIMUM_PARTS.length; i++) {
            long part;
            try {
                part = Long.parseLong(parsed.group(i + 1));
            } catch (NumberFormatException e) {
                return true;
            }
            if (part != MINIMUM_PARTS[i]) {
                return part > MINIMUM_PARTS[i];
            }
        }
        return parsed.group(4) == null;
    }
}
