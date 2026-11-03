package pl.aiwcorpo.mcp.testserver;

import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

import com.networknt.schema.Schema;
import com.networknt.schema.SchemaLocation;
import com.networknt.schema.SchemaRegistry;
import com.networknt.schema.SpecificationVersion;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Receiver side of the internal JWT (C2, mcp-contracts 3.0.2) as an MCP server or the broker must implement
 * it. Rejection reasons are the ones used in {@code test-vectors/jwt}.
 */
public final class InternalJwtVerifier {

    public static final String SERVICE_SUBJECT = "system:mcp-gateway";
    private static final long CLOCK_SKEW_SECONDS = 30;
    private static final long MAX_LIFETIME_SECONDS = 60;
    private static final Schema CLAIMS_SCHEMA = SchemaRegistry.withDefaultDialect(SpecificationVersion.DRAFT_2020_12)
            .getSchema(SchemaLocation.of("classpath:mcp-contracts/schemas/internal-jwt.schema.json"));
    private static final JsonMapper JSON = JsonMapper.builder().build();

    /** What the receiving endpoint allows: the service variant and the {@code tool} claim. */
    public record RequestRule(boolean serviceAllowed, ToolRule toolRule, String toolName) {

        public static RequestRule forJsonRpc(String method, String toolName) {
            return switch (method) {
                case "tools/call" -> new RequestRule(false, ToolRule.EQUALS, toolName);
                case "initialize", "server/discover", "tools/list", "ping" -> new RequestRule(true, ToolRule.ABSENT, null);
                default -> new RequestRule(false, ToolRule.ABSENT, null);
            };
        }

        public static RequestRule forHttp(String method, String path) {
            if (("POST".equals(method) && ("/v1/credentials/resolve".equals(path) || "/v1/authenticator/verify".equals(path)
                    || "/v1/authenticator/invalidate-codes".equals(path)))
                    || ("GET".equals(method) && "/v1/authenticator".equals(path))) {
                return new RequestRule(false, ToolRule.REQUIRED, null);
            }
            boolean service = ("GET".equals(method) && ("/mcp-manifest".equals(path) || "/v1/systems".equals(path)));
            return new RequestRule(service, ToolRule.ABSENT, null);
        }
    }

    public enum ToolRule { ABSENT, REQUIRED, EQUALS }

    /** Verification outcome; {@code reason} is null when valid. */
    public record Result(String reason, Map<String, Object> claims) {
        public boolean valid() {
            return reason == null;
        }

        static Result reject(String reason) {
            return new Result(reason, Map.of());
        }
    }

    public interface KeySource {
        /** Key for {@code kid}; {@code null} when unknown even after a refresh. */
        JWK find(String kid);
    }

    private final String issuer;
    private final String audience;
    private final boolean allowTestKeys;
    private final boolean devstackProfile;
    private final KeySource keys;
    private final Clock clock;
    private final Map<String, Long> seenJtis = new ConcurrentHashMap<>();
    private volatile boolean adapterReceiver;

    public InternalJwtVerifier(String issuer, String audience, boolean allowTestKeys, KeySource keys, Clock clock) {
        this(issuer, audience, allowTestKeys, false, keys, clock);
    }

    /** {@code dev-} keys need both consents of dev mode: the devstack profile and {@code allowTestKeys} (CC-137). */
    public InternalJwtVerifier(String issuer, String audience, boolean allowTestKeys, boolean devstackProfile, KeySource keys,
                               Clock clock) {
        this.issuer = Objects.requireNonNull(issuer);
        this.audience = Objects.requireNonNull(audience);
        this.allowTestKeys = allowTestKeys;
        this.devstackProfile = devstackProfile;
        this.keys = Objects.requireNonNull(keys);
        this.clock = Objects.requireNonNull(clock);
    }

    /**
     * Only the sidecar of an adapter takes the claims {@code mcp_risk} and {@code mcp_action} (CC-226); a native server or the broker
     * rejects them as invalid_claims. An adapter wants both, as a pair that fits, with a tool, and refuses a call without them.
     */
    public InternalJwtVerifier asAdapterReceiver(boolean adapter) {
        this.adapterReceiver = adapter;
        return this;
    }

    private static boolean pairFits(String risk, String action) {
        return switch (risk) {
            case "READ_ONLY" -> "read".equals(action);
            case "UPDATE" -> "update".equals(action) || "admin".equals(action);
            case "DESTRUCTIVE" -> "delete".equals(action) || "admin".equals(action);
            default -> false;
        };
    }

    /** Marks a jti as already used (vectors with {@code seenJtis}). */
    public void markSeen(String jti, long expiresAtEpochSecond) {
        seenJtis.put(jti, expiresAtEpochSecond);
    }

    public Result verify(String authorization, String requestIdHeader, RequestRule rule) {
        if (authorization == null || !authorization.startsWith("Bearer ") || authorization.length() == 7) {
            return Result.reject("missing_token");
        }
        String token = authorization.substring(7).trim();
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3) {
            return Result.reject("malformed_token");
        }
        JsonNode header;
        try {
            header = JSON.readTree(Base64.getUrlDecoder().decode(parts[0]));
        } catch (RuntimeException e) {
            return Result.reject("malformed_token");
        }
        if (!"ES256".equals(header.path("alg").asString(null))) {
            return Result.reject("alg_not_allowed");
        }
        String kid = header.path("kid").asString(null);
        if (kid == null || kid.isEmpty()) {
            return Result.reject("unknown_kid");
        }
        if ((!allowTestKeys && kid.startsWith("test-")) || (!(allowTestKeys && devstackProfile) && kid.startsWith("dev-"))) {
            return Result.reject("test_key_not_allowed");
        }
        JWK key = keys.find(kid);
        if (!(key instanceof ECKey ecKey)) {
            return Result.reject("unknown_kid");
        }
        SignedJWT jwt;
        try {
            jwt = SignedJWT.parse(token);
            if (!jwt.verify(new ECDSAVerifier(ecKey.toECPublicKey()))) {
                return Result.reject("bad_signature");
            }
        } catch (ParseException | JOSEException | RuntimeException e) {
            return Result.reject("bad_signature");
        }

        JsonNode claims;
        try {
            claims = JSON.readTree(Base64.getUrlDecoder().decode(parts[1]));
        } catch (RuntimeException e) {
            return Result.reject("invalid_claims");
        }
        if (!CLAIMS_SCHEMA.validate(claims).isEmpty()) {
            return Result.reject("invalid_claims");
        }
        boolean risk = claims.has("mcp_risk");
        boolean action = claims.has("mcp_action");
        if (risk || action) {
            if (!adapterReceiver || !(risk && action) || !claims.has("tool") || !pairFits(claims.path("mcp_risk").asString(""), claims.path("mcp_action").asString(""))) {
                return Result.reject("invalid_claims");
            }
        }
        if (!issuer.equals(claims.path("iss").asString())) {
            return Result.reject("wrong_issuer");
        }
        if (!audience.equals(claims.path("aud").asString())) {
            return Result.reject("wrong_audience");
        }
        long now = Instant.now(clock).getEpochSecond();
        long iat = claims.path("iat").asLong();
        long exp = claims.path("exp").asLong();
        if (exp + CLOCK_SKEW_SECONDS < now) {
            return Result.reject("expired");
        }
        if (iat > now + CLOCK_SKEW_SECONDS) {
            return Result.reject("not_yet_valid");
        }
        if (exp - iat > MAX_LIFETIME_SECONDS) {
            return Result.reject("lifetime_too_long");
        }
        if (requestIdHeader == null || !requestIdHeader.equals(claims.path("rid").asString())) {
            return Result.reject("request_id_mismatch");
        }
        boolean service = SERVICE_SUBJECT.equals(claims.path("sub").asString());
        if (service && !rule.serviceAllowed()) {
            return Result.reject("service_token_not_allowed");
        }
        String tool = claims.has("tool") ? claims.get("tool").asString() : null;
        switch (rule.toolRule()) {
            case ABSENT -> {
                if (tool != null) {
                    return Result.reject("tool_not_allowed");
                }
            }
            case REQUIRED -> {
                if (tool == null) {
                    return Result.reject("tool_missing");
                }
            }
            case EQUALS -> {
                if (tool == null) {
                    return Result.reject("tool_missing");
                }
                if (!tool.equals(rule.toolName())) {
                    return Result.reject("tool_mismatch");
                }
            }
        }
        if (adapterReceiver && rule.toolRule() == ToolRule.EQUALS && !risk) {
            return Result.reject("classification_missing");
        }
        String jti = claims.path("jti").asString();
        seenJtis.values().removeIf(expiry -> expiry + CLOCK_SKEW_SECONDS < now);
        if (seenJtis.putIfAbsent(jti, exp) != null) {
            return Result.reject("replayed_jti");
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> claimMap = JSON.convertValue(claims, Map.class);
        return new Result(null, claimMap);
    }
}
