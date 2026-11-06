package pl.aiwcorpo.mcp.gateway.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.SignedJWT;

import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.support.Contracts;
import pl.aiwcorpo.mcp.testserver.InternalJwtVerifier;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

class InternalTokenIssuerTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private final SigningKeys keys = SigningKeys.load(null, null, false, false);
    private final InternalTokenIssuer issuer = new InternalTokenIssuer(keys, "https://mcp-gateway.internal",
            Duration.ofSeconds(30), () -> 42L, Clock.systemUTC());
    private final GatewayUser alice = new GatewayUser("6f1c2a9e-4d4b-4c51-9a53-1e0f0c7d2b11", "alice", "claude-code",
            List.of("mcp-jira-read", "/mcp-jira-write", "admins", "mcp-jira-read"), "raw");

    @Test
    void userVariantMatchesTheContractSchemaAndTheReceiver() throws Exception {
        String rid = UuidV7.next();
        String token = issuer.forUser("mcp-jira", alice, "get_issue", rid);
        JsonNode claims = claims(token);
        assertThat(Contracts.schemaErrors("schemas/internal-jwt.schema.json", claims)).isEmpty();
        assertThat(claims.path("aud").isString()).isTrue();
        assertThat(claims.path("grp").toString()).isEqualTo("[\"mcp-jira-read\"]");
        assertThat(claims.path("exp").asLong() - claims.path("iat").asLong()).isLessThanOrEqualTo(60);
        assertThat(SignedJWT.parse(token).getHeader().getKeyID()).doesNotStartWith("test-");

        InternalJwtVerifier receiver = receiver("mcp-jira");
        assertThat(receiver.verify("Bearer " + token, rid, InternalJwtVerifier.RequestRule.forJsonRpc("tools/call", "get_issue"))
                .reason()).isNull();
        assertThat(receiver("mcp-jira").verify("Bearer " + token, rid,
                InternalJwtVerifier.RequestRule.forJsonRpc("tools/call", "delete_issue")).reason()).isEqualTo("tool_mismatch");
    }

    @Test
    void theClassificationOfAnAdapterToolTravelsAsAPairThatFitsAndOnlyWithATool() throws Exception {
        String rid = UuidV7.next();
        String token = issuer.forUser("mcp-opensearch", alice, "get_issue", rid, "READ_ONLY", "read");
        JsonNode claims = claims(token);
        assertThat(claims.path("mcp_risk").asString()).isEqualTo("READ_ONLY");
        assertThat(claims.path("mcp_action").asString()).isEqualTo("read");
        assertThat(Contracts.schemaErrors("schemas/internal-jwt.schema.json", claims)).isEmpty();
        assertThat(receiver("mcp-opensearch").asAdapterReceiver(true).verify("Bearer " + token, rid,
                InternalJwtVerifier.RequestRule.forJsonRpc("tools/call", "get_issue")).reason()).isNull();
        assertThat(receiver("mcp-opensearch").verify("Bearer " + token, rid,
                InternalJwtVerifier.RequestRule.forJsonRpc("tools/call", "get_issue")).reason())
                .as("a native server or the broker refuses them").isEqualTo("invalid_claims");

        for (String[] left : new String[][] {{"READ_ONLY", "delete"}, {"UPDATE", "read"}, {"READ_ONLY", null}, {null, "read"}, {"BOGUS", "read"}}) {
            JsonNode without = claims(issuer.forUser("mcp-opensearch", alice, "get_issue", UuidV7.next(), left[0], left[1]));
            assertThat(without.has("mcp_risk") || without.has("mcp_action")).as(java.util.Arrays.toString(left)).isFalse();
        }
        JsonNode noTool = claims(issuer.forUser("mcp-opensearch", alice, null, UuidV7.next(), "READ_ONLY", "read"));
        assertThat(noTool.has("mcp_risk") || noTool.has("mcp_action") || noTool.has("tool")).isFalse();
        JsonNode plain = claims(issuer.forUser("mcp-jira", alice, "get_issue", UuidV7.next()));
        assertThat(plain.has("mcp_risk")).isFalse();
    }

    @Test
    void noTokenCarriesTheRemovedLinkClaims() throws Exception {
        String rid = UuidV7.next();
        JsonNode claims = claims(issuer.forUser("mcp-jira", alice, "get_issue", rid));
        assertThat(claims.has("vs")).isFalse();
        assertThat(claims.has("vsc")).isFalse();
        assertThat(Contracts.schemaErrors("schemas/internal-jwt.schema.json", claims)).isEmpty();
    }

    @Test
    void withoutToolForProtocolMethodsAndServiceVariantOnlyWhereAllowed() throws Exception {
        String rid = UuidV7.next();
        String list = issuer.forUser("mcp-jira", alice, null, rid);
        assertThat(claims(list).has("tool")).isFalse();
        assertThat(receiver("mcp-jira").verify("Bearer " + list, rid, InternalJwtVerifier.RequestRule.forJsonRpc("tools/list", null))
                .reason()).isNull();

        String service = issuer.forService("mcp-credential-broker", rid);
        assertThat(Contracts.schemaErrors("schemas/internal-jwt.schema.json", claims(service))).isEmpty();
        assertThat(receiver("mcp-credential-broker").verify("Bearer " + service, rid,
                InternalJwtVerifier.RequestRule.forHttp("GET", "/v1/systems")).reason()).isNull();
        assertThat(receiver("mcp-credential-broker").verify("Bearer " + service, rid,
                InternalJwtVerifier.RequestRule.forHttp("POST", "/v1/credentials/resolve")).reason())
                .isEqualTo("service_token_not_allowed");
    }

    @Test
    void everyTokenHasItsOwnJti() throws Exception {
        String rid = UuidV7.next();
        assertThat(claims(issuer.forUser("mcp-jira", alice, null, rid)).path("jti"))
                .isNotEqualTo(claims(issuer.forUser("mcp-jira", alice, null, rid)).path("jti"));
    }

    @Test
    void publishesTwoKeysWithoutPrivateParts() {
        JWKSet published = keys.publicJwks();
        assertThat(published.getKeys()).hasSize(2);
        assertThat(published.getKeys()).noneMatch(k -> k.isPrivate());
        assertThat(published.getKeys()).allSatisfy(k -> assertThat(k.getKeyID()).startsWith("gw-"));
    }

    @Test
    void refusesTestKeysOutsideTests(@TempDir Path dir) throws Exception {
        Path published = dir.resolve("keys.json");
        String a = resource("mcp-contracts/test-vectors/keys/test-gateway-jwt-a.NOT-FOR-PRODUCTION.private.jwk.json");
        Files.writeString(published, "{\"keys\":[" + a + "]}");
        assertThatThrownBy(() -> SigningKeys.load(published.toString(), "test-gw-2026-10-a", false, false))
                .hasMessageContaining("test-");

        String renamed = a.replace("test-gw-2026-10-a", "prod-2026-10-a");
        Files.writeString(published, "{\"keys\":[" + renamed + "]}");
        assertThatThrownBy(() -> SigningKeys.load(published.toString(), "prod-2026-10-a", false, false))
                .hasMessageContaining("published mcp-contracts test key");
        assertThat(SigningKeys.load(published.toString(), "prod-2026-10-a", true, false).active().getKeyID()).isEqualTo("prod-2026-10-a");
    }

    @Test
    void devKeysNeedTheDevstackProfileAndTheTestKeySetting(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("keys.json");
        String a = resource("mcp-contracts/test-vectors/keys/test-gateway-jwt-a.NOT-FOR-PRODUCTION.private.jwk.json");
        Files.writeString(file, "{\"keys\":[" + a.replace("test-gw-2026-10-a", "dev-gw-2026-10-a") + "]}");
        assertThatThrownBy(() -> SigningKeys.load(file.toString(), "dev-gw-2026-10-a", false, false)).hasMessageContaining("dev-");
        assertThatThrownBy(() -> SigningKeys.load(file.toString(), "dev-gw-2026-10-a", true, false)).hasMessageContaining("dev mode");
        assertThatThrownBy(() -> SigningKeys.load(file.toString(), "dev-gw-2026-10-a", false, true)).hasMessageContaining("dev mode");
        assertThat(SigningKeys.load(file.toString(), "dev-gw-2026-10-a", true, true).active().getKeyID())
                .isEqualTo("dev-gw-2026-10-a");
    }

    @Test
    void lifetimeAboveSixtySecondsIsRefused() {
        assertThatThrownBy(() -> new InternalTokenIssuer(keys, "https://mcp-gateway.internal", Duration.ofSeconds(61),
                () -> 42L, Clock.systemUTC())).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void uuidV7Format() {
        assertThat(UuidV7.next()).matches("^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$");
    }

    private InternalJwtVerifier receiver(String audience) {
        return new InternalJwtVerifier("https://mcp-gateway.internal", audience, false, keys.publicJwks()::getKeyByKeyId,
                Clock.systemUTC());
    }

    private static JsonNode claims(String token) {
        return JSON.readTree(Base64.getUrlDecoder().decode(token.split("\\.")[1]));
    }

    private static String resource(String path) throws Exception {
        try (var in = InternalTokenIssuerTest.class.getClassLoader().getResourceAsStream(path)) {
            return new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        }
    }
}
