package pl.aiwcorpo.mcp.gateway.setup;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.ConnectException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.SSLHandshakeException;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.nimbusds.jose.jwk.JWKSet;

import pl.aiwcorpo.mcp.gateway.jwt.SigningKeys;

/** First-start generation is done once and kept; what cannot be generated is reported with its cause. */
class GatewaySetupTest {

    @TempDir
    Path dir;

    private final ByteArrayOutputStream output = new ByteArrayOutputStream();

    private GatewaySetup setup(Map<String, String> env) {
        return new GatewaySetup(env, dir, new PrintStream(output, true, StandardCharsets.UTF_8));
    }

    @Test
    void generatesWhatTheOperatorDidNotSetAndKeepsItOnTheNextRun() throws Exception {
        setup(Map.of()).generate();
        Path env = dir.resolve("gateway/env");
        String dbPassword = Files.readString(env.resolve("MCP_DB_PASSWORD"));
        String redisPassword = Files.readString(env.resolve("MCP_REDIS_PASSWORD"));
        String kid = Files.readString(env.resolve("MCP_INTERNAL_JWT_ACTIVE_KID"));

        assertThat(dbPassword).hasSizeGreaterThanOrEqualTo(43);
        assertThat(Files.readString(dir.resolve("postgres/password"))).isEqualTo(dbPassword);
        assertThat(Files.readString(dir.resolve("redis/users.acl")))
                .startsWith("user default off")
                .contains("user gateway on #" + GatewaySetup.sha256(redisPassword) + " resetkeys ~gw:*")
                .doesNotContain(redisPassword)
                .contains("user replication on #");
        String replication = Files.readString(dir.resolve("redis/replication-password"));
        assertThat(Files.readString(dir.resolve("redis/replica.conf"))).contains("masteruser replication\nmasterauth " + replication);
        assertThat(Files.readString(dir.resolve("redis/users.acl"))).doesNotContain(replication);
        assertThat(Files.getPosixFilePermissions(dir.resolve("redis/users.acl"))).isEqualTo(PosixFilePermissions.fromString("rw-r-----"));
        assertThat(Files.getPosixFilePermissions(dir.resolve("postgres/password"))).isEqualTo(PosixFilePermissions.fromString("rw-r-----"));
        assertThat(Files.getPosixFilePermissions(dir.resolve("redis"))).isEqualTo(PosixFilePermissions.fromString("rwxr-x---"));
        try (var left = Files.list(env)) {
            assertThat(left).noneMatch(f -> f.getFileName().toString().startsWith("."));
        }
        assertThat(Files.readString(dir.resolve("redis/primary.conf"))).contains("maxmemory-policy noeviction").doesNotContain(replication);
        assertThat(Files.readString(env.resolve("MCP_INTERNAL_JWT_KEYS_FILE"))).isEqualTo(dir.resolve("gateway/internal-jwt.jwks").toString());
        // The file is what the gateway loads at start.
        SigningKeys keys = SigningKeys.load(dir.resolve("gateway/internal-jwt.jwks").toString(), kid, false, false);
        assertThat(keys.publicJwks().getKeys()).hasSize(2);
        assertThat(JWKSet.load(dir.resolve("gateway/internal-jwt.jwks").toFile()).getKeys().getFirst().isPrivate()).isTrue();
        assertThat(Files.getPosixFilePermissions(dir.resolve("gateway"))).isEqualTo(PosixFilePermissions.fromString("rwx------"));
        assertThat(Files.getPosixFilePermissions(env.resolve("MCP_DB_PASSWORD"))).isEqualTo(PosixFilePermissions.fromString("rw-------"));

        String jwks = Files.readString(dir.resolve("gateway/internal-jwt.jwks"));
        setup(Map.of()).generate();
        assertThat(Files.readString(env.resolve("MCP_DB_PASSWORD"))).isEqualTo(dbPassword);
        assertThat(Files.readString(env.resolve("MCP_REDIS_PASSWORD"))).isEqualTo(redisPassword);
        assertThat(Files.readString(dir.resolve("redis/replication-password"))).isEqualTo(replication);
        assertThat(Files.readString(dir.resolve("gateway/internal-jwt.jwks"))).isEqualTo(jwks);
    }

    @Test
    void sha256IsTheHexDigestRedisExpects() {
        assertThat(GatewaySetup.sha256("abc")).isEqualTo("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    @Test
    void leavesAloneWhatTheOperatorSet() throws Exception {
        setup(Map.of("MCP_DB_PASSWORD", "own", "MCP_REDIS_PASSWORD", "own", "MCP_INTERNAL_JWT_KEYS_FILE", "/etc/keys.jwks")).generate();

        assertThat(dir.resolve("gateway/env/MCP_DB_PASSWORD")).doesNotExist();
        assertThat(dir.resolve("postgres")).doesNotExist();
        assertThat(dir.resolve("redis")).doesNotExist();
        assertThat(dir.resolve("gateway/internal-jwt.jwks")).doesNotExist();
        assertThat(dir.resolve("gateway/env/MCP_LIST_CURSOR_KEY")).exists();
    }

    @Test
    void namesEveryMissingSettingAndFails() {
        int exit = setup(Map.of("MCP_PUBLIC_URL", "https://mcp.aiwcorpo.pl")).run();

        assertThat(exit).isEqualTo(1);
        assertThat(output.toString(StandardCharsets.UTF_8))
                .contains("FAIL  not set: MCP_OIDC_ISSUER, MCP_OIDC_JWKS_URI, MCP_DB_URL")
                .doesNotContain("MCP_PUBLIC_URL,");
    }

    @Test
    void reportsMissingCertificateFilesAndTheIdentityProvider() {
        Map<String, String> env = new HashMap<>();
        GatewaySetup.REQUIRED.forEach(name -> env.put(name, "https://unused.invalid"));
        env.put("MCP_REDIS_WAIT_REPLICAS", "1");
        env.put("MCP_TLS_KEYSTORE", dir.resolve("missing.p12").toString());
        env.put("MCP_OIDC_JWKS_URI", "https://127.0.0.1:1/certs");

        int exit = setup(env).run();

        assertThat(exit).isEqualTo(1);
        assertThat(output.toString(StandardCharsets.UTF_8))
                .contains("FAIL  certificate file " + dir.resolve("missing.p12") + " does not exist")
                .contains("FAIL  identity provider keys https://127.0.0.1:1/certs: connection refused")
                .doesNotContain("MCP_REDIS_WAIT_REPLICAS");
    }

    @Test
    void doesNotAskForTheServersOrThePolicyKeysThatAreNoLongerSettings() {
        Map<String, String> env = new HashMap<>();
        GatewaySetup.REQUIRED.forEach(name -> env.put(name, "https://unused.invalid"));
        env.put("MCP_REDIS_WAIT_REPLICAS", "1");
        env.put("MCP_TLS_KEYSTORE", dir.resolve("missing.p12").toString());
        env.put("MCP_SERVER_JIRA_MCP_URL", "https://127.0.0.1:1/mcp");
        env.put("MCP_POLICY_MAIN_URL", "https://127.0.0.1:1/policies/main");

        setup(env).run();

        assertThat(GatewaySetup.REQUIRED).noneMatch(name -> name.startsWith("MCP_POLICY_"));
        assertThat(output.toString(StandardCharsets.UTF_8)).doesNotContain("mcp-jira").doesNotContain("policy");
    }

    @Test
    void anAllowedClientThatIsNoClientIdFailsTheCheck() {
        Map<String, String> env = new HashMap<>();
        GatewaySetup.REQUIRED.forEach(name -> env.put(name, "https://127.0.0.1:1/unused"));
        env.put("MCP_TLS_KEYSTORE", dir.resolve("missing.p12").toString());
        env.put("MCP_ALLOWED_CLIENTS", "claude-code, bad client");

        setup(env).run();

        assertThat(output.toString(StandardCharsets.UTF_8)).contains("FAIL  MCP_ALLOWED_CLIENTS claude-code, bad client must be client ids");
    }

    @Test
    void theBundleOfCasForTheServersIsOptionalAndWhenNamedMustBeAPemFileOfCertificates() throws Exception {
        Map<String, String> env = new HashMap<>();
        GatewaySetup.REQUIRED.forEach(name -> env.put(name, "https://127.0.0.1:1/unused"));
        env.put("MCP_TLS_KEYSTORE", dir.resolve("missing.p12").toString());

        setup(env).run();
        assertThat(output.toString(StandardCharsets.UTF_8)).contains("ok    MCP server trust: the default trust store of the JVM (MCP_SERVER_TRUSTED_CAS not set)");

        output.reset();
        env.put("MCP_SERVER_TRUSTED_CAS", dir.resolve("none.pem").toString());
        setup(env).run();
        assertThat(output.toString(StandardCharsets.UTF_8)).contains("FAIL  MCP_SERVER_TRUSTED_CAS " + dir.resolve("none.pem") + " does not exist");

        output.reset();
        Path text = dir.resolve("text.pem");
        Files.writeString(text, "not a certificate\n");
        env.put("MCP_SERVER_TRUSTED_CAS", text.toString());
        setup(env).run();
        assertThat(output.toString(StandardCharsets.UTF_8)).contains("FAIL  MCP_SERVER_TRUSTED_CAS " + text + " holds no CA certificate");

        output.reset();
        env.put("MCP_SERVER_TRUSTED_CAS", pl.aiwcorpo.mcp.gateway.support.GatewayTestEnvironment.get().serverCas.toString());
        setup(env).run();
        assertThat(output.toString(StandardCharsets.UTF_8)).contains("ok    MCP server trust: the default trust store of the JVM and the CAs in");
    }

    @Test
    void namesTheStorePasswordWhenItIsWrong() throws Exception {
        Path store = dir.resolve("store.p12");
        java.security.KeyStore empty = java.security.KeyStore.getInstance("PKCS12");
        empty.load(null, null);
        try (var out = Files.newOutputStream(store)) {
            empty.store(out, "right".toCharArray());
        }
        Map<String, String> env = new HashMap<>();
        GatewaySetup.REQUIRED.forEach(name -> env.put(name, "https://127.0.0.1:1/unused"));
        env.put("MCP_TLS_KEYSTORE", store.toString());
        env.put("MCP_TLS_TRUSTSTORE", store.toString());
        env.put("MCP_TLS_STORE_PASSWORD", "wrong");

        setup(env).run();

        assertThat(output.toString(StandardCharsets.UTF_8)).contains("wrong MCP_TLS_STORE_PASSWORD");
    }

    @Test
    void translatesConnectionErrorsIntoLikelyCauses() {
        assertThat(GatewaySetup.cause(new java.io.IOException(new UnknownHostException("idp.corp")), null)).contains("does not resolve");
        assertThat(GatewaySetup.cause(new ConnectException(), null)).contains("connection refused");
        ConnectException unresolved = new ConnectException();
        unresolved.initCause(new java.nio.channels.UnresolvedAddressException());
        assertThat(GatewaySetup.cause(unresolved, null)).contains("does not resolve");
        SSLHandshakeException pkix = new SSLHandshakeException("PKIX path building failed");
        assertThat(GatewaySetup.cause(pkix, null)).contains("JAVA_TOOL_OPTIONS");
        assertThat(GatewaySetup.cause(pkix, "mcp-jira.internal")).contains("MCP_TLS_TRUSTSTORE");
        SSLHandshakeException name = new SSLHandshakeException("handshake");
        name.initCause(new CertificateException("server certificate has no DNS SAN mcp-jira.internal"));
        assertThat(GatewaySetup.cause(name, "mcp-jira.internal")).isEqualTo("its certificate does not name mcp-jira.internal in subjectAltName");
    }
}
