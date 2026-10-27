package pl.aiwcorpo.mcp.gateway.support;

import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

import javax.net.ssl.SSLContext;

import org.springframework.test.context.DynamicPropertyRegistry;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.images.builder.Transferable;

import pl.aiwcorpo.mcp.testserver.JwksKeySource;
import pl.aiwcorpo.mcp.testserver.TestMcpServer;
import pl.aiwcorpo.mcp.testserver.Tls;

/**
 * Everything around the gateway under test, started once per JVM: internal CA and certificates, IdP stand-in,
 * broker stub, the test MCP server as mcp-jira, a second server with a certificate for the wrong name (as
 * mcp-confluence), and Redis with the ACL of mcp-platform-dev.
 */
public final class GatewayTestEnvironment {

    public static final String REDIS_GATEWAY_PASSWORD = "gateway-test-password";
    public static final String REDIS_ADMIN_PASSWORD = "admin-test-password";
    private static final String DATA_COMMANDS = "-@all +get +set +setnx +getdel +getex +mget +del +unlink +exists +expire "
            + "+pexpire +ttl +pttl +incr +incrby +decr +hset +hget +hdel +hgetall +hexists +hincrby +multi +exec +discard "
            + "+ping +auth +hello +client|setname +client|setinfo +reset +quit";

    private static GatewayTestEnvironment instance;

    public final Path dir;
    public final TestPki pki;
    public final Path gatewayKeystore;
    public final int internalPort;
    public final TestIdp idp;
    public final BrokerStub broker;
    public final TestMcpServer jira;
    public final TestMcpServer wrongName;
    public final GenericContainer<?> redis;
    public final SSLContext gatewayClientTls;

    public static synchronized GatewayTestEnvironment get() {
        if (instance == null) {
            try {
                instance = new GatewayTestEnvironment();
            } catch (Exception e) {
                throw new IllegalStateException("test environment", e);
            }
        }
        return instance;
    }

    private GatewayTestEnvironment() throws Exception {
        dir = Files.createTempDirectory("mcp-gateway-test");
        pki = new TestPki(dir);
        gatewayKeystore = pki.issue("gateway.p12", "mcp-gateway", List.of("mcp-gateway.internal", "localhost", "127.0.0.1"),
                true, true);
        Path jiraKeystore = pki.issue("jira.p12", "mcp-jira", List.of("mcp-jira.internal", "localhost"), true, false);
        Path wrongKeystore = pki.issue("wrong.p12", "mcp-confluence", List.of("mcp-jira.internal"), true, false);
        Path brokerKeystore = pki.issue("broker.p12", "mcp-credential-broker", List.of("mcp-credential-broker.internal"),
                true, false);
        try (ServerSocket socket = new ServerSocket(0)) {
            internalPort = socket.getLocalPort();
        }
        gatewayClientTls = Tls.fromPkcs12(gatewayKeystore, pki.truststore(), TestPki.PASSWORD);
        SSLContext trustOnly = Tls.fromKeyStores(null, TestPki.PASSWORD, load(pki.truststore()));
        JwksKeySource gatewayKeys = new JwksKeySource(
                URI.create("https://localhost:" + internalPort + "/.well-known/jwks.json"), trustOnly, Duration.ZERO);

        idp = new TestIdp();
        broker = new BrokerStub(Tls.fromPkcs12(brokerKeystore, pki.truststore(), TestPki.PASSWORD), gatewayKeys);
        jira = new TestMcpServer(new TestMcpServer.Config("mcp-jira", "/mcp", "https://mcp-gateway.internal", false, null,
                gatewayKeys), Tls.fromPkcs12(jiraKeystore, pki.truststore(), TestPki.PASSWORD),
                new InetSocketAddress("127.0.0.1", 0)).start();
        wrongName = new TestMcpServer(new TestMcpServer.Config("mcp-confluence", "/mcp", "https://mcp-gateway.internal",
                false, null, gatewayKeys), Tls.fromPkcs12(wrongKeystore, pki.truststore(), TestPki.PASSWORD),
                new InetSocketAddress("127.0.0.1", 0)).start();

        String acl = String.join("\n",
                "user default off resetkeys resetchannels -@all",
                "user admin on >" + REDIS_ADMIN_PASSWORD + " ~* &* +@all",
                "user gateway on >" + REDIS_GATEWAY_PASSWORD + " resetkeys ~gw:* resetchannels &credential.invalidated "
                        + DATA_COMMANDS + " +subscribe +unsubscribe",
                "");
        redis = new GenericContainer<>("redis:8.8.4-alpine")
                .withCopyToContainer(Transferable.of(acl), "/etc/redis-users.acl")
                .withCommand("redis-server", "--aclfile", "/etc/redis-users.acl", "--appendonly", "no")
                .withExposedPorts(6379);
        redis.start();
    }

    public void register(DynamicPropertyRegistry registry) {
        registry.add("gateway.oidc.issuer", () -> TestIdp.ISSUER);
        registry.add("gateway.oidc.jwks-uri", idp::jwksUri);
        registry.add("gateway.oidc.token-uri", idp::tokenUri);
        registry.add("gateway.oidc.client-id", () -> "mcp-gateway");
        registry.add("gateway.oidc.client-secret", () -> "test-client-secret");
        registry.add("gateway.internal-endpoint.port", () -> internalPort);
        registry.add("gateway.tls.keystore", gatewayKeystore::toString);
        registry.add("gateway.tls.truststore", () -> pki.truststore().toString());
        registry.add("gateway.tls.store-password", () -> new String(TestPki.PASSWORD));
        registry.add("gateway.broker.url", () -> "https://127.0.0.1:" + broker.port());
        registry.add("gateway.broker.tls-name", () -> "mcp-credential-broker.internal");
        registry.add("gateway.redis.host", redis::getHost);
        registry.add("gateway.redis.port", () -> redis.getMappedPort(6379));
        registry.add("gateway.redis.username", () -> "gateway");
        registry.add("gateway.redis.password", () -> REDIS_GATEWAY_PASSWORD);
        registry.add("spring.data.redis.host", redis::getHost);
        registry.add("spring.data.redis.port", () -> redis.getMappedPort(6379));
        registry.add("spring.data.redis.username", () -> "gateway");
        registry.add("spring.data.redis.password", () -> REDIS_GATEWAY_PASSWORD);
        registry.add("gateway.servers.mcp-jira.internal-url", () -> "https://127.0.0.1:" + jira.port() + "/mcp");
        registry.add("gateway.servers.mcp-jira.tools.delete_issue.risk", () -> "DESTRUCTIVE");
        registry.add("gateway.allowed-origins", () -> "https://allowed.test");
        registry.add("gateway.redis.health-interval", () -> "1s");
        registry.add("gateway.servers.mcp-confluence.system", () -> "confluence");
        registry.add("gateway.servers.mcp-confluence.internal-url", () -> "https://127.0.0.1:" + wrongName.port() + "/mcp");
        registry.add("gateway.servers.mcp-confluence.credential.required", () -> "false");
        registry.add("gateway.servers.mcp-confluence.tools.search_issues.risk", () -> "READ_ONLY");
    }

    private static java.security.KeyStore load(Path path) throws Exception {
        java.security.KeyStore store = java.security.KeyStore.getInstance("PKCS12");
        try (var in = Files.newInputStream(path)) {
            store.load(in, TestPki.PASSWORD);
        }
        return store;
    }
}
