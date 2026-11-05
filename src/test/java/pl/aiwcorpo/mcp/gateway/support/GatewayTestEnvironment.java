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
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.Transferable;

import pl.aiwcorpo.mcp.testserver.JwksKeySource;
import pl.aiwcorpo.mcp.testserver.TestMcpServer;
import pl.aiwcorpo.mcp.testserver.Tls;

/**
 * Everything around the gateway under test, started once per JVM: internal CA and certificates (gateway, BFF, a
 * component of another name, a certificate of a foreign CA), IdP stand-in, broker stub, the test MCP server as
 * mcp-jira and as mcp-gitlab, a server with a certificate for the wrong name (as mcp-confluence), Redis with the
 * ACL of the dev stack and PostgreSQL for the links.
 */
public final class GatewayTestEnvironment {

    public static final String REDIS_GATEWAY_PASSWORD = "gateway-test-password";
    public static final String REDIS_ADMIN_PASSWORD = "admin-test-password";
    public static final String POSTGRES_PASSWORD = "gateway-db-test-password";
    /** publicBaseUrl in tests; no request to the gateway ever carries this host. */
    public static final String PUBLIC_URL = "https://mcp.aiwcorpo.pl";
    /** The command list of the gateway's ACL in the dev stack (redis/gateway.rules, ws-01). */
    private static final String DATA_COMMANDS = "-@all +get +set +setnx +setex +psetex +getdel +getex +mget +del +unlink "
            + "+exists +expire +pexpire +expireat +pexpireat +persist +ttl +pttl +incr +incrby +decr +decrby +hset +hsetnx "
            + "+hget +hmget +hdel +hgetall +hexists +hincrby +hlen +sadd +srem +scard +sismember +smembers +zadd +zrem +zcard "
            + "+zscore +zcount +zrange +zrangebyscore +zremrangebyscore +multi +exec +discard +watch +unwatch +eval +evalsha "
            + "+wait +ping +auth +hello +client|setname +client|setinfo +reset +quit";

    private static GatewayTestEnvironment instance;

    public final Path dir;
    public final TestPki pki;
    public final Path gatewayKeystore;
    public final int internalPort;
    public final TestIdp idp;
    public final BrokerStub broker;
    public final TestMcpServer jira;
    public final TestMcpServer gitlab;
    public final TestMcpServer wrongName;
    /** The foreign server behind an adapter: mcp-opensearch in adapter mode (the test server stands in for the foreign one). */
    public final TestMcpServer opensearch;
    public final PolicyServer policies;
    public final Path policyKeys;
    public final Path policyState;
    public final GenericContainer<?> redis;
    public final GenericContainer<?> postgres;
    public final SSLContext gatewayClientTls;
    /** Client TLS identities for the admin API: the BFF, another component of the internal CA, a foreign CA. */
    public final SSLContext bffTls;
    public final SSLContext otherComponentTls;
    public final SSLContext foreignCaTls;
    public final SSLContext noClientCertificateTls;
    /** The Prometheus scraper: a client certificate whose name is listed in gateway.metrics.allowed-client-cns. */
    public final SSLContext scraperTls;
    /** A server identity of the internal CA (mcp-jira, serverAuth only), as servers use when they fetch the JWKS. */
    public final SSLContext serverIdentityTls;
    /** Pipelines of the registry (CC-161): one certificate per server, and the former shared name, which is refused. */
    public final SSLContext ciGitlabTls;
    public final SSLContext ciJiraTls;
    public final SSLContext sharedCiTls;
    /** The offboarding process (CC-155). */
    public final SSLContext offboardingTls;
    /** Adapters (CC-206): one certificate per server, mcp-adapter-<serverId>; and the pipeline of the adapter server, which may not use that channel. */
    public final SSLContext adapterOpensearchTls;
    public final SSLContext adapterJiraTls;
    public final SSLContext adapterGitlabTls;
    public final SSLContext ciOpensearchTls;

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
        Path gitlabKeystore = pki.issue("gitlab.p12", "mcp-gitlab", List.of("mcp-gitlab.internal", "localhost"), true, false);
        Path wrongKeystore = pki.issue("wrong.p12", "mcp-confluence", List.of("mcp-jira.internal"), true, false);
        Path bffKeystore = pki.issue("bff.p12", "mcp-portal-bff", List.of(), false, true);
        Path scraperKeystore = pki.issue("scraper.p12", "mcp-prometheus", List.of(), false, true);
        Path ciKeystore = pki.issue("ci.p12", "mcp-registry-ci", List.of(), false, true);
        Path ciGitlabKeystore = pki.issue("ci-gitlab.p12", "mcp-registry-ci-mcp-gitlab", List.of(), false, true);
        Path ciJiraKeystore = pki.issue("ci-jira.p12", "mcp-registry-ci-mcp-jira", List.of(), false, true);
        Path opensearchKeystore = pki.issue("opensearch.p12", "mcp-opensearch", List.of("mcp-opensearch.internal", "localhost"), true, false);
        Path adapterOpensearchKeystore = pki.issue("adapter-opensearch.p12", "mcp-adapter-mcp-opensearch", List.of(), false, true);
        Path adapterJiraKeystore = pki.issue("adapter-jira.p12", "mcp-adapter-mcp-jira", List.of(), false, true);
        Path adapterGitlabKeystore = pki.issue("adapter-gitlab.p12", "mcp-adapter-mcp-gitlab", List.of(), false, true);
        Path ciOpensearchKeystore = pki.issue("ci-opensearch.p12", "mcp-registry-ci-mcp-opensearch", List.of(), false, true);
        Path offboardingKeystore = pki.issue("offboarding.p12", "mcp-offboarding", List.of(), false, true);
        TestPki foreign = new TestPki(Files.createDirectory(dir.resolve("foreign")));
        Path foreignKeystore = foreign.issue("bff.p12", "mcp-portal-bff", List.of(), false, true);
        Path brokerKeystore = pki.issue("broker.p12", "mcp-credential-broker", List.of("mcp-credential-broker.internal"),
                true, false);
        try (ServerSocket socket = new ServerSocket(0)) {
            internalPort = socket.getLocalPort();
        }
        gatewayClientTls = Tls.fromPkcs12(gatewayKeystore, pki.truststore(), TestPki.PASSWORD);
        SSLContext trustOnly = Tls.fromKeyStores(null, TestPki.PASSWORD, load(pki.truststore()));
        JwksKeySource gatewayKeys = new JwksKeySource(
                URI.create("https://localhost:" + internalPort + "/.well-known/jwks.json"), trustOnly, Duration.ZERO);

        policies = new PolicyServer();
        policies.publishMain(TestBundles.main(TestBundles.revision(1), java.util.Map.of()));
        policyKeys = Files.createDirectory(dir.resolve("policy-keys"));
        Files.writeString(policyKeys.resolve("main.pem"), TestBundles.publicKeyPem("test-policy-bundle"));
        Files.writeString(policyKeys.resolve("overrides.pem"), TestBundles.publicKeyPem("test-policy-overrides"));
        policyState = Files.createDirectory(dir.resolve("policy-state"));

        idp = new TestIdp();
        broker = new BrokerStub(Tls.fromPkcs12(brokerKeystore, pki.truststore(), TestPki.PASSWORD), gatewayKeys);
        jira = new TestMcpServer(new TestMcpServer.Config("mcp-jira", "/mcp", "https://mcp-gateway.internal", false, null,
                gatewayKeys), Tls.fromPkcs12(jiraKeystore, pki.truststore(), TestPki.PASSWORD),
                new InetSocketAddress("127.0.0.1", 0)).start();
        gitlab = new TestMcpServer(new TestMcpServer.Config("mcp-gitlab", "/mcp", "https://mcp-gateway.internal", false, null,
                gatewayKeys), Tls.fromPkcs12(gitlabKeystore, pki.truststore(), TestPki.PASSWORD),
                new InetSocketAddress("127.0.0.1", 0)).start();
        wrongName = new TestMcpServer(new TestMcpServer.Config("mcp-confluence", "/mcp", "https://mcp-gateway.internal",
                false, null, gatewayKeys), Tls.fromPkcs12(wrongKeystore, pki.truststore(), TestPki.PASSWORD),
                new InetSocketAddress("127.0.0.1", 0)).start();

        opensearch = new TestMcpServer(new TestMcpServer.Config("mcp-opensearch", "/mcp", "https://mcp-gateway.internal", false, null,
                gatewayKeys).asAdapter(), Tls.fromPkcs12(opensearchKeystore, pki.truststore(), TestPki.PASSWORD),
                new InetSocketAddress("127.0.0.1", 0)).start();

        String acl = redisAcl();
        redis = new GenericContainer<>("redis:8.8.4-alpine")
                .withCopyToContainer(Transferable.of(acl), "/etc/redis-users.acl")
                .withCommand("redis-server", "--aclfile", "/etc/redis-users.acl", "--appendonly", "no")
                .withExposedPorts(6379);
        redis.start();

        postgres = new GenericContainer<>("postgres:18.6-alpine")
                .withEnv("POSTGRES_USER", "gateway").withEnv("POSTGRES_PASSWORD", POSTGRES_PASSWORD)
                .withEnv("POSTGRES_DB", "gateway")
                .withExposedPorts(5432)
                .waitingFor(Wait.forLogMessage(".*database system is ready to accept connections.*\\n", 2));
        postgres.start();

        bffTls = Tls.fromPkcs12(bffKeystore, pki.truststore(), TestPki.PASSWORD);
        otherComponentTls = Tls.fromPkcs12(ciKeystore, pki.truststore(), TestPki.PASSWORD);
        foreignCaTls = Tls.fromKeyStores(load(foreignKeystore), TestPki.PASSWORD, load(pki.truststore()));
        noClientCertificateTls = trustOnly;
        scraperTls = Tls.fromPkcs12(scraperKeystore, pki.truststore(), TestPki.PASSWORD);
        serverIdentityTls = Tls.fromPkcs12(jiraKeystore, pki.truststore(), TestPki.PASSWORD);
        ciGitlabTls = Tls.fromPkcs12(ciGitlabKeystore, pki.truststore(), TestPki.PASSWORD);
        ciJiraTls = Tls.fromPkcs12(ciJiraKeystore, pki.truststore(), TestPki.PASSWORD);
        sharedCiTls = otherComponentTls;
        offboardingTls = Tls.fromPkcs12(offboardingKeystore, pki.truststore(), TestPki.PASSWORD);
        adapterOpensearchTls = Tls.fromPkcs12(adapterOpensearchKeystore, pki.truststore(), TestPki.PASSWORD);
        adapterJiraTls = Tls.fromPkcs12(adapterJiraKeystore, pki.truststore(), TestPki.PASSWORD);
        adapterGitlabTls = Tls.fromPkcs12(adapterGitlabKeystore, pki.truststore(), TestPki.PASSWORD);
        ciOpensearchTls = Tls.fromPkcs12(ciOpensearchKeystore, pki.truststore(), TestPki.PASSWORD);
    }

    /**
     * Forgets the manifest and the approvals of a server in the shared database. A test that starts gateways of its own with another
     * server behind {@code serverId} (the bootstrap approves a manifest once and never replaces it) starts and ends with it.
     */
    public void forgetRegistryOf(String serverId) throws Exception {
        try (java.sql.Connection connection = java.sql.DriverManager.getConnection("jdbc:postgresql://" + postgres.getHost() + ":"
                + postgres.getMappedPort(5432) + "/gateway", "gateway", POSTGRES_PASSWORD);
             java.sql.PreparedStatement tools = connection.prepareStatement("DELETE FROM registry_tools WHERE server_id = ?");
             java.sql.PreparedStatement servers = connection.prepareStatement("DELETE FROM registry_servers WHERE server_id = ?")) {
            tools.setString(1, serverId);
            tools.executeUpdate();
            servers.setString(1, serverId);
            servers.executeUpdate();
        } catch (java.sql.SQLException e) {
            // 42P01: no gateway has migrated this database yet (a test that runs alone), so there is nothing to forget.
            if (!"42P01".equals(e.getSQLState())) {
                throw e;
            }
        }
    }

    /** The ACL file of the Redis of the dev stack: the commands the gateway may use, and an admin for the tests. */
    public static String redisAcl() {
        return String.join("\n",
                "user default off resetkeys resetchannels -@all",
                "user admin on >" + REDIS_ADMIN_PASSWORD + " ~* &* +@all",
                "user gateway on >" + REDIS_GATEWAY_PASSWORD + " resetkeys ~gw:* resetchannels &credential.invalidated "
                        + DATA_COMMANDS + " +subscribe +unsubscribe",
                "");
    }

    /** The properties {@link #register} gives a Spring context, as text, for a gateway started as a process of its own. */
    public java.util.Map<String, String> properties() {
        java.util.Map<String, String> all = new java.util.LinkedHashMap<>();
        register((name, supplier) -> all.put(name, String.valueOf(supplier.get())));
        return all;
    }

    public void register(DynamicPropertyRegistry registry) {
        registry.add("gateway.oidc.issuer", () -> TestIdp.ISSUER);
        registry.add("gateway.oidc.jwks-uri", idp::jwksUri);
        registry.add("gateway.oidc.token-uri", idp::tokenUri);
        // The tests relax production rules (test keys, http, static servers): the devstack profile with its two acknowledgements.
        // The variable MCP_DEVSTACK_ACKNOWLEDGED is a real environment variable of the test JVM (surefire, gateway/pom.xml).
        registry.add("aiwcorpo.mcp.platform.devstack.acknowledged", () -> "true");
        registry.add("gateway.policy.main-url", policies::mainUrl);
        registry.add("gateway.policy.overrides-url", policies::overridesUrl);
        registry.add("gateway.policy.main-key-id", () -> "test-policy-bundle");
        registry.add("gateway.policy.main-key-file", () -> policyKeys.resolve("main.pem").toString());
        registry.add("gateway.policy.overrides-key-id", () -> "test-policy-overrides");
        registry.add("gateway.policy.overrides-key-file", () -> policyKeys.resolve("overrides.pem").toString());
        registry.add("gateway.policy.allow-test-keys", () -> "true");
        registry.add("gateway.policy.state-dir", policyState::toString);
        registry.add("gateway.policy.main-interval", () -> "300ms");
        registry.add("gateway.policy.overrides-interval", () -> "200ms");
        registry.add("gateway.policy.startup-timeout", () -> "10s");
        registry.add("gateway.oidc.jwks-retry-interval", () -> "1s");
        registry.add("gateway.audit.certificate-rejection-interval", () -> "1s");
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
        registry.add("spring.datasource.url", () -> "jdbc:postgresql://" + postgres.getHost() + ":" + postgres.getMappedPort(5432)
                + "/gateway");
        registry.add("spring.datasource.username", () -> "gateway");
        registry.add("spring.datasource.password", () -> POSTGRES_PASSWORD);
        registry.add("gateway.public-url", () -> PUBLIC_URL);
        registry.add("gateway.servers.mcp-jira.internal-url", () -> "https://127.0.0.1:" + jira.port() + "/mcp");
        registry.add("gateway.servers.mcp-jira.tools.delete_issue.risk", () -> "DESTRUCTIVE");
        registry.add("gateway.servers.mcp-jira.tools.delete_issue.description", () -> "Deletes one Jira issue.");
        registry.add("gateway.servers.mcp-jira.tools.delete_issue.resource-refs[0].argument", () -> "issueKey");
        registry.add("gateway.servers.mcp-jira.tools.delete_issue.resource-refs[0].type", () -> "Jira::Issue");
        registry.add("gateway.servers.mcp-jira.tools.delete_issue.title", () -> "Delete issue");
        registry.add("gateway.registry.mode", () -> "static");
        registry.add("gateway.registry.bootstrap-from-server", () -> "true");
        registry.add("gateway.registry.bootstrap-retry", () -> "500ms");
        registry.add("gateway.registry.definition-check-ttl", () -> "1s");
        registry.add("gateway.mcp.tools-list-timeout", () -> "700");
        registry.add("gateway.mcp.sse-heartbeat-interval", () -> "1s");
        registry.add("gateway.mcp.change-poll-interval", () -> "300ms");
        registry.add("gateway.servers.mcp-gitlab.manifest", () -> "required");
        registry.add("gateway.servers.mcp-gitlab.system", () -> "gitlab");
        registry.add("gateway.servers.mcp-gitlab.internal-url", () -> "https://127.0.0.1:" + gitlab.port() + "/mcp");
        registry.add("gateway.servers.mcp-gitlab.credential.accepted-types", () -> "user-secret");
        registry.add("gateway.servers.mcp-gitlab.credential.type", () -> "user-secret");
        registry.add("gateway.servers.mcp-gitlab.tools.get_issue.risk", () -> "READ_ONLY");
        registry.add("gateway.servers.mcp-gitlab.tools.get_issue.description", () -> "Returns one GitLab issue.");
        registry.add("gateway.metrics.allowed-client-cns", () -> "mcp-prometheus");
        registry.add("gateway.allowed-origins", () -> "https://allowed.test");
        registry.add("gateway.redis.health-interval", () -> "1s");
        registry.add("gateway.servers.mcp-servicedesk.system", () -> "servicedesk");
        registry.add("gateway.servers.mcp-servicedesk.enabled", () -> "false");
        registry.add("gateway.servers.mcp-servicedesk.version", () -> "2.1.0");
        registry.add("gateway.servers.mcp-servicedesk.credential.required", () -> "false");
        registry.add("gateway.servers.mcp-servicedesk.internal-url", () -> "https://127.0.0.1:9/mcp");
        registry.add("gateway.servers.mcp-servicedesk.tools.get_ticket.risk", () -> "READ_ONLY");
        registry.add("gateway.servers.mcp-servicedesk.tools.get_ticket.description", () -> "Returns one ticket.");
        registry.add("gateway.servers.mcp-opensearch.system", () -> "opensearch");
        registry.add("gateway.servers.mcp-opensearch.adapter", () -> "true");
        registry.add("gateway.servers.mcp-opensearch.manifest", () -> "required");
        registry.add("gateway.servers.mcp-opensearch.internal-url", () -> "https://127.0.0.1:" + opensearch.port() + "/mcp");
        registry.add("gateway.servers.mcp-opensearch.credential.accepted-types", () -> "user-secret");
        registry.add("gateway.servers.mcp-opensearch.credential.type", () -> "user-secret");
        registry.add("gateway.servers.mcp-opensearch.credential.token-exchange", () -> "false");
        registry.add("gateway.servers.mcp-confluence.system", () -> "confluence");
        registry.add("gateway.servers.mcp-confluence.internal-url", () -> "https://127.0.0.1:" + wrongName.port() + "/mcp");
        registry.add("gateway.servers.mcp-confluence.credential.required", () -> "false");
        registry.add("gateway.servers.mcp-confluence.tools.search_issues.risk", () -> "READ_ONLY");
        registry.add("gateway.servers.mcp-confluence.tools.search_issues.description", () -> "Searches pages.");
    }

    private static java.security.KeyStore load(Path path) throws Exception {
        java.security.KeyStore store = java.security.KeyStore.getInstance("PKCS12");
        try (var in = Files.newInputStream(path)) {
            store.load(in, TestPki.PASSWORD);
        }
        return store;
    }
}
