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
 * mcp-jira and as mcp-gitlab (certificates of the internal CA, which the gateway trusts through {@code MCP_SERVER_TRUSTED_CAS}), a server
 * that presents another certificate than the one pinned for it (as mcp-confluence), Redis with the
 * ACL of the dev stack and PostgreSQL, whose registry of servers is seeded with them. Test servers are reached by address, as in
 * production: nothing about them is configured but their URL.
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
    /** The server behind mcp-confluence: its certificate is not the one that the approved connection of that server pins. */
    public final TestMcpServer pinnedElsewhere;
    /** Where the gateway's internal JWT keys are fetched from: what the test servers started here verify tokens with. */
    public final JwksKeySource gatewayKeys;
    /** The foreign server behind an adapter: mcp-opensearch in adapter mode (the test server stands in for the foreign one). */
    public final TestMcpServer opensearch;
    public final GenericContainer<?> redis;
    public final GenericContainer<?> postgres;
    public final SSLContext gatewayClientTls;
    /** The CA bundle the gateway adds to its server trust (MCP_SERVER_TRUSTED_CAS): the internal CA of the tests. */
    public final Path serverCas;
    private final java.util.Map<Integer, String> fingerprints = new java.util.concurrent.ConcurrentHashMap<>();
    /** Client TLS identities for the admin API: the BFF, another component of the internal CA, a foreign CA. */
    public final SSLContext bffTls;
    public final SSLContext otherComponentTls;
    public final SSLContext foreignCaTls;
    public final SSLContext noClientCertificateTls;
    /** The Prometheus scraper: a client certificate whose name is listed in gateway.metrics.allowed-client-cns. */
    public final SSLContext scraperTls;
    /** A server identity of the internal CA (mcp-jira, serverAuth only), as servers use when they fetch the JWKS. */
    public final SSLContext serverIdentityTls;
    /** The offboarding process (CC-155). */
    public final SSLContext offboardingTls;

    /** The test servers' addresses, as registry rows: serverId to the port its test server listens on. */

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
        Path jiraKeystore = pki.issue("jira.p12", "mcp-jira", List.of("127.0.0.1", "localhost"), true, false);
        Path gitlabKeystore = pki.issue("gitlab.p12", "mcp-gitlab", List.of("127.0.0.1", "localhost"), true, false);
        Path confluenceKeystore = pki.issue("confluence.p12", "mcp-confluence", List.of("127.0.0.1", "localhost"), true, false);
        serverCas = pki.caPem("server-cas");
        Path bffKeystore = pki.issue("bff.p12", "mcp-portal-bff", List.of(), false, true);
        Path scraperKeystore = pki.issue("scraper.p12", "mcp-prometheus", List.of(), false, true);
        Path opensearchKeystore = pki.issue("opensearch.p12", "mcp-opensearch", List.of("127.0.0.1", "localhost"), true, false);
        Path otherKeystore = pki.issue("other.p12", "mcp-other-component", List.of(), false, true);
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
        gatewayKeys = new JwksKeySource(
                URI.create("https://localhost:" + internalPort + "/.well-known/jwks.json"), trustOnly, Duration.ZERO);

        idp = new TestIdp();
        broker = new BrokerStub(Tls.fromPkcs12(brokerKeystore, pki.truststore(), TestPki.PASSWORD), gatewayKeys);
        jira = new TestMcpServer(new TestMcpServer.Config("mcp-jira", "/mcp", "https://mcp-gateway.internal", false, null,
                gatewayKeys), Tls.fromPkcs12(jiraKeystore, pki.truststore(), TestPki.PASSWORD),
                new InetSocketAddress("127.0.0.1", 0)).start();
        // The update tool is part of the manifest every gateway of the tests takes from this server (the shared context turns it off again
        // once it has the manifest, TestServers), as the static tools of 1.x were.
        jira.updateTool(true);
        jira.updateToolInManifest(true);
        gitlab = new TestMcpServer(new TestMcpServer.Config("mcp-gitlab", "/mcp", "https://mcp-gateway.internal", false, null,
                gatewayKeys), Tls.fromPkcs12(gitlabKeystore, pki.truststore(), TestPki.PASSWORD),
                new InetSocketAddress("127.0.0.1", 0)).start();
        pinnedElsewhere = new TestMcpServer(new TestMcpServer.Config("mcp-confluence", "/mcp", "https://mcp-gateway.internal",
                false, null, gatewayKeys), Tls.fromPkcs12(confluenceKeystore, pki.truststore(), TestPki.PASSWORD),
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
        otherComponentTls = Tls.fromPkcs12(otherKeystore, pki.truststore(), TestPki.PASSWORD);
        foreignCaTls = Tls.fromKeyStores(load(foreignKeystore), TestPki.PASSWORD, load(pki.truststore()));
        noClientCertificateTls = trustOnly;
        scraperTls = Tls.fromPkcs12(scraperKeystore, pki.truststore(), TestPki.PASSWORD);
        serverIdentityTls = Tls.fromPkcs12(jiraKeystore, pki.truststore(), TestPki.PASSWORD);
        offboardingTls = Tls.fromPkcs12(offboardingKeystore, pki.truststore(), TestPki.PASSWORD);
        fingerprints.put(jira.port(), TestPki.fingerprint(jiraKeystore));
        fingerprints.put(gitlab.port(), TestPki.fingerprint(gitlabKeystore));
        fingerprints.put(pinnedElsewhere.port(), TestPki.fingerprint(confluenceKeystore));
        fingerprints.put(opensearch.port(), TestPki.fingerprint(opensearchKeystore));
        seedServers();
    }

    /**
     * A test MCP server that a test adds to the registry at runtime by its address: its certificate is signed by the internal CA and names
     * 127.0.0.1, so it validates as {@code ca} (the gateway trusts that CA). It verifies the gateway's tokens, serves the manifest of its
     * system (Project and Issue types, policies of its own namespace) and holds the policy data the gateway pushes.
     */
    public TestMcpServer startServer(String serverId) throws Exception {
        return startServer(serverId, 0);
    }

    /** As above on a port that was used before: the same address with a new certificate, as a renewal or a replacement looks to the gateway. */
    public TestMcpServer startServer(String serverId, int port) throws Exception {
        Path keystore = pki.issue(serverId + "-runtime-" + System.nanoTime() + ".p12", serverId, List.of("127.0.0.1", "localhost"), true, false);
        TestMcpServer started = new TestMcpServer(new TestMcpServer.Config(serverId, "/mcp", "https://mcp-gateway.internal", false, null, gatewayKeys),
                Tls.fromPkcs12(keystore, pki.truststore(), TestPki.PASSWORD), new InetSocketAddress("127.0.0.1", port)).start();
        fingerprints.put(started.port(), TestPki.fingerprint(keystore));
        return started;
    }

    /** The sidecar of an adapter in front of a foreign server: its manifest says source adapter and it takes the classification claims. */
    public TestMcpServer startAdapterServer(String serverId) throws Exception {
        Path keystore = pki.issue(serverId + "-adapter.p12", serverId, List.of("127.0.0.1", "localhost"), true, false);
        TestMcpServer started = new TestMcpServer(new TestMcpServer.Config(serverId, "/mcp", "https://mcp-gateway.internal", false, null, gatewayKeys)
                .asAdapter(), Tls.fromPkcs12(keystore, pki.truststore(), TestPki.PASSWORD), new InetSocketAddress("127.0.0.1", 0)).start();
        fingerprints.put(started.port(), TestPki.fingerprint(keystore));
        return started;
    }

    /** As {@link #startServer} with a self-signed certificate (no CA stands behind it): it validates as nothing, so it is pinned. */
    public TestMcpServer startSelfSignedServer(String serverId) throws Exception {
        return startSelfSignedServer(serverId, 0);
    }

    public TestMcpServer startSelfSignedServer(String serverId, int port) throws Exception {
        Path keystore = TestPki.selfSigned(dir, serverId + "-self-" + System.nanoTime() + ".p12", serverId, List.of("127.0.0.1"));
        TestMcpServer started = new TestMcpServer(new TestMcpServer.Config(serverId, "/mcp", "https://mcp-gateway.internal", false, null, gatewayKeys),
                tlsOf(keystore), new InetSocketAddress("127.0.0.1", port)).start();
        fingerprints.put(started.port(), TestPki.fingerprint(keystore));
        return started;
    }

    /** A server that presents a certificate of the internal CA for another host than the one it is reached at: a certificate that does not validate as {@code ca}. */
    public TestMcpServer startServerForAnotherHost(String serverId) throws Exception {
        Path keystore = pki.issue(serverId + "-elsewhere.p12", serverId, List.of("another-host.test"), true, false);
        TestMcpServer started = new TestMcpServer(new TestMcpServer.Config(serverId, "/mcp", "https://mcp-gateway.internal", false, null, gatewayKeys),
                Tls.fromPkcs12(keystore, pki.truststore(), TestPki.PASSWORD), new InetSocketAddress("127.0.0.1", 0)).start();
        fingerprints.put(started.port(), TestPki.fingerprint(keystore));
        return started;
    }

    /** As {@link #startServer} over plain http, as a server in the Docker network of the platform. */
    public TestMcpServer startPlainServer(String serverId) throws Exception {
        return new TestMcpServer(new TestMcpServer.Config(serverId, "/mcp", "https://mcp-gateway.internal", false, null, gatewayKeys),
                null, new InetSocketAddress("127.0.0.1", 0)).start();
    }

    /** The fingerprint of the certificate a test server of this environment presents, as the gateway shows it. */
    public String fingerprint(TestMcpServer server) {
        return fingerprints.get(server.port());
    }

    private SSLContext tlsOf(Path selfSignedKeystore) throws Exception {
        return Tls.fromKeyStores(load(selfSignedKeystore), TestPki.PASSWORD, load(pki.truststore()));
    }

    /** One row of {@code servers}: what the registry holds of a server before the gateway has looked at it (or after an administrator approved its connection). */
    public record ServerRow(String serverId, String system, String url, String credentialType, boolean credentialRequired, boolean enabled,
                            boolean adapter, String connectionJson) {
        public ServerRow(String serverId, String system, String url, String credentialType, boolean credentialRequired, boolean enabled,
                         boolean adapter) {
            this(serverId, system, url, credentialType, credentialRequired, enabled, adapter, null);
        }
    }

    /**
     * The servers every gateway of the tests starts with: the test servers behind them (mcp-jira and mcp-gitlab, which the gateway has not
     * looked at yet; mcp-confluence with an approved connection that pins another certificate than the one the server presents; a disabled
     * mcp-servicedesk; mcp-opensearch behind an adapter).
     */
    public List<ServerRow> servers() {
        String pinned = "{\"tlsMode\":\"pinned\",\"fingerprint\":\"" + fingerprints.get(jira.port())
                + "\",\"subject\":\"CN=mcp-jira\",\"issuer\":\"CN=test-internal-ca\",\"sans\":[],\"notAfter\":null,"
                + "\"approvedBy\":\"test-seed\",\"approvedAt\":\"2026-11-08T00:00:00Z\"}";
        return List.of(
                new ServerRow("mcp-jira", "jira", "https://127.0.0.1:" + jira.port() + "/mcp", "user-secret", true, true, false),
                new ServerRow("mcp-gitlab", "gitlab", "https://127.0.0.1:" + gitlab.port() + "/mcp", "user-secret", true, true, false),
                new ServerRow("mcp-confluence", "confluence", "https://127.0.0.1:" + pinnedElsewhere.port() + "/mcp", "user-secret", false, true,
                        false, pinned),
                new ServerRow("mcp-servicedesk", "servicedesk", "https://127.0.0.1:9/mcp", "user-secret", false, false, false, pinned),
                new ServerRow("mcp-opensearch", "opensearch", "https://127.0.0.1:" + opensearch.port() + "/mcp", "user-secret", true, true, true));
    }

    /**
     * Migrates the database and writes the rows of {@link #servers()}, so that a gateway of any test (a context, or a process of its own)
     * finds them at start. The gateway migrates the same database with the same history table; Flyway's lock makes the two agree.
     */
    private void seedServers() throws Exception {
        seed("gateway", java.util.Map.of());
    }

    /**
     * A database of its own on the test PostgreSQL, migrated and seeded like the shared one, for a gateway that runs against test servers
     * of its own: its registry then cannot change what the shared context serves. {@code urls}: serverId to the address the test server
     * of that test listens on.
     *
     * @return the JDBC URL to give the gateway as {@code spring.datasource.url}
     */
    public String isolatedDatabase(String name, java.util.Map<String, String> urls) throws Exception {
        String url = emptyDatabase(name);
        seed(name, urls);
        return url;
    }

    /** A migrated database with no server in its registry: whoever uses it adds them through the admin API (or the admin service). */
    public String emptyDatabase(String name) throws Exception {
        try (java.sql.Connection connection = connection("gateway"); java.sql.Statement create = connection.createStatement()) {
            create.executeUpdate("DROP DATABASE IF EXISTS " + name);
            create.executeUpdate("CREATE DATABASE " + name);
        }
        org.flywaydb.core.Flyway.configure().dataSource(jdbcUrl(name), "gateway", POSTGRES_PASSWORD).locations("classpath:db/migration")
                .load().migrate();
        return jdbcUrl(name);
    }

    private String jdbcUrl(String database) {
        return "jdbc:postgresql://" + postgres.getHost() + ":" + postgres.getMappedPort(5432) + "/" + database;
    }

    private void seed(String database, java.util.Map<String, String> urls) throws Exception {
        org.flywaydb.core.Flyway.configure().dataSource(jdbcUrl(database), "gateway", POSTGRES_PASSWORD).locations("classpath:db/migration")
                .load().migrate();
        try (java.sql.Connection connection = connection(database);
             java.sql.PreparedStatement upsert = connection.prepareStatement("INSERT INTO servers (server_id, system, internal_url, "
                     + "credential, enabled, adapter, connection, status) VALUES (?, ?, ?, ?::jsonb, ?, ?, ?::jsonb, ?) "
                     + "ON CONFLICT (server_id) DO UPDATE SET "
                     + "internal_url = EXCLUDED.internal_url, credential = EXCLUDED.credential, "
                     + "enabled = EXCLUDED.enabled, adapter = EXCLUDED.adapter, connection = EXCLUDED.connection, "
                     + "status = EXCLUDED.status")) {
            for (ServerRow row : servers()) {
                upsert.setString(1, row.serverId());
                upsert.setString(2, row.system());
                upsert.setString(3, urls.getOrDefault(row.serverId(), row.url()));
                upsert.setString(4, "{\"required\":" + row.credentialRequired() + ",\"acceptedTypes\":[\"" + row.credentialType()
                        + "\"],\"type\":\"" + row.credentialType() + "\"}");
                upsert.setBoolean(5, row.enabled());
                upsert.setBoolean(6, row.adapter());
                // A server that the test moves to another address presents another certificate: what was approved for the shared one would
                // only make the first check fail, so it starts as a new server and the development bootstrap approves what it sees.
                String approved = urls.containsKey(row.serverId()) ? null : row.connectionJson();
                upsert.setString(7, approved);
                upsert.setString(8, approved == null ? "pending_approval" : "connected");
                upsert.executeUpdate();
            }
            try (java.sql.Statement bump = connection.createStatement()) {
                bump.executeUpdate("UPDATE registry_changes SET version = version + 1 WHERE id = 1");
            }
        }
    }

    private java.sql.Connection connection() throws java.sql.SQLException {
        return connection("gateway");
    }

    private java.sql.Connection connection(String database) throws java.sql.SQLException {
        return java.sql.DriverManager.getConnection(jdbcUrl(database), "gateway", POSTGRES_PASSWORD);
    }

    /**
     * Forgets the manifest and the approvals of a server in the shared database. A test that starts gateways of its own with another
     * server behind {@code serverId} (the bootstrap approves a manifest once and never replaces it) starts and ends with it.
     */
    public void forgetRegistryOf(String serverId) throws Exception {
        try (java.sql.Connection connection = connection()) {
            for (String table : List.of("registry_tools", "registry_servers", "registry_policies", "registry_namespaces", "registry_risk_floor")) {
                try (java.sql.PreparedStatement delete = connection.prepareStatement("DELETE FROM " + table + " WHERE server_id = ?")) {
                    delete.setString(1, serverId);
                    delete.executeUpdate();
                }
            }
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
        all.put("gateway.registry.bootstrap-from-server", "true");
        return all;
    }

    public void register(DynamicPropertyRegistry registry) {
        registry.add("gateway.oidc.issuer", () -> TestIdp.ISSUER);
        registry.add("gateway.oidc.jwks-uri", idp::jwksUri);
        registry.add("gateway.oidc.token-uri", idp::tokenUri);
        // The tests relax production rules (test keys, http, a manifest taken from the server): the devstack profile with its two acknowledgements.
        // The variable MCP_DEVSTACK_ACKNOWLEDGED is a real environment variable of the test JVM (surefire, gateway/pom.xml).
        registry.add("aiwcorpo.mcp.platform.devstack.acknowledged", () -> "true");
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
        // Servers are reached by address and trusted as ca through the CA of the tests; they listen on the loopback interface, which the
        // address check refuses unless the devstack allows it. The loop looks at its timers often, and refresh has no pause (its limit has a test of its own).
        registry.add("gateway.servers.trusted-cas", serverCas::toString);
        registry.add("gateway.servers.allow-loopback", () -> "true");
        registry.add("gateway.servers.loop-poll", () -> "200ms");
        registry.add("gateway.servers.refresh-interval", () -> "0s");
        // The shared context takes the manifests of the servers once, at start (TestServers); a server added later by a test waits for its own
        // approvals, as in production. A process of its own bootstraps (properties()).
        registry.add("gateway.registry.bootstrap-from-server", () -> "false");
        registry.add("gateway.registry.bootstrap-retry", () -> "500ms");
        registry.add("gateway.registry.definition-check-ttl", () -> "1s");
        registry.add("gateway.mcp.tools-list-timeout", () -> "700");
        registry.add("gateway.mcp.sse-heartbeat-interval", () -> "1s");
        registry.add("gateway.mcp.change-poll-interval", () -> "300ms");
        registry.add("gateway.metrics.allowed-client-cns", () -> "mcp-prometheus");
        registry.add("gateway.allowed-origins", () -> "https://allowed.test");
        registry.add("gateway.redis.health-interval", () -> "1s");
    }

    private static java.security.KeyStore load(Path path) throws Exception {
        java.security.KeyStore store = java.security.KeyStore.getInstance("PKCS12");
        try (var in = Files.newInputStream(path)) {
            store.load(in, TestPki.PASSWORD);
        }
        return store;
    }
}
