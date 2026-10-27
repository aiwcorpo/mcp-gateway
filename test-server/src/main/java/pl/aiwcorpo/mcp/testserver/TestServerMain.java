package pl.aiwcorpo.mcp.testserver;

import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;

import javax.net.ssl.SSLContext;

/**
 * Runs {@link TestMcpServer} in a container in the place of mcp-jira (mcp-platform-dev, profile "full").
 * Environment names follow the mcp-jira service of mcp-platform-dev's docker-compose.yml.
 */
public final class TestServerMain {

    private TestServerMain() {
    }

    public static void main(String[] args) throws Exception {
        char[] password = required("MCP_TLS_STORE_PASSWORD").toCharArray();
        SSLContext tls = Tls.fromPkcs12(Path.of(required("MCP_TLS_KEYSTORE")), Path.of(required("MCP_TLS_TRUSTSTORE")),
                password);
        URI jwks = URI.create(required("MCP_GATEWAY_JWKS_URI"));
        String tlsName = System.getenv("MCP_GATEWAY_TLS_NAME");
        if (tlsName != null && !tlsName.isBlank() && !tlsName.equals(jwks.getHost())) {
            throw new IllegalStateException("MCP_GATEWAY_JWKS_URI host must equal MCP_GATEWAY_TLS_NAME");
        }
        String jira = System.getenv("MCP_JIRA_URL");
        TestMcpServer.Config config = new TestMcpServer.Config(
                env("MCP_SERVER_ID", "mcp-jira"),
                env("MCP_PATH", "/mcp"),
                env("MCP_GATEWAY_ISSUER", "https://mcp-gateway.internal"),
                Boolean.parseBoolean(env("MCP_ALLOW_TEST_KEYS", "false")),
                jira == null || jira.isBlank() ? null : URI.create(jira),
                new JwksKeySource(jwks, tls, Duration.ofSeconds(10)));
        TestMcpServer server = new TestMcpServer(config, tls,
                new InetSocketAddress(Integer.parseInt(env("MCP_PORT", "8443")))).start();
        System.err.println("test MCP server " + config.serverId() + " on :" + server.port() + config.path());
    }

    private static String env(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? fallback : value;
    }

    private static String required(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(name + " is required");
        }
        return value;
    }
}
