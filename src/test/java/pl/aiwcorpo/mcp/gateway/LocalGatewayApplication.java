package pl.aiwcorpo.mcp.gateway;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.boot.SpringApplication;

import pl.aiwcorpo.mcp.gateway.support.GatewayTestEnvironment;

/**
 * The gateway on a developer's machine with everything around it from the integration tests: Redis and PostgreSQL in containers,
 * the internal CA, the IdP stand-in, the broker stub, the policy server and the test MCP servers (mcp-jira, mcp-gitlab, ...). Needs
 * Docker and nothing else; run it from the IDE (.run/LocalGateway.run.xml) or with
 * {@code MCP_DEVSTACK_ACKNOWLEDGED=true ./mvnw spring-boot:test-run -Dspring-boot.run.mainClass=pl.aiwcorpo.mcp.gateway.LocalGatewayApplication}.
 *
 * <p>The devstack profile relaxes the production rules (test keys, plain http), so the process must have
 * {@code MCP_DEVSTACK_ACKNOWLEDGED=true} in its environment; the run configuration sets it. Everything here is test material.
 */
public final class LocalGatewayApplication {

    static final int PUBLIC_PORT = 18600;
    static final List<String> GROUPS = List.of("mcp-jira-read", "mcp-jira-write", "mcp-jira-destructive", "mcp-gitlab-read");

    private LocalGatewayApplication() {
    }

    public static void main(String[] args) throws Exception {
        if (!"true".equals(System.getenv("MCP_DEVSTACK_ACKNOWLEDGED"))) {
            System.err.println("set MCP_DEVSTACK_ACKNOWLEDGED=true in the environment of this process (the run configuration does)");
            System.exit(2);
        }
        GatewayTestEnvironment env = GatewayTestEnvironment.get();
        Map<String, String> properties = new LinkedHashMap<>(env.properties());
        String publicUrl = "http://localhost:" + PUBLIC_PORT;
        properties.put("gateway.public-url", publicUrl);
        properties.put("gateway.allow-plain-http", "true");
        // One token for a working day instead of a fresh one every few minutes.
        properties.put("gateway.oidc.max-token-lifetime", "12h");
        properties.put("server.port", String.valueOf(PUBLIC_PORT));
        properties.put("spring.profiles.active", "devstack");
        // application.yml names these variables; the properties above replace what they feed, but the placeholders must resolve.
        for (String name : new String[] {"MCP_BROKER_TLS_NAME", "MCP_DB_PASSWORD", "MCP_OIDC_ISSUER", "MCP_POLICY_MAIN_KEY_ID",
                "MCP_REDIS_HOST", "MCP_TLS_KEYSTORE", "MCP_TLS_STORE_PASSWORD", "MCP_TLS_TRUSTSTORE", "MCP_POLICY_MAIN_KEY_FILE",
                "MCP_BROKER_URL", "MCP_DB_URL", "MCP_OIDC_JWKS_URI", "MCP_POLICY_MAIN_URL", "MCP_PUBLIC_URL", "MCP_SERVER_JIRA_URL"}) {
            if (System.getenv(name) == null) {
                System.setProperty(name, "https://placeholder.invalid");
            }
        }
        List<String> arguments = new ArrayList<>(List.of(args));
        properties.forEach((name, value) -> arguments.add("--" + name + "=" + value));
        SpringApplication.run(GatewayApplication.class, arguments.toArray(String[]::new));

        String token = env.idp.token("local-user", "local-user", GROUPS, "mcp-gateway", "claude-code", 12 * 3600);
        Path tokenFile = Path.of("target", "local-gateway.token");
        Files.createDirectories(tokenFile.getParent());
        Files.writeString(tokenFile, token);
        System.out.printf("""

                Local gateway: %s/mcp (MCP clients), https://127.0.0.1:%d (internal: JWKS, admin API, actuator)
                User token (12 h, groups %s) in %s:
                  curl -s %s/mcp -H "Authorization: Bearer $(cat %s)" -H 'Content-Type: application/json' \\
                    -H 'Accept: application/json, text/event-stream' \\
                    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"1"}}}'
                The servers behind it are the test MCP servers of the integration tests; nothing reaches a real system.

                """, publicUrl, env.internalPort, String.join(",", GROUPS), tokenFile.toAbsolutePath(), publicUrl, tokenFile);
    }
}
