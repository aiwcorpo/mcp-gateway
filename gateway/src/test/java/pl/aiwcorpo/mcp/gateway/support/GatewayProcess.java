package pl.aiwcorpo.mcp.gateway.support;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * A gateway started as a process of its own (the classes and libraries of the test JVM, GatewayApplication as main), so that a test
 * can run two instances against one Redis and one PostgreSQL and kill one of them. Everything comes from properties given as
 * arguments; the environment of the process carries only the acknowledgement of the devstack profile and the placeholders that
 * application.yml wants a value for.
 */
public final class GatewayProcess implements AutoCloseable {

    private final String name;
    private final Process process;
    private final int port;
    private final int internalPort;
    private final Path log;

    private GatewayProcess(String name, Process process, int port, int internalPort, Path log) {
        this.name = name;
        this.process = process;
        this.port = port;
        this.internalPort = internalPort;
        this.log = log;
    }

    public static int freePort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    /** Starts the process and returns when the metadata document answers, i.e. when the gateway serves. */
    public static GatewayProcess start(String name, Path directory, Map<String, String> properties, int port, int internalPort)
            throws Exception {
        List<String> command = new ArrayList<>();
        command.add(Path.of(System.getProperty("java.home"), "bin", "java").toString());
        command.add("--enable-native-access=ALL-UNNAMED");
        command.add("-Xmx384m");
        command.add("-cp");
        command.add(System.getProperty("java.class.path"));
        command.add("pl.aiwcorpo.mcp.gateway.GatewayApplication");
        properties.forEach((key, value) -> command.add("--" + key + "=" + value));
        command.add("--server.port=" + port);
        command.add("--gateway.internal-endpoint.port=" + internalPort);
        command.add("--spring.profiles.active=devstack");
        Path log = directory.resolve(name + ".log");
        ProcessBuilder builder = new ProcessBuilder(command).redirectErrorStream(true).redirectOutput(log.toFile());
        Map<String, String> environment = builder.environment();
        environment.put("MCP_DEVSTACK_ACKNOWLEDGED", "true");
        for (String placeholder : new String[] {"MCP_BROKER_TLS_NAME", "MCP_DB_PASSWORD", "MCP_OIDC_ISSUER", "MCP_POLICY_MAIN_KEY_ID",
                "MCP_REDIS_HOST", "MCP_TLS_KEYSTORE", "MCP_TLS_STORE_PASSWORD", "MCP_TLS_TRUSTSTORE", "MCP_POLICY_MAIN_KEY_FILE",
                "MCP_BROKER_URL", "MCP_DB_URL", "MCP_OIDC_JWKS_URI", "MCP_POLICY_MAIN_URL", "MCP_PUBLIC_URL", "MCP_SERVER_JIRA_URL"}) {
            environment.put(placeholder, "https://placeholder.invalid");
        }
        GatewayProcess gateway = new GatewayProcess(name, builder.start(), port, internalPort, log);
        try {
            gateway.awaitServing();
        } catch (Exception failure) {
            gateway.close();
            throw failure;
        }
        return gateway;
    }

    private void awaitServing() throws Exception {
        HttpClient http = HttpClient.newHttpClient();
        long deadline = System.nanoTime() + Duration.ofSeconds(90).toNanos();
        while (System.nanoTime() < deadline) {
            if (!process.isAlive()) {
                throw new IllegalStateException(name + " exited with " + process.exitValue() + ":\n" + tail());
            }
            try {
                HttpResponse<String> response = http.send(HttpRequest.newBuilder(
                        URI.create("http://localhost:" + port + "/.well-known/oauth-protected-resource/mcp")).GET().build(),
                        HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() == 200) {
                    return;
                }
            } catch (IOException e) {
                // not up yet
            }
            Thread.sleep(300);
        }
        throw new IllegalStateException(name + " did not serve within 90 s:\n" + tail());
    }

    public int port() {
        return port;
    }

    public int internalPort() {
        return internalPort;
    }

    public boolean alive() {
        return process.isAlive();
    }

    public Path log() {
        return log;
    }

    public String output() throws IOException {
        return Files.readString(log);
    }

    private String tail() {
        try {
            String all = output();
            return all.substring(Math.max(0, all.length() - 4000));
        } catch (IOException e) {
            return "(no log)";
        }
    }

    /** Kills the process at once, as a crashed node: no shutdown hook, no goodbye. */
    public void kill() throws InterruptedException {
        process.destroyForcibly();
        process.waitFor();
    }

    @Override
    public void close() {
        process.destroyForcibly();
    }
}
