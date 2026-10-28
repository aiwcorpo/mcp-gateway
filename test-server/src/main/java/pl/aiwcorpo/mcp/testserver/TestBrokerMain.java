package pl.aiwcorpo.mcp.testserver;

import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.net.ssl.SSLContext;

/**
 * Runs {@link TestBroker} on the host for the gateway demo. {@code MCP_TEST_BROKER_PATS} lists
 * {@code user=pat} pairs separated by commas; a user that is not listed gets credential_required. {@code MCP_TEST_BROKER_TOTP}
 * lists {@code sub=base32seed} pairs: those users have an authenticator.
 */
public final class TestBrokerMain {

    private TestBrokerMain() {
    }

    public static void main(String[] args) throws Exception {
        char[] password = required("MCP_TLS_STORE_PASSWORD").toCharArray();
        SSLContext tls = Tls.fromPkcs12(Path.of(required("MCP_TLS_KEYSTORE")), Path.of(required("MCP_TLS_TRUSTSTORE")), password);
        Map<String, String> pats = new LinkedHashMap<>();
        for (String pair : env("MCP_TEST_BROKER_PATS", "").split(",")) {
            int eq = pair.indexOf('=');
            if (eq > 0) {
                pats.put(pair.substring(0, eq).trim(), pair.substring(eq + 1).trim());
            }
        }
        TestBroker broker = new TestBroker(tls,
                new JwksKeySource(URI.create(required("MCP_GATEWAY_JWKS_URI")), tls, Duration.ofSeconds(10)),
                env("MCP_GATEWAY_ISSUER", "https://mcp-gateway.internal"), pats, required("MCP_PORTAL_CONNECT_URL"),
                new InetSocketAddress(Integer.parseInt(env("MCP_PORT", "8443"))));
        for (String pair : env("MCP_TEST_BROKER_TOTP", "").split(",")) {
            int eq = pair.indexOf('=');
            if (eq > 0) {
                broker.enroll(pair.substring(0, eq).trim(), pair.substring(eq + 1).trim());
            }
        }
        broker.start();
        System.err.println("test broker on :" + broker.port() + " for users " + pats.keySet());
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
