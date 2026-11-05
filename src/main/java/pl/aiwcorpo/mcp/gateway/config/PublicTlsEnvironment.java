package pl.aiwcorpo.mcp.gateway.config;

import java.util.Map;

import org.springframework.boot.EnvironmentPostProcessor;
import org.springframework.boot.SpringApplication;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

/**
 * Prepares the files of the optional TLS of the public port for the SSL bundle. Operators give plain paths, but a Spring resource
 * location without a scheme is read from the classpath, so the {@code file:} prefix is added here (a value that already has it is
 * kept, as in the portal).
 */
public final class PublicTlsEnvironment implements EnvironmentPostProcessor {

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        environment.getPropertySources().addFirst(new MapPropertySource("gatewayPublicTls", Map.of(
                "gateway.public-tls.certificate-location", location(environment.getProperty("gateway.public-tls.certificate", "")),
                "gateway.public-tls.private-key-location", location(environment.getProperty("gateway.public-tls.private-key", "")))));
    }

    static String location(String path) {
        return path.isBlank() || path.startsWith("file:") ? path : "file:" + path;
    }

    /** The file system path of a value that may carry the {@code file:} prefix. */
    static String path(String value) {
        return value.startsWith("file:") ? value.substring("file:".length()) : value;
    }
}
