package pl.aiwcorpo.mcp.gateway.support;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** Test vectors of the mcp-contracts test-vectors jar, read from the classpath. */
public final class Vectors {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final String ROOT = "mcp-contracts/test-vectors/";

    private Vectors() {
    }

    public record Vector(String name, JsonNode document) {
    }

    /** All vectors of a directory such as {@code confirmation-binding}, sorted by name, without the stale ones. */
    public static List<Vector> of(String directory) {
        try {
            URI location = Vectors.class.getClassLoader().getResource(ROOT + directory).toURI();
            FileSystem jar = "jar".equals(location.getScheme()) ? zip(location) : null;
            Path path = jar == null ? Path.of(location) : jar.getPath(ROOT + directory);
            try (Stream<Path> files = Files.list(path)) {
                return files.filter(f -> f.toString().endsWith(".json")).sorted()
                        .map(f -> new Vector(f.getFileName().toString(), read(f))).toList();
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (URISyntaxException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The jar is opened once per JVM and shared with other tests that read it; it is never closed here. */
    private static synchronized FileSystem zip(URI location) throws IOException {
        try {
            return FileSystems.newFileSystem(location, Map.of());
        } catch (java.nio.file.FileSystemAlreadyExistsException e) {
            return FileSystems.getFileSystem(location);
        }
    }

    /** A file of the test-vectors jar as text, e.g. {@code activity-cursor/valid.json}. */
    public static String text(String relative) {
        try (InputStream in = Vectors.class.getClassLoader().getResourceAsStream(ROOT + relative)) {
            if (in == null) {
                throw new IllegalArgumentException("no test vector " + relative);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * A file of the contracts that a vector names by its path from the root of the repository: {@code cedar/...} is in the mcp-contracts jar,
     * {@code test-vectors/...} in the test-vectors jar.
     */
    public static String contractFile(String path) {
        String resource = "mcp-contracts/" + path;
        try (InputStream in = Vectors.class.getClassLoader().getResourceAsStream(resource)) {
            if (in == null) {
                throw new IllegalArgumentException("no contract file " + path);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static JsonNode read(Path file) {
        try {
            return JSON.readTree(Files.readString(file));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
