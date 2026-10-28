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
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Test vectors of the mcp-contracts test-vectors jar. The 3.0.1 jar in the local repository was packed from a build
 * directory that still held files of 3.0.0 and earlier (removed vectors such as {@code whoami-identity/}, the old
 * {@code confirmation-binding/valid-*}); {@code stale-vectors-3.0.1.txt} lists them, so they are not run against rules
 * that no longer exist. The release tarball does not have them.
 */
public final class Vectors {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final String ROOT = "mcp-contracts/test-vectors/";
    private static final Set<String> STALE = stale();

    private Vectors() {
    }

    public record Vector(String name, JsonNode document) {
    }

    /** All vectors of a directory such as {@code confirmation-binding}, sorted by name, without the stale ones. */
    public static List<Vector> of(String directory) {
        try {
            URI location = Vectors.class.getClassLoader().getResource(ROOT + directory).toURI();
            try (FileSystem jar = "jar".equals(location.getScheme()) ? FileSystems.newFileSystem(location, Map.of()) : null) {
                Path path = jar == null ? Path.of(location) : jar.getPath(ROOT + directory);
                try (Stream<Path> files = Files.list(path)) {
                    return files.filter(f -> f.toString().endsWith(".json")).sorted()
                            .filter(f -> !STALE.contains(directory + "/" + f.getFileName()))
                            .map(f -> new Vector(f.getFileName().toString(), read(f))).toList();
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (URISyntaxException e) {
            throw new IllegalStateException(e);
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

    private static JsonNode read(Path file) {
        try {
            return JSON.readTree(Files.readString(file));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static Set<String> stale() {
        try (InputStream in = Vectors.class.getClassLoader().getResourceAsStream("stale-vectors-3.0.1.txt")) {
            Set<String> names = new HashSet<>();
            for (String line : new String(in.readAllBytes(), StandardCharsets.UTF_8).split("\n")) {
                if (!line.isBlank()) {
                    names.add(line.trim());
                }
            }
            return names;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
