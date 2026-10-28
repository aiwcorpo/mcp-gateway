package pl.aiwcorpo.mcp.testserver;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** The vectors of totp/ (mcp-contracts 3.0.2) against the authenticator rules of the stand-in broker. */
class TotpVectorTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final String ROOT = "mcp-contracts/test-vectors/totp";

    @TestFactory
    Stream<DynamicTest> allTotpVectors() throws Exception {
        java.net.URI location = getClass().getClassLoader().getResource(ROOT).toURI();
        FileSystem jar = "jar".equals(location.getScheme()) ? zip(location) : null;
        Path dir = jar == null ? Path.of(location) : jar.getPath(ROOT);
        List<Path> files;
        try (Stream<Path> list = Files.list(dir)) {
            files = list.filter(p -> p.toString().endsWith(".json")).sorted().toList();
        }
        List<JsonNode> vectors = new ArrayList<>();
        List<String> names = new ArrayList<>();
        for (Path file : files) {
            vectors.add(JSON.readTree(Files.readString(file)));
            names.add(file.getFileName().toString());
        }
        assertThat(vectors).hasSizeGreaterThanOrEqualTo(46);
        List<DynamicTest> tests = new ArrayList<>();
        for (int i = 0; i < vectors.size(); i++) {
            JsonNode vector = vectors.get(i);
            tests.add(DynamicTest.dynamicTest(names.get(i), () -> check(vector)));
        }
        return tests.stream();
    }

    /** Several tests open the same jar; the file system stays open for the JVM and is shared. */
    private static FileSystem zip(java.net.URI location) throws IOException {
        try {
            return FileSystems.newFileSystem(location, Map.of());
        } catch (java.nio.file.FileSystemAlreadyExistsException e) {
            return FileSystems.getFileSystem(location);
        }
    }

    private static void check(JsonNode vector) {
        String secret = vector.path("secret").asString();
        if (vector.has("cases") && vector.path("cases").get(0).has("code")) {
            for (JsonNode c : vector.path("cases")) {
                assertThat(Totp.code(secret, c.path("step").asLong())).isEqualTo(c.path("code").asString());
                assertThat(Totp.stepOf(c.path("time").asLong())).isEqualTo(c.path("step").asLong());
            }
            return;
        }
        if (vector.has("cases")) {
            return; // otpauth URI: the URI is built by the portal, not by the gateway or this stand-in
        }
        Totp.State state = vector.has("initial") ? initial(vector.path("initial")) : Totp.State.fresh();
        long wrongCodes = vector.path("enrollment").path("wrongCodes").asLong(0);
        long enrollmentStart = vector.has("enrollment") ? at(vector.path("enrollment").path("createdAt")) : 0;
        boolean pending = vector.has("enrollment");
        for (JsonNode step : vector.path("steps")) {
            long at = at(step.path("at"));
            JsonNode expected = step.path("expected");
            switch (step.path("op").asString()) {
                case "verify" -> {
                    Totp.Verification result = Totp.verify(secret, state, step.path("code").asString(), at);
                    assertThat(result.result()).as(vector.path("description").asString()).isEqualTo(expected.path("result").asString());
                    if (expected.has("retryAfterSeconds")) {
                        assertThat(result.retryAfterSeconds()).isEqualTo(expected.path("retryAfterSeconds").asLong());
                    }
                    state = result.state();
                    assertAfter(state, expected.path("after"));
                }
                case "burn" -> {
                    state = Totp.burn(state, at);
                    assertAfter(state, expected.path("after"));
                }
                case "confirm" -> {
                    String code = step.path("code").asString();
                    String result;
                    if (!code.matches("^[0-9]{6}$")) {
                        result = "malformed";
                    } else if (!pending || at > enrollmentStart + 600) {
                        pending = false;
                        result = "enrollment_invalid";
                    } else {
                        long proven = Totp.enrollmentStep(secret, code, at);
                        if (proven >= 0) {
                            pending = false;
                            result = "active";
                            state = Totp.activate(state, proven);
                            if (expected.has("lastAcceptedStep")) {
                                assertThat(proven).isEqualTo(expected.path("lastAcceptedStep").asLong());
                            }
                        } else if (++wrongCodes >= 3) {
                            pending = false;
                            result = "enrollment_invalid";
                        } else {
                            result = "invalid_code";
                        }
                    }
                    assertThat(result).as(vector.path("description").asString()).isEqualTo(expected.path("result").asString());
                }
                default -> throw new AssertionError("op " + step.path("op").asString());
            }
        }
    }

    private static void assertAfter(Totp.State state, JsonNode after) {
        if (after.has("lastAcceptedStep")) {
            assertThat(state.lastAcceptedStep()).isEqualTo(after.path("lastAcceptedStep").isNull() ? null : after.path("lastAcceptedStep").asLong());
        }
        if (after.has("lockedUntil")) {
            assertThat(state.lockedUntil()).isEqualTo(after.path("lockedUntil").isNull() ? null : at(after.path("lockedUntil")));
        }
        if (after.has("disabled")) {
            assertThat(state.disabled()).isEqualTo(after.path("disabled").asBoolean());
        }
    }

    private static Totp.State initial(JsonNode node) {
        List<Long> failures = new ArrayList<>();
        node.path("failures").forEach(f -> failures.add(at(f)));
        List<Long> daily = new ArrayList<>();
        node.path("dailyFailures").forEach(f -> daily.add(at(f)));
        return new Totp.State(node.path("lastAcceptedStep").isNull() ? null : node.path("lastAcceptedStep").asLong(), failures, daily,
                node.path("lockedUntil").isNull() || !node.has("lockedUntil") ? null : at(node.path("lockedUntil")),
                node.path("disabled").asBoolean(false), null);
    }

    private static long at(JsonNode iso) {
        return Instant.parse(iso.asString()).getEpochSecond();
    }
}
