package pl.aiwcorpo.mcp.testserver;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import com.nimbusds.jose.jwk.JWKSet;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** The test server's receiver must agree with every C2 vector of mcp-contracts 3.0.2, including the reason. */
class InternalJwtVerifierVectorTest {

    private static final String ROOT = "mcp-contracts/test-vectors/";
    private static final JsonMapper JSON = JsonMapper.builder().build();

    @TestFactory
    Stream<DynamicTest> allJwtVectors() throws Exception {
        List<Path> files;
        URL dir = getClass().getClassLoader().getResource(ROOT + "jwt/valid.json");
        assertThat(dir).as("test-vectors jar on the classpath").isNotNull();
        FileSystem fs = dir.getProtocol().equals("jar")
                ? zip(dir.toURI())
                : null;
        Path jwtDir = (fs != null ? fs.provider().getPath(dir.toURI()) : Path.of(dir.toURI())).getParent();
        try (Stream<Path> stream = Files.list(jwtDir)) {
            files = stream.filter(p -> p.toString().endsWith(".json")).sorted().toList();
        }
        assertThat(files).hasSizeGreaterThanOrEqualTo(40);
        return files.stream().map(file -> DynamicTest.dynamicTest(file.getFileName().toString(), () -> check(file)));
    }

    /** Other tests open the same jar; the file system is shared and stays open for the JVM. */
    private static FileSystem zip(java.net.URI location) throws IOException {
        try {
            return FileSystems.newFileSystem(location, Map.of());
        } catch (java.nio.file.FileSystemAlreadyExistsException e) {
            return FileSystems.getFileSystem(location);
        }
    }

    private void check(Path file) throws IOException, ParseException, URISyntaxException {
        JsonNode vector = JSON.readTree(Files.readString(file));
        JsonNode verifier = vector.get("verifier");
        JWKSet jwks = JWKSet.parse(resource(verifier.get("jwks").asString()));
        Clock clock = Clock.fixed(Instant.parse(verifier.get("now").asString()), ZoneOffset.UTC);
        InternalJwtVerifier subject = new InternalJwtVerifier(verifier.get("issuer").asString(),
                verifier.get("audience").asString(), verifier.path("allowTestKeys").asBoolean(false),
                verifier.path("devstackProfile").asBoolean(false), jwks::getKeyByKeyId, clock)
                .asAdapterReceiver("adapter".equals(verifier.path("receiverMode").asString("native")));
        for (JsonNode jti : verifier.path("seenJtis")) {
            subject.markSeen(jti.asString(), Long.MAX_VALUE / 2);
        }
        JsonNode request = vector.get("request");
        InternalJwtVerifier.RequestRule rule = "jsonrpc".equals(request.get("kind").asString())
                ? InternalJwtVerifier.RequestRule.forJsonRpc(request.get("method").asString(),
                        request.path("toolName").asString(null))
                : InternalJwtVerifier.RequestRule.forHttp(request.get("method").asString(),
                        request.get("path").asString());
        String token = vector.path("token").asString(null);
        String authorization = token == null || token.isEmpty() ? null : "Bearer " + token;

        InternalJwtVerifier.Result result = subject.verify(authorization, request.path("xRequestId").asString(null), rule);

        JsonNode expected = vector.get("expected");
        assertThat(result.valid()).as(vector.path("description").asString()).isEqualTo(expected.get("valid").asBoolean());
        if (!expected.get("valid").asBoolean()) {
            assertThat(result.reason()).isEqualTo(expected.get("reason").asString());
        }
    }

    private static String resource(String relative) {
        try (InputStream in = InternalJwtVerifierVectorTest.class.getClassLoader().getResourceAsStream(ROOT + relative)) {
            assertThat(in).as(relative).isNotNull();
            return new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
