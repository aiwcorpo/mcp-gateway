package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;

import pl.aiwcorpo.mcp.gateway.support.Contracts;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** The C8 vectors of mcp-contracts 2.2.5 (CC-120 among them) against the schema the gateway's events are checked with. */
class AuditVectorsTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    @Test
    void everyAuditVectorIsJudgedAsTheContractExpects() throws Exception {
        java.net.URI location = AuditVectorsTest.class.getClassLoader()
                .getResource("mcp-contracts/test-vectors/audit-events").toURI();
        try (FileSystem jar = location.getScheme().equals("jar") ? FileSystems.newFileSystem(location, java.util.Map.of()) : null) {
            check(jar == null ? Path.of(location) : jar.getPath("mcp-contracts/test-vectors/audit-events"));
        }
    }

    private static void check(Path directory) throws Exception {
        List<Path> vectors;
        try (Stream<Path> files = Files.list(directory)) {
            vectors = files.filter(f -> f.toString().endsWith(".json")).sorted().toList();
        }
        assertThat(vectors).hasSizeGreaterThan(30);
        assertThat(vectors.stream().map(f -> f.getFileName().toString())).contains("gateway-authentication-denied-expired.json",
                "gateway-authentication-denied-wrong-audience.json", "gateway-authentication-denied-jwks-unavailable.json",
                "gateway-authentication-denied-replay-store-unavailable.json", "invalid-authentication-with-backend-user.json",
                "invalid-authentication-jwks-unavailable-unauthenticated.json");
        for (Path vector : vectors) {
            JsonNode document = JSON.readTree(Files.readString(vector));
            boolean expectedValid = document.path("expected").path("valid").asBoolean();
            List<String> errors = Contracts.schemaErrors("schemas/audit-event.schema.json", document.path("event"));
            assertThat(errors.isEmpty()).as(vector.getFileName() + " " + errors).isEqualTo(expectedValid);
        }
    }
}
