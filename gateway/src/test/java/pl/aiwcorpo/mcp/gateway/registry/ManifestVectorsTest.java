package pl.aiwcorpo.mcp.gateway.registry;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import pl.aiwcorpo.mcp.gateway.server.CredentialPolicy;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.support.Vectors;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** The manifest vectors of mcp-contracts 3.1.0 (CC-115, CC-123: title required, inputSchema closed and bounded) as the gateway judges them. */
class ManifestVectorsTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    @TestFactory
    List<DynamicTest> everyManifestVector() {
        ManifestValidator validator = new ManifestValidator(JSON);
        List<DynamicTest> tests = new ArrayList<>();
        List<Vectors.Vector> vectors = Vectors.of("manifests");
        assertThat(vectors).hasSizeGreaterThanOrEqualTo(52);
        for (Vectors.Vector vector : vectors) {
            tests.add(DynamicTest.dynamicTest(vector.name(), () -> {
                JsonNode manifest = vector.document().path("manifest");
                String serverId = manifest.path("serverId").asString("mcp-jira");
                McpServer configured = new McpServer(serverId, serverId.replaceFirst("^mcp-", ""),
                        URI.create("https://" + serverId + ".internal:8443/mcp"), "1.0.0", true,
                        new CredentialPolicy(true, Set.of("user-secret"), List.of(), false), Map.of());
                boolean valid = vector.document().path("expected").path("valid").asBoolean();
                assertThat(validator.violations(manifest, configured).isEmpty()).as(vector.document().path("description").asString())
                        .isEqualTo(valid);
            }));
        }
        return tests;
    }
}
