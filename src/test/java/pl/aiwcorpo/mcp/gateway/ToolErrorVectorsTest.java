package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;

import pl.aiwcorpo.mcp.gateway.mcp.ToolErrors;
import pl.aiwcorpo.mcp.gateway.support.Contracts;
import pl.aiwcorpo.mcp.gateway.support.Vectors;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** The C10 vectors of tool-errors/ (mcp-contracts 3.0.2) and the error codes the gateway can produce. */
class ToolErrorVectorsTest {

    @Test
    void everyVectorIsJudgedAsTheContractExpects() {
        List<Vectors.Vector> vectors = Vectors.of("tool-errors");
        assertThat(vectors).hasSizeGreaterThanOrEqualTo(30);
        for (Vectors.Vector vector : vectors) {
            boolean expectedValid = vector.document().path("expected").path("valid").asBoolean();
            List<String> errors = Contracts.schemaErrors("schemas/tool-error.schema.json", vector.document().path("error"));
            assertThat(errors.isEmpty()).as(vector.name() + " " + errors).isEqualTo(expectedValid);
        }
    }

    @Test
    void everyValidVectorOfAKnownCodeIsRecognisedByTheGateway() {
        ToolErrors errors = new ToolErrors(JsonMapper.builder().build());
        for (Vectors.Vector vector : Vectors.of("tool-errors")) {
            if (!vector.document().path("expected").path("valid").asBoolean()) {
                continue;
            }
            JsonNode error = vector.document().path("error");
            JsonNode wrapped = errors.error(error.path("error").asString(), error.path("message").asString());
            assertThat(errors.codeOf(wrapped)).as(vector.name()).isEqualTo(error.path("error").asString());
        }
    }
}
