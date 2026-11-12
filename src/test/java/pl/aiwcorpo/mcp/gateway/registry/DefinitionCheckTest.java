package pl.aiwcorpo.mcp.gateway.registry;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

class DefinitionCheckTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    private static JsonNode definition(String description) {
        return JSON.createObjectNode().put("name", "get_issue").put("description", description);
    }

    @Test
    void anEmojiWithItsVariationSelectorDoesNotHideText() {
        assertThat(DefinitionCheck.hidesText(definition("⚠️ Deletes the issue"))).isFalse();
    }

    @Test
    void aLoneLeadingOrDoubledVariationSelectorHidesText() {
        assertThat(DefinitionCheck.hidesText(definition("️ Deletes the issue"))).as("leading").isTrue();
        assertThat(DefinitionCheck.hidesText(definition("Deletes️ the issue"))).as("after a letter").isTrue();
        assertThat(DefinitionCheck.hidesText(definition("⚠️️ Deletes the issue"))).as("doubled").isTrue();
    }

    @Test
    void aVariationSelectorInAPropertyNameIsJudgedTheSameWay() {
        assertThat(DefinitionCheck.hidesText(JSON.createObjectNode().put("⚠️", "x"))).isFalse();
        assertThat(DefinitionCheck.hidesText(JSON.createObjectNode().put("a️", "x"))).isTrue();
    }
}
