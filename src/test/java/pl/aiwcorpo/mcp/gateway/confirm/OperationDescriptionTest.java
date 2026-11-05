package pl.aiwcorpo.mcp.gateway.confirm;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;

import pl.aiwcorpo.mcp.cedar.entities.ResourceRef;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

class OperationDescriptionTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    @Test
    void argumentsOutsideTheBasicPlaneAreCutByCodePointsAndNeverThrow() {
        ObjectNode arguments = JSON.createObjectNode();
        for (String name : List.of("a", "b", "c", "d")) {
            arguments.put(name, "\uD83D\uDE00".repeat(250));
        }
        PendingCall.Display display = OperationDescription.of(JSON, "jira__delete_issue", "jira", arguments, List.of());
        assertThat(display.arguments()).hasSize(4);
        assertThat(display.arguments()).allMatch(PendingCall.Argument::truncated);
        assertThat(display.description().codePointCount(0, display.description().length())).isLessThanOrEqualTo(1000);
        assertThat(display.description()).endsWith("...");
        // No half of a surrogate pair is left at a cut.
        assertThat(display.description().codePoints().noneMatch(cp -> cp >= 0xD800 && cp <= 0xDFFF)).isTrue();
    }

    @Test
    void forbiddenCharactersAreShownEscaped() {
        ObjectNode arguments = JSON.createObjectNode();
        arguments.put("issueKey", "ABC-1\u202E");
        PendingCall.Display display = OperationDescription.of(JSON, "jira__delete_issue", "jira", arguments,
                List.of(new ResourceRef("issueKey", "Jira::Issue")));
        assertThat(display.arguments().getFirst().value()).contains("\\u202e").doesNotContain("\u202E");
        assertThat(display.resource()).as("an identifier with such a character is no resource").isNull();
    }
}
