package pl.aiwcorpo.mcp.gateway.primitive;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;

import org.junit.jupiter.api.Test;

import pl.aiwcorpo.mcp.gateway.support.Manifests;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/** A pattern that got past the grammar still costs a bounded time and no stack when a value is matched against it. */
class BoundedMatchTest {

    @Test
    void aPatternThatBacktracksExponentiallyGivesUpAtTheDeadline() {
        long started = System.nanoTime();

        boolean matched = BoundedMatch.matches("^(.*a){12}$", "a".repeat(30) + "b");

        assertThat(matched).isFalse();
        assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(1));
    }

    @Test
    void aPatternThatRecursesDeeplyIsARefusalAndNotAnError() {
        assertThat(BoundedMatch.matches("^(a|aa)+$", "a".repeat(4000) + "b")).isFalse();
    }

    @Test
    void anOrdinaryPatternMatchesAsItDid() {
        assertThat(BoundedMatch.matches("^[A-Z]{2,8}-[0-9]{1,6}$", "ABC-123")).isTrue();
        assertThat(BoundedMatch.matches("^[A-Z]{2,8}-[0-9]{1,6}$", "ABC-123\n")).isFalse();
    }

    @Test
    void aPromptWhoseRuleSlippedThroughIsRefusedAtTheRequestWithinTheDeadline() {
        JsonMapper json = JsonMapper.builder().build();
        ObjectNode manifest = Manifests.jira("1.0.0");
        Manifests.addPrompt(manifest, "summarize", "Summarize");
        ObjectNode entry = (ObjectNode) manifest.path("prompts").get(0);
        ((ObjectNode) entry.path("argumentRules").get(0)).put("pattern", "^(.*a){12}$");
        ObjectNode arguments = json.createObjectNode().put("ticketId", "a".repeat(30) + "b");
        long started = System.nanoTime();

        PromptRenderer.Outcome outcome = PromptRenderer.render(json, entry, type -> java.util.Optional.empty(), arguments);

        assertThat(outcome).isInstanceOf(PromptRenderer.Refused.class);
        assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(1));
    }
}
