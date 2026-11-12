package pl.aiwcorpo.mcp.gateway.confirm;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class TextHygieneTest {

    private static final String WARNING_SIGN = "⚠";
    private static final String VS16 = "️";

    @Test
    void aSingleVariationSelectorDirectlyAfterAnEmojiIsAllowed() {
        assertThat(TextHygiene.containsForbidden("Careful " + WARNING_SIGN + VS16 + " deletes data")).isFalse();
        assertThat(TextHygiene.containsForbidden("❤" + VS16)).isFalse();
    }

    @Test
    void aVariationSelectorWithoutAnEmojiBeforeItIsForbidden() {
        assertThat(TextHygiene.containsForbidden(VS16)).as("alone").isTrue();
        assertThat(TextHygiene.containsForbidden(VS16 + WARNING_SIGN)).as("leading").isTrue();
        assertThat(TextHygiene.containsForbidden("a" + VS16)).as("after a letter").isTrue();
        assertThat(TextHygiene.containsForbidden(" " + VS16)).as("after a space").isTrue();
    }

    @Test
    void aSecondVariationSelectorInARowIsForbidden() {
        assertThat(TextHygiene.containsForbidden(WARNING_SIGN + VS16 + VS16)).isTrue();
    }

    @Test
    void otherVariationSelectorsAreForbiddenAlsoAfterAnEmoji() {
        assertThat(TextHygiene.containsForbidden(WARNING_SIGN + "︎")).isTrue();
        assertThat(TextHygiene.containsForbidden(WARNING_SIGN + "󠄀")).isTrue();
    }

    @Test
    void escapingKeepsTheEmojiSequenceAndShowsTheOthers() {
        assertThat(TextHygiene.escape(WARNING_SIGN + VS16 + "x")).isEqualTo(WARNING_SIGN + VS16 + "x");
        assertThat(TextHygiene.escape("a" + VS16 + VS16)).isEqualTo("a\\ufe0f\\ufe0f");
    }
}
