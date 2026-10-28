package pl.aiwcorpo.mcp.gateway.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

/** The acknowledgements of the devstack profile are never in the jar: not in a configuration file, not as a profile file. */
class ConsentPackagingTest {

    @Test
    void noConfigurationFileOnTheClasspathCarriesTheAcknowledgements() throws IOException {
        PathMatchingResourcePatternResolver resolver = new PathMatchingResourcePatternResolver();
        Resource[] files = resolver.getResources("classpath*:application*");
        assertThat(files).isNotEmpty();
        for (Resource file : files) {
            String text = new String(file.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            assertThat(text).as(file.getDescription()).doesNotContain("devstack.acknowledged").doesNotContain("DEVSTACK_ACKNOWLEDGED");
            assertThat(file.getFilename()).as("a devstack profile file would carry its own settings").doesNotContain("devstack");
        }
        for (Resource file : resolver.getResources("classpath*:META-INF/spring.factories")) {
            String text = new String(file.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            assertThat(text).doesNotContain("ACKNOWLEDGED");
        }
    }
}
