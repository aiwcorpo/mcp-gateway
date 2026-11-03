package pl.aiwcorpo.mcp.gateway.killswitch;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.Test;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

/** The cache of the switches of one instance (CC-194): at most the TTL old, never lengthened by a failed read, fail-closed. */
class KillSwitchesTest {

    private static final KillSwitchStore.Entry TOOL = new KillSwitchStore.Entry("mcp-jira", "update_issue", "admin", Instant.EPOCH, "incident");
    private static final KillSwitchStore.Entry SERVER = new KillSwitchStore.Entry("mcp-gitlab", null, "admin", Instant.EPOCH, "incident");

    private final AtomicLong clock = new AtomicLong();
    private final AtomicBoolean down = new AtomicBoolean();
    private final AtomicInteger reads = new AtomicInteger();
    private volatile List<KillSwitchStore.Entry> stored = List.of(TOOL, SERVER);

    private KillSwitches switches() {
        return new KillSwitches(() -> {
            reads.incrementAndGet();
            if (down.get()) {
                throw new IllegalStateException("database down");
            }
            return stored;
        }, Duration.ofSeconds(5), clock::get, new SimpleMeterRegistry());
    }

    @Test
    void aSwitchOfAToolAndOfAServer() {
        KillSwitches switches = switches();
        assertThat(switches.status("mcp-jira", "update_issue")).isEqualTo(KillSwitches.Status.ON);
        assertThat(switches.status("mcp-jira", "get_issue")).isEqualTo(KillSwitches.Status.OFF);
        assertThat(switches.status("mcp-gitlab", "anything")).isEqualTo(KillSwitches.Status.ON);
        assertThat(switches.status("mcp-confluence", "update_issue")).isEqualTo(KillSwitches.Status.OFF);
    }

    @Test
    void aChangeIsSeenAtTheLatestWhenTheCopyIsFiveSecondsOld() {
        KillSwitches switches = switches();
        stored = List.of();
        clock.addAndGet(Duration.ofSeconds(4).toNanos());
        assertThat(switches.status("mcp-jira", "update_issue")).as("the copy is still young").isEqualTo(KillSwitches.Status.ON);
        clock.addAndGet(Duration.ofSeconds(2).toNanos());
        assertThat(switches.status("mcp-jira", "update_issue")).as("older than the TTL: read again").isEqualTo(KillSwitches.Status.OFF);
    }

    @Test
    void aFailedReadIsNotAnExtensionOfTheCopy() {
        KillSwitches switches = switches();
        down.set(true);
        clock.addAndGet(Duration.ofSeconds(6).toNanos());
        assertThat(switches.status("mcp-jira", "get_issue")).isEqualTo(KillSwitches.Status.UNREADABLE);
        assertThat(switches.readable()).isFalse();
        assertThat(switches.entries()).isEmpty();
    }

    @Test
    void aStalledDatabaseIsAskedOncePerSecondNotOncePerCall() {
        KillSwitches switches = switches();
        down.set(true);
        clock.addAndGet(Duration.ofSeconds(6).toNanos());
        int before = reads.get();
        for (int i = 0; i < 50; i++) {
            assertThat(switches.status("mcp-jira", "get_issue")).isEqualTo(KillSwitches.Status.UNREADABLE);
        }
        assertThat(reads.get() - before).isEqualTo(1);
        clock.addAndGet(Duration.ofSeconds(2).toNanos());
        down.set(false);
        assertThat(switches.status("mcp-jira", "update_issue")).as("readable again").isEqualTo(KillSwitches.Status.ON);
    }

    @Test
    void anInstanceThatStartsWithoutTheDatabaseIsUnreadableNotOpen() {
        down.set(true);
        KillSwitches switches = switches();
        assertThat(switches.status("mcp-jira", "get_issue")).isEqualTo(KillSwitches.Status.UNREADABLE);
    }
}
