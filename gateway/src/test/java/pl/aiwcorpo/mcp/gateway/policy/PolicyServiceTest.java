package pl.aiwcorpo.mcp.gateway.policy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import pl.aiwcorpo.mcp.gateway.config.GatewayProperties;
import pl.aiwcorpo.mcp.gateway.support.PolicyServer;
import pl.aiwcorpo.mcp.gateway.support.TestBundles;
import pl.aiwcorpo.mcp.policy.bundle.Channel;

/** The loader of C7 bundles: no start without one, no going back (also across a restart), the overrides awaited after a restart. */
class PolicyServiceTest {

    private PolicyServer server;
    private Path dir;
    private final SimpleMeterRegistry meters = new SimpleMeterRegistry();

    @BeforeEach
    void setUp() throws Exception {
        server = new PolicyServer();
        dir = Files.createTempDirectory("policy-service-test");
        Files.writeString(dir.resolve("main.pem"), TestBundles.publicKeyPem("test-policy-bundle"));
        Files.writeString(dir.resolve("overrides.pem"), TestBundles.publicKeyPem("test-policy-overrides"));
    }

    @AfterEach
    void tearDown() {
        server.close();
    }

    private PolicyService service(boolean withOverrides, String minimumMain, Duration startup, Duration grace) {
        return new PolicyService(new GatewayProperties.Policy(URI.create(server.mainUrl()),
                withOverrides ? URI.create(server.overridesUrl()) : null, "test-policy-bundle", dir.resolve("main.pem").toString(),
                withOverrides ? "test-policy-overrides" : null, withOverrides ? dir.resolve("overrides.pem").toString() : null, true,
                dir.resolve("state").toString(), minimumMain, null, Duration.ofMinutes(1), Duration.ofMinutes(1), startup, grace),
                new BundleFetcher(), meters, true);
    }

    private static final String FORBID = "@id(\"emergency\") forbid (principal, action == Action::\"call\", resource is Tool)"
            + " when { resource.name == \"get_issue\" };";

    @Test
    void aBundleKeyNamedTestIsRefusedWithoutTheDevelopmentSetting() {
        server.publishMain(TestBundles.main(TestBundles.revision(5), Map.of()));
        PolicyService strict = new PolicyService(new GatewayProperties.Policy(URI.create(server.mainUrl()), null, "test-policy-bundle",
                dir.resolve("main.pem").toString(), null, null, false, dir.resolve("strict-state").toString(), null, null,
                Duration.ofMinutes(1), Duration.ofMinutes(1), Duration.ofSeconds(2), Duration.ofSeconds(1)), new BundleFetcher(), meters,
                false);
        assertThatThrownBy(strict::start).isInstanceOf(IllegalStateException.class).hasMessageContaining("CC-068");
        assertThat(meters.find("gateway_policy_bundle_rejected_total").tag("reason", "test_key_not_allowed").counter())
                .as("the library refused the key by its name, not for some other reason").isNotNull();
    }

    @Test
    void aKeyNamedDevNeedsTheDevstackProfileAndTheTestKeySettingTogether() {
        server.publishMain(TestBundles.main(TestBundles.revision(5), Map.of()));
        GatewayProperties.Policy withDevKey = new GatewayProperties.Policy(URI.create(server.mainUrl()), null, "dev-policy-bundle",
                dir.resolve("main.pem").toString(), null, null, true, dir.resolve("dev-state").toString(), null, null,
                Duration.ofMinutes(1), Duration.ofMinutes(1), Duration.ofSeconds(2), Duration.ofSeconds(1));
        PolicyService production = new PolicyService(withDevKey, new BundleFetcher(), meters, false);
        assertThatThrownBy(production::start).isInstanceOf(IllegalStateException.class);
        assertThat(meters.find("gateway_policy_bundle_rejected_total").tag("reason", "test_key_not_allowed").counter()).isNotNull();

        PolicyService dev = new PolicyService(withDevKey, new BundleFetcher(), meters, true).start();
        try {
            assertThat(dev.revision()).isEqualTo(TestBundles.revision(5));
        } finally {
            dev.destroy();
        }
    }

    @Test
    void withoutTheDevstackProfileAStateDirectoryIsRequired() {
        assertThatThrownBy(() -> new PolicyService(new GatewayProperties.Policy(URI.create(server.mainUrl()), null, "policies-main",
                dir.resolve("main.pem").toString(), null, null, false, null, null, null, Duration.ofMinutes(1), Duration.ofMinutes(1),
                Duration.ofSeconds(2), Duration.ofSeconds(1)), new BundleFetcher(), meters, false))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("state-dir");
    }

    @Test
    void thereIsNoStartWithoutAMainBundle() {
        PolicyService service = service(false, null, Duration.ofSeconds(2), Duration.ofSeconds(1));
        assertThatThrownBy(service::start).isInstanceOf(IllegalStateException.class).hasMessageContaining("CC-068");
    }

    @Test
    void aBundleWithABadSignatureOrChangedBytesNeverStarts() {
        server.publishMain(TestBundles.mainSignedByTheWrongKey(TestBundles.revision(5)));
        assertThatThrownBy(() -> service(false, null, Duration.ofSeconds(2), Duration.ofSeconds(1)).start())
                .isInstanceOf(IllegalStateException.class);
        server.publishMain(TestBundles.tampered(TestBundles.main(TestBundles.revision(5), Map.of())));
        assertThatThrownBy(() -> service(false, null, Duration.ofSeconds(2), Duration.ofSeconds(1)).start())
                .isInstanceOf(IllegalStateException.class);
        assertThat(meters.find("gateway_policy_bundle_rejected_total").counters()).isNotEmpty();
    }

    @Test
    void anOlderOrEqualRevisionIsRefusedWhileRunning() {
        server.publishMain(TestBundles.main(TestBundles.revision(5), Map.of()));
        PolicyService service = service(false, null, Duration.ofSeconds(5), Duration.ofSeconds(1)).start();
        try {
            assertThat(service.revision()).isEqualTo(TestBundles.revision(5));
            server.publishMain(TestBundles.main(TestBundles.revision(4), Map.of()));
            service.sync(Channel.MAIN);
            assertThat(service.revision()).as("older").isEqualTo(TestBundles.revision(5));
            server.publishMain(TestBundles.main(TestBundles.revision(5), Map.of("other.cedar", FORBID)));
            service.sync(Channel.MAIN);
            assertThat(service.snapshot().orElseThrow().policies().toString()).as("same revision, other bytes").doesNotContain("emergency");
            server.publishMain(TestBundles.main(TestBundles.revision(6), Map.of("other.cedar", FORBID)));
            service.sync(Channel.MAIN);
            assertThat(service.revision()).isEqualTo(TestBundles.revision(6));
        } finally {
            service.destroy();
        }
    }

    @Test
    void aBadSignatureIsFetchedAgainSoThatAFixedSignatureUnderTheSamePointerIsTaken() {
        server.publishMain(TestBundles.main(TestBundles.revision(5), Map.of()));
        PolicyService service = service(false, null, Duration.ofSeconds(5), Duration.ofSeconds(1)).start();
        try {
            server.publishMain(TestBundles.mainSignedByTheWrongKey(TestBundles.revision(6)));
            service.sync(Channel.MAIN);
            int afterFirst = server.requests();
            service.sync(Channel.MAIN);
            assertThat(server.requests() - afterFirst).as("latest.json, archive and signature again").isEqualTo(3);
            assertThat(service.revision()).isEqualTo(TestBundles.revision(5));
            server.publishMain(TestBundles.main(TestBundles.revision(6), Map.of()));
            service.sync(Channel.MAIN);
            assertThat(service.revision()).isEqualTo(TestBundles.revision(6));
        } finally {
            service.destroy();
        }
    }

    @Test
    void aBundleThatIsNotNewerIsFetchedOnceAndIsNotAnError() {
        server.publishMain(TestBundles.main(TestBundles.revision(5), Map.of()));
        PolicyService service = service(false, null, Duration.ofSeconds(5), Duration.ofSeconds(1)).start();
        try {
            // latest.json went back to the revision in force: same content, nothing to learn from it again.
            server.publishMain(TestBundles.main(TestBundles.revision(4), Map.of()));
            service.sync(Channel.MAIN);
            int afterFirst = server.requests();
            for (int i = 0; i < 5; i++) {
                service.sync(Channel.MAIN);
            }
            assertThat(server.requests() - afterFirst).as("only the conditional latest.json request, answered 304").isEqualTo(5);
            assertThat(meters.find("gateway_policy_bundle_rejected_total").counters()).as("not an error").isEmpty();
            assertThat(service.revision()).isEqualTo(TestBundles.revision(5));
            server.publishMain(TestBundles.main(TestBundles.revision(6), Map.of()));
            service.sync(Channel.MAIN);
            assertThat(service.revision()).as("a newer bundle is still taken").isEqualTo(TestBundles.revision(6));
        } finally {
            service.destroy();
        }
    }

    @Test
    void theRollbackProtectionHoldsAcrossARestart() {
        server.publishMain(TestBundles.main(TestBundles.revision(7), Map.of()));
        service(false, null, Duration.ofSeconds(5), Duration.ofSeconds(1)).start().destroy();
        // The server now offers an older (validly signed) bundle: a restarted gateway does not take it.
        server.publishMain(TestBundles.main(TestBundles.revision(3), Map.of()));
        assertThatThrownBy(() -> service(false, null, Duration.ofSeconds(2), Duration.ofSeconds(1)).start())
                .isInstanceOf(IllegalStateException.class);
        // The same bundle again is fine.
        server.publishMain(TestBundles.main(TestBundles.revision(7), Map.of()));
        PolicyService again = service(false, null, Duration.ofSeconds(5), Duration.ofSeconds(1)).start();
        assertThat(again.revision()).isEqualTo(TestBundles.revision(7));
        again.destroy();
    }

    @Test
    void aConfiguredMinimumRevisionIsNeverUndercut() {
        server.publishMain(TestBundles.main(TestBundles.revision(2), Map.of()));
        assertThatThrownBy(() -> service(false, TestBundles.revision(9), Duration.ofSeconds(2), Duration.ofSeconds(1)).start())
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void overridesWithAPermitAreRefusedAndForbidRulesTakeEffect() {
        server.publishMain(TestBundles.main(TestBundles.revision(1), Map.of()));
        server.publishOverrides(TestBundles.overrides(TestBundles.revision(2), Map.of("permit.cedar",
                "@id(\"sneaky\") permit (principal, action == Action::\"call\", resource is Tool);")));
        PolicyService service = service(true, null, Duration.ofSeconds(5), Duration.ofSeconds(1)).start();
        try {
            assertThat(service.snapshot().orElseThrow().overrides()).isEmpty();
            server.publishOverrides(TestBundles.overrides(TestBundles.revision(3), Map.of("forbid.cedar", FORBID)));
            service.sync(Channel.OVERRIDES);
            assertThat(service.snapshot().orElseThrow().overrides()).isPresent();
        } finally {
            service.destroy();
        }
    }

    @Test
    void afterARestartTheGatewayWaitsForTheOverridesThatWereActive() {
        server.publishMain(TestBundles.main(TestBundles.revision(1), Map.of()));
        server.publishOverrides(TestBundles.overrides(TestBundles.revision(2), Map.of("forbid.cedar", FORBID)));
        service(true, null, Duration.ofSeconds(5), Duration.ofSeconds(1)).start().destroy();

        server.withdrawOverrides();
        long begun = System.nanoTime();
        PolicyService restarted = service(true, null, Duration.ofSeconds(5), Duration.ofSeconds(2)).start();
        try {
            assertThat(Duration.ofNanos(System.nanoTime() - begun)).as("it waited for the overrides").isGreaterThanOrEqualTo(Duration.ofMillis(1500));
            assertThat(restarted.snapshot().orElseThrow().overrides()).isEmpty();
            assertThat(restarted.ready()).as("after the grace period, with an alarm").isTrue();
        } finally {
            restarted.destroy();
        }
    }
}
