package pl.aiwcorpo.mcp.gateway.net;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import pl.aiwcorpo.mcp.gateway.support.Vectors;
import tools.jackson.databind.JsonNode;

/** The vectors of {@code address-refusal/} (C5, CC-249): which addresses a server may have, however the address is written. */
class AddressPolicyVectorsTest {

    private final AddressPolicy policy = new AddressPolicy(false);

    private static AddressPolicy policyFor(JsonNode input) {
        List<String> refused = new ArrayList<>();
        input.path("refusedAddresses").forEach(entry -> refused.add(entry.asString()));
        return new AddressPolicy(false, refused);
    }

    @TestFactory
    List<DynamicTest> theVectors() {
        List<DynamicTest> tests = new ArrayList<>();
        for (Vectors.Vector vector : Vectors.of("address-refusal")) {
            tests.add(DynamicTest.dynamicTest(vector.name(), () -> run(vector.document())));
        }
        assertThat(tests).hasSize(Vectors.of("address-refusal").size());
        assertThat(tests).hasSizeGreaterThanOrEqualTo(70);
        return tests;
    }

    private void run(JsonNode vector) {
        JsonNode input = vector.path("input");
        JsonNode expected = vector.path("expected");
        String why = vector.path("description").asString();
        AddressPolicy policy = policyFor(input);
        if (input.has("address")) {
            AddressPolicy.Verdict verdict = policy.judge(input.path("address").asString());
            assertThat(verdict.allowed()).as(why).isEqualTo(expected.path("allowed").asBoolean());
            if (!verdict.allowed()) {
                assertThat(verdict.cls()).as(why).isEqualTo(expected.path("class").asString());
                assertThat(verdict.judgedAs()).as(why).isEqualTo(expected.path("judgedAs").asString(null));
            }
        } else if (input.has("resolved")) {
            List<byte[]> addresses = new ArrayList<>();
            input.path("resolved").forEach(address -> addresses.add(AddressPolicy.parseLiteral(address.asString()).orElseThrow()));
            assertRefusal(policy.checkResolved(addresses), expected, why);
        } else {
            Optional<ServerUrl> url = ServerUrl.parse(input.path("url").asString());
            assertThat(url).as(why).isPresent();
            Optional<byte[]> literal = AddressPolicy.parseLiteral(url.get().host());
            if (expected.path("needsResolution").asBoolean(false)) {
                assertThat(literal).as(why).isEmpty();
                assertThat(url.get().host()).isEqualTo(expected.path("host").asString());
                return;
            }
            assertThat(literal).as("a literal address: " + why).isPresent();
            assertThat(url.get().host()).as(why).isEqualTo(expected.path("host").asString());
            assertRefusal(policy.check(url.get().host()), expected, why);
        }
    }

    private static void assertRefusal(Optional<AddressPolicy.Refusal> refusal, JsonNode expected, String why) {
        assertThat(refusal.isEmpty()).as(why).isEqualTo(expected.path("allowed").asBoolean());
        if (refusal.isPresent()) {
            assertThat(refusal.get().reason()).as(why).isEqualTo(expected.path("reason").asString());
            assertThat(refusal.get().address()).as(why).isEqualTo(expected.path("address").asString(refusal.get().address()));
            assertThat(refusal.get().cls()).as(why).isEqualTo(expected.path("class").asString(null));
        }
    }

    @Test
    void aNameIsResolvedAndEveryAddressIsJudgedAndTheAnswerOfTheMomentCounts() {
        AddressPolicy rebinding = new AddressPolicy(false, host -> {
            try {
                return List.of(InetAddress.getByAddress(host, new byte[] {10, 0, 0, 5}), InetAddress.getByAddress(host, new byte[] {(byte) 169, (byte) 254, (byte) 169, (byte) 254}));
            } catch (java.net.UnknownHostException e) {
                throw new IllegalStateException(e);
            }
        });

        Optional<AddressPolicy.Refusal> refusal = rebinding.check("mcp-notes.corp.test");

        assertThat(refusal).isPresent();
        assertThat(refusal.get().address()).isEqualTo("169.254.169.254");
        assertThat(refusal.get().cls()).isEqualTo("link_local");
        assertThat(new AddressPolicy(false, host -> List.of()).check("nowhere.test").orElseThrow().reason()).isEqualTo("host_not_resolved");
    }

    @Test
    void theDevelopmentStackMayAllowLoopbackAndNothingElse() {
        AddressPolicy dev = new AddressPolicy(true);

        assertThat(dev.judge("127.0.0.1").allowed()).isTrue();
        assertThat(dev.judge("::1").allowed()).isTrue();
        assertThat(dev.judge("169.254.169.254").allowed()).isFalse();
        assertThat(dev.judge("0.0.0.0").allowed()).isFalse();
        assertThat(dev.judge("224.0.0.1").allowed()).isFalse();
    }

    @Test
    void anAddressIsNormalisedAndTheShapeOfTheUrlIsChecked() {
        assertThat(ServerUrl.parse("https://MCP-Notes.Corp.Test:8443/mcp").orElseThrow().uri().toString()).isEqualTo("https://mcp-notes.corp.test:8443/mcp");
        assertThat(ServerUrl.parse("http://2130706433/x").orElseThrow().uri().toString()).isEqualTo("http://127.0.0.1/x");
        assertThat(ServerUrl.parse("https://[::ffff:127.0.0.1]:9/mcp").orElseThrow().uri().toString()).isEqualTo("https://[::ffff:7f00:1]:9/mcp");
        assertThat(ServerUrl.parse("https://host/mcp").orElseThrow().port()).isEqualTo(443);
        assertThat(ServerUrl.parse("http://host/mcp").orElseThrow().port()).isEqualTo(80);
        for (String bad : List.of("ftp://host/", "https://", "https://user@host/", "https://host/#x", "https://host:0/", "https://host:70000/",
                "https://ho st/", "https:/host", "host", "", "https://-bad/")) {
            assertThat(ServerUrl.parse(bad)).as(bad).isEmpty();
        }
    }

    @Test
    void theMetadataAddressesOfOtherCloudsAreRefusedInEveryFormTheyCanBeWritten() {
        for (String address : List.of("100.100.100.200", "192.0.0.192", "169.254.169.254", "fd00:ec2::254",
                "::ffff:100.100.100.200", "::ffff:c000:c0", "::100.100.100.200", "64:ff9b::6464:64c8", "64:ff9b::c000:c0",
                "2002:6464:64c8::1", "2002:c000:c0::", "2002:a9fe:a9fe::1")) {
            AddressPolicy.Verdict verdict = policy.judge(address);

            assertThat(verdict.allowed()).as(address).isFalse();
            assertThat(verdict.cls()).as(address).isIn("metadata", "link_local");
        }
        for (String text : List.of("http://1684301000/", "http://0x64.0x64.0x64.0xc8/", "http://0300.0.0.0300/", "http://3221225664/")) {
            String host = ServerUrl.parse(text).orElseThrow().host();
            assertThat(policy.check(host).map(AddressPolicy.Refusal::cls)).as(text).hasValue("metadata");
        }
        assertThat(policy.judge("100.100.100.201").allowed()).as("the neighbours are ordinary addresses").isTrue();
        assertThat(policy.judge("192.0.0.193").allowed()).isTrue();
        assertThat(policy.judge("2002:6464:64c9::1").allowed()).isTrue();
    }

    @Test
    void theDeploymentCanRefuseMoreAddressesAndRangesAlsoInEmbeddedForms() {
        AddressPolicy configured = new AddressPolicy(false, AddressPolicy.parseList("10.9.0.0/16, 203.0.113.7 ,fd12::/16,,"));

        assertThat(configured.judge("10.9.4.5").allowed()).isFalse();
        assertThat(configured.judge("10.9.4.5").cls()).isEqualTo("refused_by_configuration");
        assertThat(configured.judge("10.10.0.1").allowed()).isTrue();
        assertThat(configured.judge("203.0.113.7").allowed()).isFalse();
        assertThat(configured.judge("203.0.113.8").allowed()).isTrue();
        assertThat(configured.judge("fd12:1::5").allowed()).isFalse();
        assertThat(configured.judge("fd13::1").allowed()).isTrue();
        assertThat(configured.judge("::ffff:10.9.4.5").allowed()).as("an IPv4 range covers the mapped form").isFalse();
        assertThat(configured.judge("64:ff9b::a09:405").allowed()).as("and NAT64").isFalse();
        assertThat(configured.check("10.9.255.255").map(AddressPolicy.Refusal::message)).hasValueSatisfying(message -> assertThat(message).contains("10.9.255.255"));
        assertThat(new AddressPolicy(false).judge("10.9.4.5").allowed()).as("nothing is refused without the setting").isTrue();
    }

    @Test
    void aSettingThatIsNoAddressOrRangeStopsTheGateway() {
        for (String bad : List.of("10.9.0.0/33", "not-an-address", "10.0.0.0/x", "fd12::/129", "10.0.0.0/8/8", "example")) {
            org.assertj.core.api.Assertions.assertThatThrownBy(() -> new AddressPolicy(false, AddressPolicy.parseList(bad)))
                    .as(bad).isInstanceOf(IllegalArgumentException.class);
        }
    }
}
