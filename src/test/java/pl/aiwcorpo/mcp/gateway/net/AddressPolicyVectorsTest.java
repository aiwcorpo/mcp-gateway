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

    @TestFactory
    List<DynamicTest> theVectors() {
        List<DynamicTest> tests = new ArrayList<>();
        for (Vectors.Vector vector : Vectors.of("address-refusal")) {
            tests.add(DynamicTest.dynamicTest(vector.name(), () -> run(vector.document())));
        }
        assertThat(tests).hasSize(46);
        return tests;
    }

    private void run(JsonNode vector) {
        JsonNode input = vector.path("input");
        JsonNode expected = vector.path("expected");
        String why = vector.path("description").asString();
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
        } else if (input.has("connectedTo")) {
            assertRefusal(policy.checkResolved(List.of(AddressPolicy.parseLiteral(input.path("connectedTo").asString()).orElseThrow())), expected, why);
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
}
