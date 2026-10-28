package pl.aiwcorpo.mcp.gateway.authz;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import pl.aiwcorpo.mcp.cedar.entities.Caller;
import pl.aiwcorpo.mcp.cedar.entities.ResourceRef;
import pl.aiwcorpo.mcp.cedar.entities.ToolDescriptor;
import pl.aiwcorpo.mcp.cedar.entities.VirtualServerScope;
import pl.aiwcorpo.mcp.gateway.config.GatewayProperties;
import pl.aiwcorpo.mcp.gateway.policy.BundleFetcher;
import pl.aiwcorpo.mcp.gateway.policy.PolicyService;
import pl.aiwcorpo.mcp.gateway.support.PolicyServer;
import pl.aiwcorpo.mcp.gateway.support.TestBundles;
import pl.aiwcorpo.mcp.gateway.support.Vectors;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * The gateway-level vectors of policy-decisions/ (mcp-contracts 3.1.0) through the gateway's own loader and evaluator: the
 * bundle is pulled, verified and loaded like in production, and the decision is the one the vector expects. The step-up rule is
 * not in a production bundle, so the vectors that only it decides are not applicable.
 */
class CedarDecisionVectorsTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static PolicyServer server;
    private static PolicyService policies;
    private static CedarToolAuthorizer authorizer;

    @BeforeAll
    static void load() throws Exception {
        server = new PolicyServer();
        server.publishMain(TestBundles.main(TestBundles.revision(1), Map.of()));
        Path keys = Files.createTempDirectory("policy-keys");
        Files.writeString(keys.resolve("main.pem"), TestBundles.publicKeyPem("test-policy-bundle"));
        policies = new PolicyService(new GatewayProperties.Policy(URI.create(server.mainUrl()), null, "test-policy-bundle",
                keys.resolve("main.pem").toString(), null, null, true, null, null, null, Duration.ofMinutes(1),
                Duration.ofMinutes(1), Duration.ofSeconds(10), Duration.ofSeconds(1)), new BundleFetcher(), new SimpleMeterRegistry())
                .start();
        authorizer = new CedarToolAuthorizer(policies, JSON);
    }

    @AfterAll
    static void stop() {
        policies.destroy();
        server.close();
    }

    @TestFactory
    List<DynamicTest> gatewayVectors() {
        List<DynamicTest> tests = new ArrayList<>();
        for (Vectors.Vector vector : Vectors.of("policy-decisions")) {
            JsonNode document = vector.document();
            if (!vector.name().startsWith("gw-") || !"gateway".equals(document.path("builder").path("level").asString())) {
                continue;
            }
            Set<String> expectedPolicies = new TreeSet<>();
            document.path("expected").path("determiningPolicies").forEach(p -> expectedPolicies.add(p.asString()));
            if (expectedPolicies.contains("destructive-requires-fresh-mfa")) {
                continue;
            }
            if (vector.name().equals("gw-unknown-tool.json")) {
                // The vector evaluates a request whose Tool entity is missing. The gateway builds the entity from the registry
                // and never evaluates a tool that the registry does not have (not_found_or_denied, GatewayIntegrationTest).
                continue;
            }
            tests.add(DynamicTest.dynamicTest(vector.name(), () -> {
                JsonNode input = document.path("builder").path("input");
                JsonNode tool = input.path("tool");
                List<ResourceRef> refs = new ArrayList<>();
                tool.path("resourceRefs").forEach(r -> refs.add(new ResourceRef(r.path("argument").asString(), r.path("type").asString())));
                ToolDescriptor descriptor = new ToolDescriptor(tool.path("serverId").asString(), tool.path("system").asString(),
                        tool.path("name").asString(), tool.path("risk").asString(), tool.path("action").asString(), refs);
                JsonNode c = input.path("caller");
                List<String> groups = new ArrayList<>();
                c.path("grp").forEach(g -> groups.add(g.asString()));
                Caller caller = Caller.of(c.path("sub").asString(), c.path("usr").asString(), groups, c.path("azp").asString());
                if (c.has("vs")) {
                    Map<String, List<String>> vsc = new LinkedHashMap<>();
                    c.path("vsc").properties().forEach(e -> {
                        List<String> ids = new ArrayList<>();
                        e.getValue().forEach(id -> ids.add(id.asString()));
                        vsc.put(e.getKey(), ids);
                    });
                    caller = caller.withVirtualServer(VirtualServerScope.fromClaims(c.path("vs").asString(), vsc));
                }
                CedarToolAuthorizer.Evaluation result = authorizer.evaluate(caller, descriptor,
                        JSON.convertValue(input.path("arguments"), Map.class), List.of());
                assertThat(result.decision().allowed()).as(document.path("description").asString())
                        .isEqualTo("allow".equals(document.path("expected").path("decision").asString()));
                SortedSet<String> actual = new TreeSet<>(result.determiningPolicies());
                assertThat(actual).as("determining policies of " + vector.name()).isEqualTo(expectedPolicies);
            }));
        }
        assertThat(tests).hasSizeGreaterThanOrEqualTo(15);
        return tests;
    }
}
