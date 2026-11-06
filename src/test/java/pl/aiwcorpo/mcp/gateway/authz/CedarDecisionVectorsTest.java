package pl.aiwcorpo.mcp.gateway.authz;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import pl.aiwcorpo.mcp.cedar.entities.Caller;
import pl.aiwcorpo.mcp.cedar.entities.ResourceRef;
import pl.aiwcorpo.mcp.cedar.entities.ResourceTypes;
import pl.aiwcorpo.mcp.cedar.entities.ScopeMapping;
import pl.aiwcorpo.mcp.cedar.entities.ToolDescriptor;
import pl.aiwcorpo.mcp.gateway.support.Snapshots;
import pl.aiwcorpo.mcp.gateway.support.Vectors;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * The gateway-level vectors of policy-decisions/ (mcp-contracts 7.0.0) through the gateway's own authorizer: the platform policies of the
 * contracts jar and the step-up override of the examples (an override of the administrator, not a platform policy), the resource types and the
 * scope mapping the vector names, and the decision the vector expects.
 */
class CedarDecisionVectorsTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final List<String> CLIENTS = List.of("claude-code", "claude-ai");

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
            if (document.path("builder").has("adjustment")) {
                // The vector takes the refs out of the request after the builder made it, which the gateway never does: its builder always
                // gives them, and a request without them is the contract's own fail-closed case (the entity builder vectors).
                continue;
            }
            if (vector.name().equals("gw-unknown-tool-denied.json")) {
                // The vector evaluates a request whose Tool entity is missing. The gateway builds the entity from the registry
                // and never evaluates a tool that the registry does not have (not_found_or_denied, GatewayIntegrationTest).
                continue;
            }
            tests.add(DynamicTest.dynamicTest(vector.name(), () -> {
                JsonNode builder = document.path("builder");
                List<ResourceTypes> declared = new ArrayList<>();
                builder.path("resourceTypes").forEach(file -> declared.add(ResourceTypes.fromJson(Vectors.contractFile(file.asString()))));
                ResourceTypes types = ResourceTypes.union(declared);
                ScopeMapping mapping = ScopeMapping.fromJson(types, Vectors.contractFile(builder.path("scopeMapping").asString()), true);
                CedarToolAuthorizer authorizer = new CedarToolAuthorizer(
                        Snapshots.source(Snapshots.of(1, types, mapping,
                                Map.of("step-up.cedar", Vectors.contractFile("cedar/examples/overrides/step-up.cedar")), CLIENTS)), JSON);
                JsonNode input = builder.path("input");
                JsonNode tool = input.path("tool");
                List<ResourceRef> refs = new ArrayList<>();
                tool.path("resourceRefs").forEach(r -> refs.add(new ResourceRef(r.path("argument").asString(), r.path("type").asString())));
                ToolDescriptor descriptor = new ToolDescriptor(tool.path("serverId").asString(), tool.path("system").asString(),
                        tool.path("name").asString(), tool.path("risk").asString(), tool.path("action").asString(), refs);
                JsonNode c = input.path("caller");
                List<String> groups = new ArrayList<>();
                c.path("grp").forEach(g -> groups.add(g.asString()));
                Caller caller = Caller.of(c.path("sub").asString(), c.path("usr").asString(), groups, c.path("azp").asString());
                if (c.has("mfa")) {
                    caller = caller.withMfaAge(c.path("mfa").asLong());
                }
                CedarToolAuthorizer.Evaluation result = authorizer.evaluate(caller, descriptor,
                        JSON.convertValue(input.path("arguments"), Map.class), List.of(), input.path("credentialType").asString(null));
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
