package pl.aiwcorpo.mcp.gateway.support;

import java.util.List;
import java.util.Map;

import com.cedarpolicy.model.policy.PolicySet;

import pl.aiwcorpo.mcp.cedar.entities.McpCedarSchema;
import pl.aiwcorpo.mcp.cedar.entities.PolicyFragments;
import pl.aiwcorpo.mcp.cedar.entities.ResourceTypes;
import pl.aiwcorpo.mcp.cedar.entities.ScopeMapping;
import pl.aiwcorpo.mcp.gateway.policy.PolicyService;
import pl.aiwcorpo.mcp.gateway.policy.PolicySource;

/** Policy data for unit tests of the authorizer: the platform policies plus the given ones, with the given types and mapping. */
public final class Snapshots {

    private Snapshots() {
    }

    public static PolicyService.Snapshot of(long revision, ResourceTypes types, ScopeMapping mapping, Map<String, String> extraPolicyFiles,
                                            List<String> allowedClients) {
        PolicySet policies = PolicyFragments.merge(McpCedarSchema.platformPolicies(), PolicyFragments.policySet(extraPolicyFiles));
        return new PolicyService.Snapshot(revision, types, mapping, policies, allowedClients, Map.of(), Map.of(), List.of(), null);
    }

    public static PolicySource source(PolicyService.Snapshot snapshot) {
        return () -> snapshot;
    }
}
