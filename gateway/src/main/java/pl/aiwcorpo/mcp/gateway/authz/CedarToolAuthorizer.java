package pl.aiwcorpo.mcp.gateway.authz;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.cedarpolicy.BasicAuthorizationEngine;
import com.cedarpolicy.model.AuthorizationResponse;
import com.cedarpolicy.model.exception.AuthException;

import pl.aiwcorpo.mcp.cedar.entities.Caller;
import pl.aiwcorpo.mcp.cedar.entities.CedarRequest;
import pl.aiwcorpo.mcp.cedar.entities.EntityBuilderException;
import pl.aiwcorpo.mcp.cedar.entities.ToolDescriptor;
import pl.aiwcorpo.mcp.cedar.entities.VirtualServerScope;
import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.policy.PolicyService;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.server.ToolDefinition;
import pl.aiwcorpo.mcp.policy.bundle.PolicyStore;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * {@code Action::"call"} on the {@code Tool} from the signed bundle (C7), with the caller's groups, the resources of the
 * arguments named by {@code resourceRefs} (context {@code refs}) and the link (context {@code virtualServer}, {@code vsScopes}).
 * The groups only become members of {@code UserGroup} entities; what they allow is in the bundle. No bundle in force, an
 * evaluation error or an argument that does not fit a reference is a deny.
 */
public final class CedarToolAuthorizer implements ToolAuthorizer {

    private static final Logger log = LoggerFactory.getLogger(CedarToolAuthorizer.class);
    private static final BasicAuthorizationEngine ENGINE = new BasicAuthorizationEngine();

    private final PolicyService policies;
    private final JsonMapper json;

    public CedarToolAuthorizer(PolicyService policies, JsonMapper json) {
        this.policies = policies;
        this.json = json;
    }

    /** A decision with the ids of the policies that determined it (permits for an allow, forbids for a deny). */
    public record Evaluation(ToolDecision decision, java.util.Set<String> determiningPolicies) {
    }

    @Override
    public ToolDecision decide(GatewayUser user, McpServer server, ToolDefinition tool, JsonNode arguments, String virtualSlug) {
        if (!server.enabled() || tool.disabled()) {
            return ToolDecision.deny("tool_disabled", List.of());
        }
        Caller caller = Caller.of(user.sub(), user.username(), user.mcpGroups(), user.client());
        if (virtualSlug != null) {
            caller = caller.withVirtualServer(VirtualServerScope.withoutNarrowing(virtualSlug));
        }
        ToolDescriptor descriptor = new ToolDescriptor(server.serverId(), server.system(), tool.name(), tool.risk().name(),
                tool.action(), tool.resourceRefs());
        Map<String, ?> values = arguments == null || !arguments.isObject() ? Map.of() : json.convertValue(arguments, Map.class);
        return evaluate(caller, descriptor, values, requiredEntitlements(server, tool)).decision();
    }

    /** The Cedar {@code call} for a caller as the token and the link describe it. Deny on anything that goes wrong. */
    public Evaluation evaluate(Caller caller, ToolDescriptor tool, Map<String, ?> arguments, List<String> entitlementsForAMissingPermit) {
        Optional<PolicyStore.Snapshot> snapshot = policies.snapshot();
        if (snapshot.isEmpty() || !policies.ready()) {
            return new Evaluation(ToolDecision.deny("policy_unavailable", List.of()), java.util.Set.of());
        }
        try {
            CedarRequest request = snapshot.get().entityBuilder().forToolCall(caller, tool, arguments);
            AuthorizationResponse response = ENGINE.isAuthorized(request.toAuthorizationRequest(snapshot.get().schema()),
                    snapshot.get().policies(), request.cedarEntities());
            return judge(response, tool.name(), entitlementsForAMissingPermit);
        } catch (EntityBuilderException e) {
            // An argument that is not an identifier of its type never reaches Cedar; the caller sees invalid_argument.
            String reason = e.code().wireCode().equals("invalid_argument") ? "invalid_argument" : "policy_error";
            return new Evaluation(ToolDecision.deny(reason, List.of()), java.util.Set.of());
        } catch (AuthException | RuntimeException e) {
            log.error("Cedar evaluation of {} failed: {}", tool.name(), e.getClass().getName());
            return new Evaluation(ToolDecision.deny("policy_error", List.of()), java.util.Set.of());
        }
    }

    private Evaluation judge(AuthorizationResponse response, String tool, List<String> entitlements) {
        if (response.type != AuthorizationResponse.SuccessOrFailure.Success || response.success.isEmpty()) {
            log.error("Cedar evaluation of {} answered a failure", tool);
            return new Evaluation(ToolDecision.deny("policy_error", List.of()), java.util.Set.of());
        }
        var success = response.success.get();
        if (!success.getErrors().isEmpty()) {
            // A policy that failed to evaluate may be a forbid that did not apply: never read that as an allow.
            log.error("Cedar evaluation of {} reported {} policy errors", tool, success.getErrors().size());
            return new Evaluation(ToolDecision.deny("policy_error", List.of()), java.util.Set.of());
        }
        if (success.isAllowed()) {
            return new Evaluation(ToolDecision.allow(), success.getReason());
        }
        // A deny that names policies is a forbid; a deny without any is the default deny: no permit matched.
        boolean forbidden = !success.getReason().isEmpty();
        return new Evaluation(forbidden ? ToolDecision.deny("policy_forbid", List.of())
                : ToolDecision.deny("not_granted", entitlements), success.getReason());
    }

    @Override
    public List<String> requiredEntitlements(McpServer server, ToolDefinition tool) {
        return List.of("mcp-" + server.system() + "-" + switch (tool.risk()) {
            case READ_ONLY -> "read";
            case UPDATE -> "write";
            case DESTRUCTIVE -> "destructive";
        });
    }

    @Override
    public String policyRevision() {
        return policies.revision();
    }
}
