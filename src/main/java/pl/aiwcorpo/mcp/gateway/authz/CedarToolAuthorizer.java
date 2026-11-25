package pl.aiwcorpo.mcp.gateway.authz;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.cedarpolicy.BasicAuthorizationEngine;
import com.cedarpolicy.model.AuthorizationResponse;
import com.cedarpolicy.model.exception.AuthException;
import com.cedarpolicy.model.schema.Schema;

import pl.aiwcorpo.mcp.cedar.entities.Caller;
import pl.aiwcorpo.mcp.cedar.entities.CedarRequest;
import pl.aiwcorpo.mcp.cedar.entities.EntityBuilder;
import pl.aiwcorpo.mcp.cedar.entities.EntityBuilderException;
import pl.aiwcorpo.mcp.cedar.entities.McpCedarSchema;
import pl.aiwcorpo.mcp.cedar.entities.PromptDescriptor;
import pl.aiwcorpo.mcp.cedar.entities.ResourceDescriptor;
import pl.aiwcorpo.mcp.cedar.entities.ResourceRef;
import pl.aiwcorpo.mcp.cedar.entities.ResourceTypes;
import pl.aiwcorpo.mcp.cedar.entities.ToolDescriptor;
import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.policy.PolicyService;
import pl.aiwcorpo.mcp.gateway.policy.PolicySource;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.server.PromptDefinition;
import pl.aiwcorpo.mcp.gateway.server.ResourceDefinition;
import pl.aiwcorpo.mcp.gateway.server.ToolDefinition;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * {@code Action::"call"} on the {@code Tool} (C7): the base schema, the platform policies of the contracts and the overrides an administrator
 * aimed at the gateway, with the caller's groups, the scopes the scope mapping gives them and the resources of the arguments named by
 * {@code resourceRefs} (context {@code refs}, always present). The clients that may call ({@code azp}) are checked here, in code, before
 * Cedar (an agent is accepted by the registry of agents instead). The groups only become members of {@code UserGroup} entities; what they allow is the platform policy. Data that cannot be
 * used, an evaluation error or an argument that does not fit a reference is a deny.
 */
public final class CedarToolAuthorizer implements ToolAuthorizer {

    private static final Logger log = LoggerFactory.getLogger(CedarToolAuthorizer.class);
    private static final BasicAuthorizationEngine ENGINE = new BasicAuthorizationEngine();
    private static final Schema SCHEMA = McpCedarSchema.schema();

    private final PolicySource policies;
    private final JsonMapper json;

    public CedarToolAuthorizer(PolicySource policies, JsonMapper json) {
        this.policies = policies;
        this.json = json;
    }

    /** A decision with the ids of the policies that determined it (permits for an allow, forbids for a deny). */
    public record Evaluation(ToolDecision decision, java.util.Set<String> determiningPolicies) {
    }

    @Override
    public ToolDecision decide(GatewayUser user, McpServer server, ToolDefinition tool, JsonNode arguments) {
        if (!server.enabled() || tool.disabled()) {
            return ToolDecision.deny("tool_disabled", List.of());
        }
        return evaluate(user, server, tool, arguments).decision();
    }

    @Override
    public ToolDecision forCatalog(GatewayUser user, McpServer server, ToolDefinition tool) {
        List<String> clients = policies.snapshot().allowedClients();
        if (clients.isEmpty()) {
            return decide(user, server, tool);
        }
        return decide(new GatewayUser(user.sub(), user.username(), clients.getFirst(), user.groups(), user.accessToken()), server, tool);
    }

    @Override
    public ToolDecision readForCatalog(GatewayUser user, McpServer server, ResourceDefinition resource) {
        return mayRead(asAiClient(user), server, resource, Map.of());
    }

    @Override
    public ToolDecision getForCatalog(GatewayUser user, McpServer server, PromptDefinition prompt) {
        return mayGet(asAiClient(user), server, prompt);
    }

    /** The caller of the catalog is the portal, whose own client name says nothing of the AI clients the user works with. */
    private GatewayUser asAiClient(GatewayUser user) {
        List<String> clients = policies.snapshot().allowedClients();
        return clients.isEmpty() ? user : new GatewayUser(user.sub(), user.username(), clients.getFirst(), user.groups(), user.accessToken());
    }

    @Override
    public ToolDecision toolLevel(GatewayUser user, McpServer server, ToolDefinition tool) {
        return evaluate(user, server, tool, null).decision();
    }

    private Evaluation evaluate(GatewayUser user, McpServer server, ToolDefinition tool, JsonNode arguments) {
        Caller caller = Caller.of(user.sub(), user.username(), user.mcpGroups(), user.client()).withPrincipalType(user.principalType());
        // Without arguments there is nothing a reference could name, so the decision at the level of a tool does not depend on the
        // resource types of the server (a server whose policies wait for approval has none that count yet).
        ToolDescriptor descriptor;
        try {
            descriptor = descriptor(server, tool, arguments == null ? List.of() : tool.resourceRefs());
        } catch (IllegalArgumentException e) {
            // A group that does not fit the server cannot come from a manifest that passed the rules; it is never read as no group.
            return new Evaluation(ToolDecision.deny("policy_error", List.of()), java.util.Set.of());
        }
        if (arguments != null && oversized(tool, arguments)) {
            return new Evaluation(ToolDecision.deny("invalid_argument", List.of()), java.util.Set.of());
        }
        Map<String, ?> values = arguments == null || !arguments.isObject() ? Map.of() : json.convertValue(arguments, Map.class);
        return evaluate(caller, descriptor, values, requiredEntitlements(server, tool), server.credential().type());
    }

    /**
     * An identifier longer than a resource id can be never reaches a pattern: a long argument costs more to match than to refuse, and the
     * limit is the one the contract gives ({@link ResourceTypes#MAX_ID_LENGTH}).
     */
    private static boolean oversized(ToolDefinition tool, JsonNode arguments) {
        for (var ref : tool.resourceRefs()) {
            JsonNode value = arguments.get(ref.argument());
            if (value == null) {
                continue;
            }
            if (value.isString() && value.asString().length() > ResourceTypes.MAX_ID_LENGTH) {
                return true;
            }
            if (value.isArray()) {
                for (JsonNode element : value) {
                    if (element.isString() && element.asString().length() > ResourceTypes.MAX_ID_LENGTH) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /**
     * The Cedar {@code call} for a caller as the token describes it. Deny on anything that goes wrong.
     *
     * @param credentialType the type of the system from the server registry, put into {@code context.credentialType} before every
     *                       decision (CC-136), not the type the broker answers with; null for a system that needs no credential
     */
    public Evaluation evaluate(Caller caller, ToolDescriptor tool, Map<String, ?> arguments, List<String> entitlementsForAMissingPermit,
                               String credentialType) {
        return evaluate(caller, tool.name(), credentialType, builder -> builder.forToolCall(caller, tool, arguments), entitlementsForAMissingPermit);
    }

    @Override
    public ToolDecision mayRead(GatewayUser user, McpServer server, ResourceDefinition resource, Map<String, String> variables) {
        Caller caller = Caller.of(user.sub(), user.username(), user.mcpGroups(), user.client()).withPrincipalType(user.principalType());
        List<ResourceRef> typed = new java.util.ArrayList<>();
        resource.variables().stream().filter(variable -> variable.type() != null)
                .forEach(variable -> typed.add(new ResourceRef(variable.name(), variable.type())));
        ResourceDescriptor descriptor;
        try {
            descriptor = new ResourceDescriptor(server.serverId(), server.system(), resource.name(), resource.locator(), typed,
                    Optional.ofNullable(resource.additionalGroup()));
        } catch (IllegalArgumentException e) {
            return ToolDecision.deny("policy_error", List.of());
        }
        return evaluateRead(caller, descriptor, variables, server.credential().type()).decision();
    }

    /** The Cedar {@code read_resource} for a caller and an approved entry, with the values of the variables of the URI; deny on anything that goes wrong. */
    public Evaluation evaluateRead(Caller caller, ResourceDescriptor resource, Map<String, ?> variables, String credentialType) {
        return evaluate(caller, resource.name(), credentialType, builder -> builder.forResourceRead(caller, resource, variables), List.of());
    }

    /** The Cedar {@code get_prompt} for a caller and an approved prompt. */
    public Evaluation evaluateGet(Caller caller, PromptDescriptor prompt, String credentialType) {
        return evaluate(caller, prompt.name(), credentialType, builder -> builder.forPromptGet(caller, prompt), List.of());
    }

    @Override
    public ToolDecision mayGet(GatewayUser user, McpServer server, PromptDefinition prompt) {
        Caller caller = Caller.of(user.sub(), user.username(), user.mcpGroups(), user.client()).withPrincipalType(user.principalType());
        PromptDescriptor descriptor;
        try {
            descriptor = new PromptDescriptor(server.serverId(), server.system(), prompt.name(), Optional.ofNullable(prompt.additionalGroup()));
        } catch (IllegalArgumentException e) {
            return ToolDecision.deny("policy_error", List.of());
        }
        return evaluateGet(caller, descriptor, server.credential().type()).decision();
    }

    @Override
    public ResourceTypes resourceTypes() {
        return policies.snapshot().types();
    }

    private Evaluation evaluate(Caller caller, String label, String credentialType, Function<EntityBuilder, CedarRequest> request,
                                List<String> entitlementsForAMissingPermit) {
        PolicyService.Snapshot snapshot = policies.snapshot();
        if (snapshot.revision() == 0) {
            return new Evaluation(ToolDecision.deny("policy_unavailable", List.of()), java.util.Set.of());
        }
        if (!snapshot.usable()) {
            return new Evaluation(ToolDecision.deny("policy_error", List.of()), java.util.Set.of());
        }
        // The registry replaced this list for an agent when its token was accepted (CC-266); a human never takes the azp of an agent from it.
        if (!"agent".equals(caller.principalType()) && !snapshot.allowedClients().contains(caller.client())) {
            return new Evaluation(ToolDecision.deny("not_granted", List.of()), java.util.Set.of());
        }
        try {
            EntityBuilder builder = new EntityBuilder(snapshot.types(), snapshot.mapping());
            if (credentialType != null) {
                builder = builder.withCredentialType(credentialType);
            }
            CedarRequest built = request.apply(builder);
            AuthorizationResponse response = ENGINE.isAuthorized(built.toAuthorizationRequest(SCHEMA), snapshot.gatewayPolicies(),
                    built.cedarEntities());
            return judge(response, label, entitlementsForAMissingPermit);
        } catch (EntityBuilderException e) {
            // An argument that is not an identifier of its type never reaches Cedar; the caller sees invalid_argument.
            String reason = e.code().wireCode().equals("invalid_argument") ? "invalid_argument" : "policy_error";
            return new Evaluation(ToolDecision.deny(reason, List.of()), java.util.Set.of());
        } catch (AuthException | RuntimeException e) {
            log.error("Cedar evaluation of {} failed: {}", label, e.getClass().getName());
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

    private static ToolDescriptor descriptor(McpServer server, ToolDefinition tool, List<pl.aiwcorpo.mcp.cedar.entities.ResourceRef> refs) {
        ToolDescriptor descriptor = new ToolDescriptor(server.serverId(), server.system(), tool.name(), tool.risk().name(), tool.action(), refs);
        return tool.additionalGroup() == null ? descriptor : descriptor.withAdditionalGroup(tool.additionalGroup());
    }

    @Override
    public List<String> requiredEntitlements(McpServer server, ToolDefinition tool) {
        ToolDescriptor descriptor = descriptor(server, tool, List.of());
        return descriptor.additionalGroup().map(group -> List.of(descriptor.requiredGroup(), group)).orElse(List.of(descriptor.requiredGroup()));
    }

    @Override
    public long policyRevision() {
        return policies.revision();
    }
}
