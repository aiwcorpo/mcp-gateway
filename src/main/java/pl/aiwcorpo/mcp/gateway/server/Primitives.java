package pl.aiwcorpo.mcp.gateway.server;

import java.util.Map;

/**
 * What a server has next to its tools since 8.0.0: the approved resources and templates, the approved prompts, the
 * {@code contractsVersion} of its last accepted manifest (null for 7.x or older) and whether its policies are approved (CC-249).
 */
public record Primitives(Map<String, ResourceDefinition> resources, Map<String, PromptDefinition> prompts, String contractsVersion,
                         boolean policiesApproved) {

    public static final Primitives NONE = new Primitives(Map.of(), Map.of(), null, true);
}
