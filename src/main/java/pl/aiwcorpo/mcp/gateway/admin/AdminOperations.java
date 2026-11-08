package pl.aiwcorpo.mcp.gateway.admin;

import java.util.List;

import pl.aiwcorpo.mcp.gateway.admin.AdminClientCertificateFilter.Rule;

/** Client certificate names per operation, copied from {@code x-allowed-client-cn} in gateway-admin.v1.yaml. */
public final class AdminOperations {

    private AdminOperations() {
    }

    public static List<Rule> admin(List<String> portalBff) {
        return List.of(
                Rule.of("GET", "/admin/v1/catalog", portalBff),
                Rule.of("GET", "/admin/v1/registry/servers", portalBff),
                Rule.of("GET", "/admin/v1/registry/servers/{serverId}/tools/{tool}/pending", portalBff),
                Rule.of("POST", "/admin/v1/registry/servers/{serverId}/tools/{tool}/approve", portalBff),
                Rule.of("GET", "/admin/v1/activity", portalBff),
                Rule.of("GET", "/admin/v1/confirmations/{confirmationId}", portalBff),
                Rule.of("POST", "/admin/v1/confirmations/{confirmationId}/viewed", portalBff),
                Rule.of("POST", "/admin/v1/confirmations/{confirmationId}/cancel", portalBff),
                Rule.of("GET", "/admin/v1/activity/calls", portalBff),
                Rule.of("GET", "/admin/v1/policy/status", portalBff),
                Rule.of("GET", "/admin/v1/servers", portalBff),
                Rule.of("POST", "/admin/v1/servers", portalBff),
                Rule.of("GET", "/admin/v1/servers/{serverId}", portalBff),
                Rule.of("PATCH", "/admin/v1/servers/{serverId}", portalBff),
                Rule.of("DELETE", "/admin/v1/servers/{serverId}", portalBff),
                Rule.of("POST", "/admin/v1/servers/{serverId}/connection/approve", portalBff),
                Rule.of("POST", "/admin/v1/servers/{serverId}/refresh", portalBff),
                Rule.of("GET", "/admin/v1/policy/scope-mapping", portalBff),
                Rule.of("PUT", "/admin/v1/policy/scope-mapping", portalBff),
                Rule.of("GET", "/admin/v1/policy/overrides", portalBff),
                Rule.of("GET", "/admin/v1/policy/overrides/{id}", portalBff),
                Rule.of("PUT", "/admin/v1/policy/overrides/{id}", portalBff),
                Rule.of("DELETE", "/admin/v1/policy/overrides/{id}", portalBff),
                Rule.of("GET", "/admin/v1/registry/servers/{serverId}/policies", portalBff),
                Rule.of("GET", "/admin/v1/registry/servers/{serverId}/policies/pending", portalBff),
                Rule.of("POST", "/admin/v1/registry/servers/{serverId}/policies/approve", portalBff),
                Rule.of("GET", "/admin/v1/kill-switches", portalBff),
                Rule.of("PUT", "/admin/v1/registry/servers/{serverId}/kill-switch", portalBff),
                Rule.of("DELETE", "/admin/v1/registry/servers/{serverId}/kill-switch", portalBff),
                Rule.of("PUT", "/admin/v1/registry/servers/{serverId}/tools/{tool}/kill-switch", portalBff),
                Rule.of("DELETE", "/admin/v1/registry/servers/{serverId}/tools/{tool}/kill-switch", portalBff));
    }

    /** The operations that have no user token: the offboarding process (CC-155). */
    public static List<Rule> certificateOnly(List<String> offboarding) {
        return List.of(
                Rule.of("POST", "/admin/v1/users/{sub}/purge", offboarding));
    }

    public static List<Rule> metrics(List<String> scrapers) {
        return List.of(Rule.of("GET", "/actuator/prometheus", scrapers));
    }
}
