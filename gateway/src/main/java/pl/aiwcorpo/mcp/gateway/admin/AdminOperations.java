package pl.aiwcorpo.mcp.gateway.admin;

import java.util.List;

import pl.aiwcorpo.mcp.gateway.admin.AdminClientCertificateFilter.Rule;

/** Client certificate names per operation, copied from {@code x-allowed-client-cn} in gateway-admin.v1.yaml. */
public final class AdminOperations {

    private AdminOperations() {
    }

    public static List<Rule> admin(List<String> portalBff, List<String> registryCi) {
        return List.of(
                Rule.of("GET", "/admin/v1/catalog", portalBff),
                Rule.of("GET", "/admin/v1/virtual-servers", portalBff),
                Rule.of("POST", "/admin/v1/virtual-servers", portalBff),
                Rule.of("DELETE", "/admin/v1/virtual-servers/{slug}", portalBff),
                Rule.of("GET", "/admin/v1/registry/servers", portalBff),
                Rule.of("PUT", "/admin/v1/registry/servers/{serverId}", registryCi),
                Rule.of("GET", "/admin/v1/registry/servers/{serverId}/tools/{tool}/pending", portalBff),
                Rule.of("POST", "/admin/v1/registry/servers/{serverId}/tools/{tool}/approve", portalBff),
                Rule.of("GET", "/admin/v1/activity", portalBff),
                Rule.of("GET", "/admin/v1/confirmations/{confirmationId}", portalBff),
                Rule.of("POST", "/admin/v1/confirmations/{confirmationId}/viewed", portalBff),
                Rule.of("POST", "/admin/v1/confirmations/{confirmationId}/cancel", portalBff),
                Rule.of("GET", "/admin/v1/activity/calls", portalBff),
                Rule.of("GET", "/admin/v1/policy/status", portalBff));
    }

    public static List<Rule> metrics(List<String> scrapers) {
        return List.of(Rule.of("GET", "/actuator/prometheus", scrapers));
    }
}
