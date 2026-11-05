package pl.aiwcorpo.mcp.gateway.admin;

import java.util.List;

import pl.aiwcorpo.mcp.gateway.admin.AdminClientCertificateFilter.Rule;

/** Client certificate names per operation, copied from {@code x-allowed-client-cn} in gateway-admin.v1.yaml. */
public final class AdminOperations {

    private AdminOperations() {
    }

    /** The certificate name of the pipeline of one server (CC-161): this prefix and the serverId of the request path, as a whole. */
    public static final String REGISTRY_CI_PREFIX = "mcp-registry-ci-";

    /** The certificate name of the adapter of one foreign server (CC-206): this prefix and the serverId of the request path, as a whole. */
    public static final String ADAPTER_PREFIX = "mcp-adapter-";

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
                Rule.of("GET", "/admin/v1/kill-switches", portalBff),
                Rule.of("PUT", "/admin/v1/registry/servers/{serverId}/kill-switch", portalBff),
                Rule.of("DELETE", "/admin/v1/registry/servers/{serverId}/kill-switch", portalBff),
                Rule.of("PUT", "/admin/v1/registry/servers/{serverId}/tools/{tool}/kill-switch", portalBff),
                Rule.of("DELETE", "/admin/v1/registry/servers/{serverId}/tools/{tool}/kill-switch", portalBff));
    }

    /** The operations that have no user token: the registry pipeline of one server and the offboarding process (CC-155, CC-161). */
    public static List<Rule> certificateOnly(List<String> offboarding) {
        return List.of(
                Rule.of("PUT", "/admin/v1/registry/servers/{serverId}", List.of(REGISTRY_CI_PREFIX + "{serverId}")),
                Rule.of("PUT", "/admin/v1/registry/adapters/{serverId}", List.of(ADAPTER_PREFIX + "{serverId}")),
                Rule.of("POST", "/admin/v1/users/{sub}/purge", offboarding));
    }

    public static List<Rule> metrics(List<String> scrapers) {
        return List.of(Rule.of("GET", "/actuator/prometheus", scrapers));
    }
}
