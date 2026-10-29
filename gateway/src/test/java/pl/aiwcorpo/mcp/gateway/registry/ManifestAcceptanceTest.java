package pl.aiwcorpo.mcp.gateway.registry;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import pl.aiwcorpo.mcp.gateway.registry.ManifestValidator.Rejection;
import pl.aiwcorpo.mcp.gateway.server.CredentialPolicy;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.support.Manifests;
import pl.aiwcorpo.mcp.gateway.support.Manifests.Tool;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/** What a gateway refuses although the manifest is a valid one: another environment (CC-138) and another credential type (CC-159). */
class ManifestAcceptanceTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    private static McpServer server(String... credentialTypes) {
        CredentialPolicy credential = credentialTypes.length == 0 ? new CredentialPolicy(false, Set.of(), List.of(), false, null)
                : new CredentialPolicy(true, Set.of(credentialTypes), List.of(), "token-exchange".equals(credentialTypes[0]), credentialTypes[0]);
        return new McpServer("mcp-jira", "jira", URI.create("https://mcp-jira.internal:8443/mcp"), "1.0.0", true, credential, Map.of());
    }

    private static ObjectNode jira(String... types) {
        return Manifests.manifest("mcp-jira", "jira", "1.0.0", List.of(types), Tool.readOnly("get_issue"));
    }

    @Test
    void aManifestForTheDevEnvironmentIsRefusedOutsideDevMode() {
        ObjectNode manifest = jira("user-secret").put("environment", "dev");

        List<Rejection> refused = new ManifestValidator(JSON, false).check(manifest, server("user-secret"));

        assertThat(refused).extracting(Rejection::reason).containsExactly(ManifestValidator.ENVIRONMENT_MISMATCH);
        assertThat(new ManifestValidator(JSON, true).check(manifest, server("user-secret"))).isEmpty();
    }

    @Test
    void productionAndNoEnvironmentAreTheSame() {
        ManifestValidator production = new ManifestValidator(JSON, false);
        assertThat(production.check(jira("user-secret"), server("user-secret"))).isEmpty();
        assertThat(production.check(jira("user-secret").put("environment", "production"), server("user-secret"))).isEmpty();
    }

    @Test
    void aManifestThatDoesNotAcceptTheTypeTheGatewayAsksTheBrokerForIsRefused() {
        // The shape of the migration of OpenSearch: the server said user-secret, the gateway and the broker exchange the token.
        List<Rejection> refused = new ManifestValidator(JSON, false).check(jira("user-secret"), server("token-exchange"));

        assertThat(refused).hasSize(1);
        assertThat(refused.getFirst().reason()).isEqualTo(ManifestValidator.CREDENTIAL_TYPE_MISMATCH);
        assertThat(refused.getFirst().message()).contains("token-exchange").contains("user-secret").doesNotContain("sha256");
    }

    @Test
    void everyTypeOfTheSystemMustBeAcceptedByTheManifest() {
        ManifestValidator validator = new ManifestValidator(JSON, false);
        assertThat(validator.check(jira("user-oauth", "user-secret"), server("user-oauth", "user-secret"))).isEmpty();
        assertThat(validator.check(jira("user-oauth", "user-secret"), server("user-secret"))).as("a manifest may accept more").isEmpty();
        assertThat(validator.check(jira("user-secret"), server("user-oauth", "user-secret"))).extracting(Rejection::reason)
                .as("the broker may return user-oauth, which the server would refuse").containsExactly(ManifestValidator.CREDENTIAL_TYPE_MISMATCH);
    }

    @Test
    void aSetThatMixesTheServiceAccountWithUserTypesIsRefusedAsACredentialTypeMismatch() {
        List<Rejection> refused = new ManifestValidator(JSON, false).check(jira("service-account", "user-secret"), server("service-account"));

        assertThat(refused).extracting(Rejection::reason).contains(ManifestValidator.CREDENTIAL_TYPE_MISMATCH);
    }

    @Test
    void aSystemThatNeedsNoCredentialIsNotChecked() {
        assertThat(new ManifestValidator(JSON, false).check(jira("user-secret"), server())).isEmpty();
    }

    @Test
    void aManifestThatDeclaresNoCredentialWhereTheGatewayAsksForOneIsRefused() {
        ObjectNode manifest = jira("user-secret");
        ((ObjectNode) manifest.get("credential")).put("required", false).putArray("acceptedTypes");

        assertThat(new ManifestValidator(JSON, false).check(manifest, server("user-secret"))).extracting(Rejection::reason)
                .contains(ManifestValidator.CREDENTIAL_TYPE_MISMATCH);
    }
}
