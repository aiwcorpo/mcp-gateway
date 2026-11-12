package pl.aiwcorpo.mcp.gateway.registry;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import pl.aiwcorpo.mcp.gateway.GatewayTestBase;
import pl.aiwcorpo.mcp.gateway.jwt.UuidV7;
import pl.aiwcorpo.mcp.gateway.tls.ServerCertificate;
import pl.aiwcorpo.mcp.testserver.TestMcpServer;
import tools.jackson.databind.JsonNode;

/**
 * An approval that lands while a look at the server is on the network (review of CC-249): the look was judged against the connection the
 * server had before, so applying it could pin a certificate nobody approved. The stale observation is dropped.
 */
class ServerChecksRaceTest extends GatewayTestBase {

    private static final String SERVER = "/admin/v1/servers/mcp-race";

    @Autowired
    ServerChecks checks;

    @Autowired
    RegistryStore store;

    private TestMcpServer server;

    @AfterEach
    void cleanUp() throws Exception {
        adminCall("DELETE", SERVER, null);
        if (server != null) {
            server.close();
        }
    }

    private JsonNode approvePinned() throws Exception {
        server = env.startSelfSignedServer("mcp-race");
        HttpResponse<String> created = adminCall("POST", "/admin/v1/servers",
                "{\"internalUrl\":\"https://127.0.0.1:" + server.port() + "/mcp\"}");
        assertThat(created.statusCode()).as(created.body()).isEqualTo(201);
        String fingerprint = JSON.readTree(created.body()).path("pendingConnection").path("fingerprint").asString();
        HttpResponse<String> approved = adminCall("POST", SERVER + "/connection/approve",
                "{\"tlsMode\":\"pinned\",\"fingerprint\":\"" + fingerprint + "\"}");
        assertThat(approved.statusCode()).as(approved.body()).isEqualTo(200);
        return JSON.readTree(approved.body()).path("connection");
    }

    private static ServerCertificate otherCertificate() {
        return new ServerCertificate("sha256:" + "c3".repeat(32), "CN=other", "CN=other", List.of("other"), Instant.now().plusSeconds(3600));
    }

    @Test
    void aRenewalSeenUnderAnotherConnectionIsNotAppliedToThePinThatWasApprovedMeanwhile() throws Exception {
        JsonNode pinned = approvePinned();
        ServerConfig.Connection seenWith = new ServerConfig.Connection("ca", "sha256:" + "a1".repeat(32), "CN=old", "CN=old", List.of(),
                Instant.now().plusSeconds(3600), "someone", Instant.now());
        ServerChecks.Observation renewal = new ServerChecks.Observation(ServerConfig.CONNECTED, null, null, null, false, otherCertificate());

        checks.applyObservation(UuidV7.next(), "mcp-race", seenWith, renewal, ServerConfig.CONNECTED, null, Instant.now());

        ServerConfig.Connection stored = store.config("mcp-race").orElseThrow().connection();
        assertThat(stored.tlsMode()).isEqualTo("pinned");
        assertThat(stored.fingerprint()).as("still the certificate that was approved").isEqualTo(pinned.path("fingerprint").asString());
    }

    @Test
    void aPendingConnectionFoundUnderAnotherConnectionIsNotRecorded() throws Exception {
        approvePinned();
        ServerConfig.Connection seenWith = new ServerConfig.Connection("pinned", "sha256:" + "a1".repeat(32), "CN=old", "CN=old", List.of(),
                Instant.now().plusSeconds(3600), "someone", Instant.now());
        ServerConfig.PendingConnection found = new ServerConfig.PendingConnection("pinned", "sha256:" + "c3".repeat(32), "CN=other", "CN=other",
                List.of(), Instant.now().plusSeconds(3600), false, "certificate_changed", Instant.now());
        ServerChecks.Observation changed = new ServerChecks.Observation(ServerConfig.CERTIFICATE_CHANGED, "certificate_changed", null, found,
                false, null);

        checks.applyObservation(UuidV7.next(), "mcp-race", seenWith, changed, ServerConfig.CERTIFICATE_CHANGED, "certificate_changed", Instant.now());

        ServerConfig stored = store.config("mcp-race").orElseThrow();
        assertThat(stored.pendingConnection()).isNull();
        assertThat(stored.status()).as("the status of the dropped look is not applied either").isNotEqualTo(ServerConfig.CERTIFICATE_CHANGED);
    }

    @Test
    void anObservationMadeUnderTheCurrentConnectionIsStillApplied() throws Exception {
        JsonNode pinned = approvePinned();
        ServerConfig current = store.config("mcp-race").orElseThrow();
        ServerChecks.Observation down = ServerChecks.Observation.failed(ServerConfig.UNREACHABLE, "manifest_unreachable");

        checks.applyObservation(UuidV7.next(), "mcp-race", current.connection(), down, ServerConfig.UNREACHABLE, "manifest_unreachable", Instant.now());

        ServerConfig stored = store.config("mcp-race").orElseThrow();
        assertThat(stored.status()).isEqualTo(ServerConfig.UNREACHABLE);
        assertThat(stored.connection().fingerprint()).isEqualTo(pinned.path("fingerprint").asString());
    }

    @Test
    void aLookThatBeganBeforeTheOneAlreadyStoredIsNotApplied() throws Exception {
        approvePinned();
        ServerConfig current = store.config("mcp-race").orElseThrow();
        Instant earlier = Instant.now();
        Instant later = earlier.plusSeconds(1);
        ServerChecks.Observation invalid = ServerChecks.Observation.failed(ServerConfig.MANIFEST_INVALID, "manifest_invalid");
        ServerChecks.Observation down = ServerChecks.Observation.failed(ServerConfig.UNREACHABLE, "manifest_unreachable");

        checks.applyObservation(UuidV7.next(), "mcp-race", current.connection(), invalid, ServerConfig.MANIFEST_INVALID, "manifest_invalid", later);
        checks.applyObservation(UuidV7.next(), "mcp-race", current.connection(), down, ServerConfig.UNREACHABLE, "manifest_unreachable", earlier);

        assertThat(store.config("mcp-race").orElseThrow().status()).as("the newer look stays").isEqualTo(ServerConfig.MANIFEST_INVALID);
    }
}
