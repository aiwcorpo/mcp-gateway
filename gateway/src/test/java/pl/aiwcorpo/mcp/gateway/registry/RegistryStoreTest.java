package pl.aiwcorpo.mcp.gateway.registry;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import pl.aiwcorpo.mcp.gateway.GatewayTestBase;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** The registry store on a real PostgreSQL: risk floors that outlive a tool, and registrations that cannot interleave. */
class RegistryStoreTest extends GatewayTestBase {

    private static final int READ_ONLY = 0;
    private static final int UPDATE = 1;
    private static final int DESTRUCTIVE = 2;

    @Autowired
    RegistryStore store;

    private static String freshServer() {
        java.util.Random random = new java.util.Random();
        StringBuilder name = new StringBuilder("mcp-t");
        for (int i = 0; i < 10; i++) {
            name.append((char) ('a' + random.nextInt(26)));
        }
        return name.toString();
    }

    private static JsonNode manifest(String marker) {
        return JsonMapper.builder().build().createObjectNode().put("marker", marker);
    }

    @Test
    void aToolRemovedAndAddedAgainWithALowerRiskIsRefused() {
        String server = freshServer();
        assertThat(store.write(server, manifest("1"), "ci", Map.of("delete_it", DESTRUCTIVE, "read_it", READ_ONLY), Map.of(), false))
                .isInstanceOf(RegistryStore.Written.Done.class);
        // The tool disappears from the manifest: the floor stays.
        assertThat(store.write(server, manifest("2"), "ci", Map.of("read_it", READ_ONLY), Map.of(), false))
                .isInstanceOf(RegistryStore.Written.Done.class);
        RegistryStore.Written again = store.write(server, manifest("3"), "ci", Map.of("delete_it", UPDATE, "read_it", READ_ONLY), Map.of(), false);
        assertThat(again).isEqualTo(new RegistryStore.Written.Lowered(List.of("delete_it")));
        assertThat(store.find(server).orElseThrow().manifest().path("marker").asString()).as("nothing was written").isEqualTo("2");
        assertThat(store.write(server, manifest("4"), "ci", Map.of("delete_it", DESTRUCTIVE), Map.of(), false))
                .isInstanceOf(RegistryStore.Written.Done.class);
    }

    @Test
    void theConfiguredMinimumIsEnforcedFromTheFirstRegistration() {
        String server = freshServer();
        assertThat(store.write(server, manifest("1"), "bootstrap", Map.of("delete_it", READ_ONLY), Map.of("delete_it", DESTRUCTIVE), true))
                .isEqualTo(new RegistryStore.Written.Lowered(List.of("delete_it")));
        assertThat(store.find(server)).isEmpty();
    }

    @Test
    void floorsComeAlsoFromAStoredManifestThatIsNoLongerAcceptable() {
        String server = freshServer();
        store.write(server, manifest("1"), "ci", Map.of("a", READ_ONLY), Map.of(), false);
        store.raiseFloors(server, Map.of("a", UPDATE));
        assertThat(store.write(server, manifest("2"), "ci", Map.of("a", READ_ONLY), Map.of(), false))
                .isEqualTo(new RegistryStore.Written.Lowered(List.of("a")));
    }

    @Test
    void theBootstrapNeverReplacesAnApproval() throws Exception {
        String server = freshServer();
        store.write(server, manifest("from-ci"), "ci", Map.of("a", READ_ONLY), Map.of(), false);
        ExecutorService pool = Executors.newFixedThreadPool(8);
        try {
            List<Future<RegistryStore.Written>> results = new ArrayList<>();
            for (int i = 0; i < 24; i++) {
                results.add(pool.submit(() -> store.write(server, manifest("from-server"), "bootstrap", Map.of("a", READ_ONLY), Map.of(), true)));
            }
            for (Future<RegistryStore.Written> result : results) {
                assertThat(result.get()).isInstanceOf(RegistryStore.Written.AlreadyThere.class);
            }
        } finally {
            pool.shutdownNow();
        }
        assertThat(store.find(server).orElseThrow().source()).isEqualTo("ci");
        assertThat(store.find(server).orElseThrow().manifest().path("marker").asString()).isEqualTo("from-ci");
    }

    @Test
    void aBootstrapRacingARegistrationNeverWinsOverIt() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(4);
        try {
            for (int round = 0; round < 25; round++) {
                String server = freshServer();
                Future<RegistryStore.Written> bootstrap = pool.submit(() ->
                        store.write(server, manifest("from-server"), "bootstrap", Map.of("a", READ_ONLY), Map.of(), true));
                Future<RegistryStore.Written> ci = pool.submit(() ->
                        store.write(server, manifest("from-ci"), "ci", Map.of("a", READ_ONLY), Map.of(), false));
                bootstrap.get();
                assertThat(ci.get()).isInstanceOf(RegistryStore.Written.Done.class);
                assertThat(store.find(server).orElseThrow().source()).as("round " + round).isEqualTo("ci");
            }
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void aLoweringRegistrationRacingARaisingOneCannotSlipThrough() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(4);
        try {
            for (int round = 0; round < 40; round++) {
                String server = freshServer();
                Future<RegistryStore.Written> raising = pool.submit(() ->
                        store.write(server, manifest("raising"), "ci", Map.of("a", DESTRUCTIVE), Map.of(), false));
                Future<RegistryStore.Written> lowering = pool.submit(() ->
                        store.write(server, manifest("lowering"), "ci", Map.of("a", READ_ONLY), Map.of(), false));
                raising.get();
                lowering.get();
                assertThat(store.floors(server)).as("round " + round).containsEntry("a", DESTRUCTIVE);
                assertThat(store.find(server).orElseThrow().manifest().path("marker").asString())
                        .as("the stored manifest never ends below the floor, round " + round).isEqualTo("raising");
            }
        } finally {
            pool.shutdownNow();
        }
    }
}
