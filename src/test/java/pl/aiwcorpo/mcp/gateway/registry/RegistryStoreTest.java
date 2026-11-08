package pl.aiwcorpo.mcp.gateway.registry;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import pl.aiwcorpo.mcp.gateway.GatewayTestBase;
import pl.aiwcorpo.mcp.gateway.support.Manifests;
import pl.aiwcorpo.mcp.gateway.support.Manifests.Tool;
import tools.jackson.databind.JsonNode;

/** The registry store on a real PostgreSQL: both entries of a tool survive a round trip, floors only rise, a server's changes cannot interleave. */
class RegistryStoreTest extends GatewayTestBase {

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

    private static RegisteredTool toolWith(String name, boolean approved, boolean pending) {
        JsonNode entry = Manifests.tool(Manifests.jira("1.0.0", Tool.update(name)), name);
        RegisteredTool.Approved a = approved ? new RegisteredTool.Approved(entry, "sha256:" + "1".repeat(64), "1.0.0", "null") : null;
        RegisteredTool.Pending p = pending ? new RegisteredTool.Pending(entry, "sha256:" + "2".repeat(64), "1.1.0", approved ? "changed" : "new",
                "server", "null") : null;
        return new RegisteredTool(name, a, p);
    }

    @Test
    void theApprovedAndThePendingEntryOfAToolComeBackAsWritten() {
        String server = freshServer();
        RegisteredTool both = toolWith("update_issue", true, true);
        RegisteredTool onlyPending = toolWith("create_issue", false, true);
        RegisteredTool onlyApproved = toolWith("get_issue", true, false);

        store.locked(server, tx -> {
            tx.saveServer(Manifests.jira("1.0.0", Tool.update("update_issue")), "manifest");
            tx.saveTool(both);
            tx.saveTool(onlyPending);
            tx.saveTool(onlyApproved);
            return null;
        });

        assertThat(store.tools(server)).containsOnlyKeys("create_issue", "get_issue", "update_issue");
        assertThat(store.tools(server).get("update_issue")).isEqualTo(both);
        assertThat(store.tools(server).get("create_issue")).isEqualTo(onlyPending);
        assertThat(store.tools(server).get("get_issue")).isEqualTo(onlyApproved);
        assertThat(store.findServer(server).orElseThrow().source()).isEqualTo("manifest");
    }

    @Test
    void aToolCanLoseItsPendingEntryAndBeDeleted() {
        String server = freshServer();
        store.locked(server, tx -> {
            tx.saveTool(toolWith("update_issue", true, true));
            return null;
        });
        store.locked(server, tx -> {
            tx.saveTool(toolWith("update_issue", true, false));
            return null;
        });
        assertThat(store.tools(server).get("update_issue").pending()).isNull();
        store.locked(server, tx -> {
            tx.deleteTool("update_issue");
            return null;
        });
        assertThat(store.tools(server)).isEmpty();
    }

    @Test
    void aFloorIsNeverLoweredAndOutlivesTheTool() {
        String server = freshServer();
        store.locked(server, tx -> {
            tx.saveTool(toolWith("delete_it", true, false));
            tx.raiseFloors(Map.of("delete_it", 2));
            return null;
        });
        store.locked(server, tx -> {
            tx.deleteTool("delete_it");
            tx.raiseFloors(Map.of("delete_it", 0));
            return null;
        });
        assertThat(store.floors(server)).containsEntry("delete_it", 2);
    }

    @Test
    void aFailedTransactionWritesNothing() {
        String server = freshServer();
        try {
            store.locked(server, tx -> {
                tx.saveServer(Manifests.jira("1.0.0", Tool.update("update_issue")), "manifest");
                tx.saveTool(toolWith("update_issue", true, false));
                throw new IllegalStateException("stop");
            });
        } catch (IllegalStateException expected) {
            // the transaction was rolled back
        }
        assertThat(store.findServer(server)).isEmpty();
        assertThat(store.tools(server)).isEmpty();
    }

    @Test
    void changesToOneServerRunOneAfterAnother() throws Exception {
        String server = freshServer();
        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch start = new CountDownLatch(1);
        try {
            List<Future<?>> done = new ArrayList<>();
            for (int i = 0; i < 24; i++) {
                done.add(pool.submit(() -> {
                    start.await();
                    store.locked(server, tx -> {
                        // read, think, write: without the lock two of these would both see the same count
                        int seen = tx.tools().size();
                        try {
                            Thread.sleep(5);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                        }
                        tx.saveTool(toolWith("tool_" + (char) ('a' + seen), true, false));
                        return null;
                    });
                    return null;
                }));
            }
            start.countDown();
            for (Future<?> future : done) {
                future.get();
            }
        } finally {
            pool.shutdownNow();
        }
        assertThat(store.tools(server)).hasSize(24);
    }
}
