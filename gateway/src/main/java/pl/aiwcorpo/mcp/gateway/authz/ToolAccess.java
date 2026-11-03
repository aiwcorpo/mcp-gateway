package pl.aiwcorpo.mcp.gateway.authz;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.server.ToolDefinition;

/**
 * The decision of Cedar at the level of the tool for many tools of one server at once (the list of a client, the list a stream compares).
 * Every tool still gets its own decision, the same one {@link ToolAuthorizer#mayCall} gives; only the evaluations run side by side
 * instead of one after another, which is what a list of hundreds of tools costs most. A decision that cannot be made is a refusal (fail-closed).
 */
public final class ToolAccess implements AutoCloseable {

    /** Below this many tools the threads would cost more than they save. */
    private static final int PARALLEL_FROM = 8;

    private final ToolAuthorizer authorizer;
    private final ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
    /** The decisions in progress at once in the whole process, lists and streams together: Cedar is CPU work, more threads than cores only queue. */
    private final java.util.concurrent.Semaphore slots = new java.util.concurrent.Semaphore(Math.max(4, Runtime.getRuntime().availableProcessors() * 2));

    public ToolAccess(ToolAuthorizer authorizer) {
        this.authorizer = authorizer;
    }

    /** Whether the user may call each tool, in the order of {@code tools}. */
    public List<Boolean> mayCall(GatewayUser user, McpServer server, List<ToolDefinition> tools) {
        List<Boolean> out = new ArrayList<>(tools.size());
        if (tools.size() < PARALLEL_FROM) {
            tools.forEach(tool -> out.add(authorizer.mayCall(user, server, tool)));
            return out;
        }
        List<Future<Boolean>> decisions = new ArrayList<>(tools.size());
        tools.forEach(tool -> decisions.add(workers.submit(() -> {
            slots.acquireUninterruptibly();
            try {
                return authorizer.mayCall(user, server, tool);
            } finally {
                slots.release();
            }
        })));
        for (Future<Boolean> decision : decisions) {
            try {
                out.add(decision.get());
            } catch (ExecutionException e) {
                out.add(false);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                decisions.forEach(pending -> pending.cancel(true));
                tools.forEach(tool -> out.add(false));
                return out.subList(0, tools.size());
            }
        }
        return out;
    }

    @Override
    public void close() {
        workers.shutdownNow();
    }
}
