package pl.aiwcorpo.mcp.gateway.authz;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;

import pl.aiwcorpo.mcp.gateway.auth.GatewayUser;
import pl.aiwcorpo.mcp.gateway.server.McpServer;
import pl.aiwcorpo.mcp.gateway.server.ToolDefinition;

/**
 * The decision of Cedar at the level of the tool for many tools of one server at once (the list of a client, the list a stream compares).
 * Every tool still gets its own decision, the same one {@link ToolAuthorizer#mayCall} gives; only the evaluations run side by side
 * instead of one after another, which is what a list of hundreds of tools costs most. A decision that cannot be made is a refusal (fail-closed).
 *
 * <p>Two lanes with slots of their own: the lists that clients wait for, and the lists streams compute in the background after a change.
 * A change that wakes thousands of streams therefore cannot take the slots a {@code tools/list} needs within its time limit.
 */
public final class ToolAccess implements AutoCloseable {

    public enum Lane { INTERACTIVE, BACKGROUND }

    /** Below this many tools the threads would cost more than they save. */
    private static final int PARALLEL_FROM = 8;

    private final ToolAuthorizer authorizer;
    private final ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
    /** Decisions in progress at once, per lane: Cedar is CPU work, more threads than cores only queue. */
    private final Semaphore interactive;
    private final Semaphore background;

    public ToolAccess(ToolAuthorizer authorizer) {
        this(authorizer, Math.max(4, Runtime.getRuntime().availableProcessors() * 2), Math.max(2, Runtime.getRuntime().availableProcessors() / 2));
    }

    public ToolAccess(ToolAuthorizer authorizer, int interactiveSlots, int backgroundSlots) {
        this.authorizer = authorizer;
        this.interactive = new Semaphore(interactiveSlots);
        this.background = new Semaphore(backgroundSlots);
    }

    /** Whether the user may call each tool, in the order of {@code tools}, for a client that waits for the answer. */
    public List<Boolean> mayCall(GatewayUser user, McpServer server, List<ToolDefinition> tools) {
        return mayCall(user, server, tools, Lane.INTERACTIVE);
    }

    public List<Boolean> mayCall(GatewayUser user, McpServer server, List<ToolDefinition> tools, Lane lane) {
        Semaphore slots = lane == Lane.INTERACTIVE ? interactive : background;
        List<Boolean> out = new ArrayList<>(tools.size());
        if (tools.size() < PARALLEL_FROM) {
            tools.forEach(tool -> out.add(decide(slots, user, server, tool)));
            return out;
        }
        List<Future<Boolean>> decisions = new ArrayList<>(tools.size());
        tools.forEach(tool -> decisions.add(workers.submit(() -> decide(slots, user, server, tool))));
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

    /** A task that was cancelled while it waited for a slot (the list timed out) does not compute a decision nobody collects. */
    private boolean decide(Semaphore slots, GatewayUser user, McpServer server, ToolDefinition tool) {
        try {
            slots.acquire();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
        try {
            return authorizer.mayCall(user, server, tool);
        } finally {
            slots.release();
        }
    }

    @Override
    public void close() {
        workers.shutdownNow();
    }
}
