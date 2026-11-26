package pl.aiwcorpo.mcp.gateway.primitive;

import java.util.function.Supplier;

import pl.aiwcorpo.mcp.gateway.killswitch.KillSwitches;

/**
 * The order of the checks of {@code prompts/get} before the arguments are looked at (CC-259): the prompt is known and Cedar {@code get_prompt}
 * allows it, the address leaves it, then its state: a switch (an unreadable store is -32603, not -32602), the state of the server, the state
 * of the entry. The arguments come last, so that a caller who may not get the prompt cannot learn from an argument what it takes. Every refusal
 * but the unreadable store is one answer, -32602 {@code Prompt not found}; the reason is for the audit.
 */
public final class PromptGetOrder {

    public enum Answer { PASSES, NOT_FOUND, UPSTREAM_UNAVAILABLE }

    public record Verdict(Answer answer, String reason) {

        public boolean passes() {
            return answer == Answer.PASSES;
        }
    }

    private static final Verdict PASSES = new Verdict(Answer.PASSES, null);

    private PromptGetOrder() {
    }

    /**
     * @param serverServed the server is approved, its connection and policies are, and it is enabled (CC-249)
     * @param changedSinceApproval the manifest holds another text, which waits for an administrator: the approved one is not served meanwhile
     */
    public static Verdict decide(boolean known, boolean mayGet, boolean forbidden, boolean visible, Supplier<KillSwitches.Status> killSwitch,
                                 boolean serverServed, boolean changedSinceApproval) {
        if (!known || !mayGet) {
            return new Verdict(Answer.NOT_FOUND, !known || !forbidden ? "not_granted" : "policy_forbid");
        }
        if (!visible) {
            return new Verdict(Answer.NOT_FOUND, "filter_scope");
        }
        switch (killSwitch.get()) {
            case UNREADABLE -> {
                return new Verdict(Answer.UPSTREAM_UNAVAILABLE, "upstream_unavailable");
            }
            case ON -> {
                return new Verdict(Answer.NOT_FOUND, "kill_switch");
            }
            case OFF -> {
            }
        }
        if (!serverServed) {
            return new Verdict(Answer.NOT_FOUND, "not_granted");
        }
        if (changedSinceApproval) {
            return new Verdict(Answer.NOT_FOUND, "definition_changed");
        }
        return PASSES;
    }
}
