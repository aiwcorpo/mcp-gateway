package pl.aiwcorpo.mcp.gateway.mcp;

import java.util.function.BooleanSupplier;
import java.util.function.Supplier;

import pl.aiwcorpo.mcp.gateway.killswitch.KillSwitches;

/**
 * The order of the checks of {@code tools/call} up to the call of the server (CC-178). The state of the tool, of its server and
 * of the user's account is asked for only when the endpoint leaves the tool visible and in the order of the contract, so that a
 * tool the filter cuts says nothing about any of them and a state that was not needed is not read (it can cost a call to the
 * server or to the broker).
 */
public final class CallOrder {

    /** {@code errorCode} is the C10 code; both are null when the call goes on to the decision with arguments. */
    public record Verdict(String errorCode, String auditReason) {

        public boolean passes() {
            return errorCode == null;
        }
    }

    private static final Verdict PASSES = new Verdict(null, null);
    private static final Verdict NOT_GRANTED = new Verdict("not_found_or_denied", "not_granted");
    private static final Verdict FILTER_SCOPE = new Verdict("not_found_or_denied", "filter_scope");

    private CallOrder() {
    }

    /**
     * @param mayCall the registry knows the tool in any state and the Cedar decision at the level of the tool allows it
     * @param visible the endpoint (its route and filter) leaves the tool visible
     * @param killSwitch the emergency switch of the tool or its server (CC-194, CC-206): a state like the others, asked for only here, so
     *                   that a user who may not call the tool or whose filter cuts it learns nothing; an unreadable store refuses
     * @param toolEnabled neither the server nor the tool is switched off by an administrator
     * @param serverAvailable the definitions of the server could be read (asked for after {@code toolEnabled})
     * @param definitionIntact the server presents the approved definition of the tool and serves it; only a server that was read can say
     */
    public static Verdict decide(boolean mayCall, boolean visible, Supplier<KillSwitches.Status> killSwitch, BooleanSupplier toolEnabled, BooleanSupplier serverAvailable,
                                 BooleanSupplier definitionIntact, BooleanSupplier connected) {
        if (!mayCall) {
            return NOT_GRANTED;
        }
        if (!visible) {
            return FILTER_SCOPE;
        }
        switch (killSwitch.get()) {
            case UNREADABLE -> {
                return new Verdict("upstream_unavailable", "upstream_unavailable");
            }
            case ON -> {
                return new Verdict("tool_disabled", "kill_switch");
            }
            case OFF -> {
            }
        }
        if (!toolEnabled.getAsBoolean()) {
            return new Verdict("tool_disabled", "tool_disabled");
        }
        if (!serverAvailable.getAsBoolean()) {
            return new Verdict("upstream_unavailable", "upstream_unavailable");
        }
        if (!definitionIntact.getAsBoolean()) {
            return new Verdict("tool_disabled", "tool_disabled");
        }
        if (!connected.getAsBoolean()) {
            return new Verdict("credential_required", "credential_required");
        }
        return PASSES;
    }
}
