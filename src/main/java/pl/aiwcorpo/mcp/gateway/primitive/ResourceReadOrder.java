package pl.aiwcorpo.mcp.gateway.primitive;

import java.util.function.BooleanSupplier;
import java.util.function.Supplier;

import pl.aiwcorpo.mcp.gateway.killswitch.KillSwitches;

/**
 * The order of the checks of {@code resources/read} up to the call of the server (CC-259, steps 3 to 8; the token and the header of the modern
 * era come before). Each state is asked for only when the checks before it passed, so that what the client may not know about says nothing
 * of the state of the server, of the entry or of the account, and a state that was not needed is not read (it can cost a call). Steps 3 to 6
 * are one answer, -32602 {@code Resource not found} (D5): the refusal tells the audit why and the client nothing.
 */
public final class ResourceReadOrder {

    public enum Answer { PASSES, NOT_FOUND, UPSTREAM_UNAVAILABLE, CREDENTIAL_REQUIRED }

    /** {@code step} is the number the contract gives the check that stopped the call; {@code reason} is the audit reason. */
    public record Verdict(Answer answer, String reason, int step) {

        public boolean passes() {
            return answer == Answer.PASSES;
        }
    }

    private static final Verdict PASSES = new Verdict(Answer.PASSES, null, 8);

    private ResourceReadOrder() {
    }

    /**
     * @param mayRead the registry knows the entry and Cedar {@code read_resource} allows it at the level of the resource (step 4)
     * @param forbidden the refusal of {@code mayRead} came from a forbid and not from a missing grant
     * @param visible the endpoint (its filter) leaves resources visible (step 5)
     * @param killSwitch the switch of the resource or of its server; an unreadable store is -32603, not -32602
     * @param serverServed the server is approved, its connection and policies are, and it is enabled (CC-249)
     * @param entryServed the entry is approved and enabled
     * @param definitionMatches the server presents the approved definition of the entry
     * @param serverAvailable the server answers (step 7)
     * @param emissionAllowed the receivers of the call (the server, and the broker for a template that needs a credential) are known to take the
     *                        claim {@code resource} (CC-260): a call to one that is not is not sent, whatever else is true
     * @param principalEligible the caller can use what the credential needs: an autonomous agent cannot use a credential of a person (CC-261)
     * @param connected the account is connected, true for what needs no credential (step 8)
     */
    public static Verdict decide(boolean mayRead, boolean forbidden, boolean visible, Supplier<KillSwitches.Status> killSwitch, BooleanSupplier serverServed,
                                 BooleanSupplier entryServed, BooleanSupplier definitionMatches, BooleanSupplier serverAvailable,
                                 BooleanSupplier emissionAllowed, BooleanSupplier principalEligible, BooleanSupplier connected) {
        if (!mayRead) {
            return new Verdict(Answer.NOT_FOUND, forbidden ? "policy_forbid" : "not_granted", 4);
        }
        if (!visible) {
            return new Verdict(Answer.NOT_FOUND, "filter_scope", 5);
        }
        switch (killSwitch.get()) {
            case UNREADABLE -> {
                return new Verdict(Answer.UPSTREAM_UNAVAILABLE, "upstream_unavailable", 6);
            }
            case ON -> {
                return new Verdict(Answer.NOT_FOUND, "kill_switch", 6);
            }
            case OFF -> {
            }
        }
        if (!serverServed.getAsBoolean() || !entryServed.getAsBoolean()) {
            return new Verdict(Answer.NOT_FOUND, "not_granted", 6);
        }
        if (!definitionMatches.getAsBoolean()) {
            return new Verdict(Answer.NOT_FOUND, "definition_changed", 6);
        }
        if (!serverAvailable.getAsBoolean()) {
            return new Verdict(Answer.UPSTREAM_UNAVAILABLE, "upstream_unavailable", 7);
        }
        if (!emissionAllowed.getAsBoolean()) {
            return new Verdict(Answer.UPSTREAM_UNAVAILABLE, "contracts_version_unsupported", 7);
        }
        if (!principalEligible.getAsBoolean()) {
            return new Verdict(Answer.NOT_FOUND, "principal_not_eligible", 8);
        }
        if (!connected.getAsBoolean()) {
            return new Verdict(Answer.CREDENTIAL_REQUIRED, "credential_required", 8);
        }
        return PASSES;
    }
}
