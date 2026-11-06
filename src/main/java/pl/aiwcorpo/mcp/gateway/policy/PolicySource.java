package pl.aiwcorpo.mcp.gateway.policy;

/** What the authorizer decides with: the policy data of this instance as it was last read. */
public interface PolicySource {

    PolicyService.Snapshot snapshot();

    /** The revision of the data in force, for {@code prv} and {@code policyRevision}; 0 before the first load. */
    default long revision() {
        return snapshot().revision();
    }
}
