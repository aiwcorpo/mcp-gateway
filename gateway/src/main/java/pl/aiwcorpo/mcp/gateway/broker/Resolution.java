package pl.aiwcorpo.mcp.gateway.broker;

/** Outcome of resolving a credential; anything but {@link Granted} stops the call (fail-closed). */
public sealed interface Resolution {

    record Granted(Credential credential, boolean fromCache) implements Resolution {
    }

    /** 409 credential_required: the user has to connect the account in the portal. */
    record Required(String system, String connectUrl) implements Resolution {
    }

    /** Broker, IdP or network unavailable (C10 upstream_unavailable). */
    record Unavailable(String reason) implements Resolution {
    }

    /** The broker rejected the gateway's own request or answered outside C4 (C10 internal_error). */
    record Failed(String reason) implements Resolution {
    }
}
