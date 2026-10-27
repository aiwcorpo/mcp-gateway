package pl.aiwcorpo.mcp.gateway.server;

import java.util.List;
import java.util.Set;

/** Whether a server's tools need a credential from the broker and which types the gateway accepts. */
public record CredentialPolicy(boolean required, Set<String> acceptedTypes, List<String> scopes, boolean tokenExchange) {
}
