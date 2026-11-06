package pl.aiwcorpo.mcp.gateway.server;

import java.util.List;
import java.util.Set;

/**
 * Whether a server's tools need a credential from the broker and which types the gateway accepts. {@code type} is the one
 * credential type of the system as the server registry names it; it becomes {@code context.credentialType} of every Cedar
 * decision (CC-136), whatever the broker answers later. Null when the server needs no credential. {@code tokenExchange} is true
 * for a system whose credential is the user's token exchanged at the identity provider.
 */
public record CredentialPolicy(boolean required, Set<String> acceptedTypes, List<String> scopes, boolean tokenExchange, String type) {
}
