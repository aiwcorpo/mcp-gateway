package pl.aiwcorpo.mcp.gateway.server;

import java.util.List;
import java.util.Set;

/**
 * Whether a server's tools need a credential from the broker and which types the gateway accepts. {@code type} is the one
 * credential type of the system as the gateway configuration names it; it becomes {@code context.credentialType} of every Cedar
 * decision (CC-136), whatever the broker answers later. Null when the server needs no credential.
 */
public record CredentialPolicy(boolean required, Set<String> acceptedTypes, List<String> scopes, boolean tokenExchange, String type) {
}
