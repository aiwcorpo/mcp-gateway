package pl.aiwcorpo.mcp.gateway.broker;

import java.time.Instant;

/** Credential from the broker for the C3 headers. The value never appears in toString, logs or audit. */
public record Credential(String scheme, String value, String type, Instant expiresAt, int cacheTtlSeconds) {

    public String headerValue() {
        return scheme + " " + value;
    }

    @Override
    public String toString() {
        return "Credential[scheme=" + scheme + ", type=" + type + ", value=***]";
    }
}
