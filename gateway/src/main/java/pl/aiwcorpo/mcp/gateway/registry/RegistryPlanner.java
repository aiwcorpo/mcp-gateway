package pl.aiwcorpo.mcp.gateway.registry;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import pl.aiwcorpo.mcp.gateway.server.Risk;
import tools.jackson.databind.JsonNode;

/**
 * What a registration does to the registry (CC-133), as a function of the stored tools and the manifest: a new or changed
 * READ_ONLY tool is approved by the review of the commit, a new or changed UPDATE or DESTRUCTIVE tool waits for an
 * administrator, a tool the manifest no longer has is removed, and a tool that lowers the risk stops the whole registration.
 * No I/O: the store applies the result under its lock.
 */
public final class RegistryPlanner {

    /** One audited consequence of a registration; {@code kind} is the C8 reason (definition_registered, definition_submitted, tool_removed). */
    public record Change(String kind, String tool, String hash) {
    }

    /**
     * @param tools the registry after the registration
     * @param changes what to audit, in manifest order, removals last
     * @param lowered tools whose risk is below what was approved or configured; when not empty nothing may be written
     * @param risks risk ordinal of every tool approved by this registration, for the floors
     */
    public record Plan(Map<String, RegisteredTool> tools, List<Change> changes, List<String> lowered, Map<String, Integer> risks) {
    }

    private RegistryPlanner() {
    }

    /**
     * @param minimum risk ordinal per tool below which a manifest may not go (the highest approved so far, the configured minimum)
     * @param approveAll the dev bootstrap: the manifest the server serves is taken whole, there is no reviewed commit behind it
     */
    public static Plan plan(JsonNode manifest, String credentialJson, Map<String, RegisteredTool> existing,
                            Map<String, Integer> minimum, boolean approveAll) {
        String version = manifest.path("version").asString();
        Map<String, RegisteredTool> next = new LinkedHashMap<>();
        List<Change> changes = new ArrayList<>();
        List<String> lowered = new ArrayList<>();
        Map<String, Integer> risks = new HashMap<>();
        for (JsonNode entry : manifest.path("tools")) {
            String name = entry.path("name").asString();
            String hash = entry.path("definitionHash").asString();
            int risk = Risk.valueOf(entry.path("risk").asString()).ordinal();
            RegisteredTool current = existing.get(name);
            int floor = Math.max(minimum.getOrDefault(name, 0), current == null ? 0 : current.approvedRisk());
            if (risk < floor) {
                lowered.add(name);
                continue;
            }
            RegisteredTool.Approved approved = current == null ? null : current.approved();
            if (approved != null && approved.hash().equals(hash)) {
                next.put(name, new RegisteredTool(name, approved, null));
                continue;
            }
            if (risk == Risk.READ_ONLY.ordinal() || approveAll) {
                next.put(name, new RegisteredTool(name, new RegisteredTool.Approved(entry, hash, version, credentialJson), null));
                changes.add(new Change("definition_registered", name, hash));
                risks.put(name, risk);
                continue;
            }
            RegisteredTool.Pending kept = current == null ? null : current.pending();
            if (kept != null && kept.hash().equals(hash) && "ci".equals(kept.source())) {
                next.put(name, new RegisteredTool(name, approved, kept));
                continue;
            }
            next.put(name, new RegisteredTool(name, approved, new RegisteredTool.Pending(entry, hash, version,
                    approved == null ? "new" : "changed", "ci", credentialJson)));
            changes.add(new Change("definition_submitted", name, hash));
        }
        existing.forEach((name, current) -> {
            if (!next.containsKey(name) && !lowered.contains(name)) {
                changes.add(new Change("tool_removed", name, current.approved() != null ? current.approved().hash() : current.pending().hash()));
            }
        });
        return new Plan(next, List.copyOf(changes), List.copyOf(lowered), risks);
    }
}
