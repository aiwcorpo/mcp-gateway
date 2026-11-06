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
     * @param lowered tools whose risk is below the minimum of the gateway configuration; when not empty nothing may be written
     * @param risks risk ordinal of every tool this registration approved or submitted, for the floors: the highest risk ever reported for a tool
     */
    public record Plan(Map<String, RegisteredTool> tools, List<Change> changes, List<String> lowered, Map<String, Integer> risks) {
    }

    private RegistryPlanner() {
    }

    /**
     * The registration of an adapter (CC-206, CC-207): nothing is approved by it. A tool whose hash is the approved one stays as it is, with
     * its classification; every other new or changed tool waits for an administrator with the source {@code adapter}, a tool that looks
     * like a read included; a tool the manifest no longer has is removed, and its classification with it (the floor of the risk stays). There is no risk to compare, so
     * no floor and no lowering here: the administrator classifies when approving.
     */
    public static Plan planAdapter(JsonNode manifest, String credentialJson, Map<String, RegisteredTool> existing) {
        String version = manifest.path("version").asString();
        Map<String, RegisteredTool> next = new LinkedHashMap<>();
        List<Change> changes = new ArrayList<>();
        for (JsonNode entry : manifest.path("tools")) {
            String name = entry.path("name").asString();
            String hash = entry.path("definitionHash").asString();
            RegisteredTool current = existing.get(name);
            RegisteredTool.Approved approved = current == null ? null : current.approved();
            if (approved != null && approved.hash().equals(hash)) {
                next.put(name, new RegisteredTool(name, approved, null));
                continue;
            }
            RegisteredTool.Pending kept = current == null ? null : current.pending();
            if (kept != null && kept.hash().equals(hash) && "adapter".equals(kept.source())) {
                next.put(name, new RegisteredTool(name, approved, kept));
                continue;
            }
            next.put(name, new RegisteredTool(name, approved, new RegisteredTool.Pending(entry, hash, version,
                    approved == null ? "new" : "changed", "adapter", credentialJson)));
            changes.add(new Change("definition_submitted", name, hash));
        }
        existing.forEach((name, current) -> {
            if (!next.containsKey(name)) {
                changes.add(new Change("tool_removed", name, current.approved() != null ? current.approved().hash() : current.pending().hash()));
            }
        });
        return new Plan(next, List.copyOf(changes), List.of(), Map.of());
    }

    /**
     * Removing or changing the additionalGroup of a tool that is registered widens or moves who may call it, which the review of a commit does
     * not approve (CC-245): the entry waits for an administrator, whatever its risk, and the approved one stays in force. Adding a group only
     * narrows access and follows the normal rule.
     */
    private static boolean dropsAdditionalGroup(RegisteredTool.Approved approved, JsonNode entry) {
        if (approved == null || !approved.entry().has("additionalGroup")) {
            return false;
        }
        return !approved.entry().get("additionalGroup").asString().equals(entry.path("additionalGroup").asString(null));
    }

    /**
     * @param floors the highest risk ever reported per tool (ordinal), pending entries included (CC-167): a tool below it does not
     *        reject the manifest, it waits for an administrator who accepts the lowering
     * @param configuredMinimum risk ordinal per tool below which a manifest may never go: the operator's configuration
     * @param approveAll the dev bootstrap: the manifest the server serves is taken whole, there is no reviewed commit behind it
     */
    public static Plan plan(JsonNode manifest, String credentialJson, Map<String, RegisteredTool> existing,
                            Map<String, Integer> floors, Map<String, Integer> configuredMinimum, boolean approveAll) {
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
            if (risk < configuredMinimum.getOrDefault(name, 0)) {
                lowered.add(name);
                continue;
            }
            RegisteredTool.Approved approved = current == null ? null : current.approved();
            int floor = Math.max(floors.getOrDefault(name, 0), current == null ? 0 : current.approvedRisk());
            if (risk < floor && !approveAll) {
                // Below the highest risk ever reported: never approved by a commit, not even a return to an older definition.
                RegisteredTool.Pending kept = current == null ? null : current.pending();
                if (kept != null && kept.riskLowered() && kept.hash().equals(hash) && "ci".equals(kept.source())) {
                    next.put(name, new RegisteredTool(name, approved, kept));
                } else {
                    next.put(name, new RegisteredTool(name, approved, new RegisteredTool.Pending(entry, hash, version,
                            approved == null ? "new" : "changed", "ci", credentialJson, true)));
                    changes.add(new Change("definition_submitted", name, hash));
                }
                continue;
            }
            if (approved != null && approved.hash().equals(hash)) {
                next.put(name, new RegisteredTool(name, approved, null));
                continue;
            }
            if ((risk == Risk.READ_ONLY.ordinal() && !dropsAdditionalGroup(approved, entry)) || approveAll) {
                next.put(name, new RegisteredTool(name, new RegisteredTool.Approved(entry, hash, version, credentialJson), null));
                changes.add(new Change("definition_registered", name, hash));
                risks.put(name, risk);
                continue;
            }
            RegisteredTool.Pending kept = current == null ? null : current.pending();
            if (kept != null && kept.hash().equals(hash) && "ci".equals(kept.source())) {
                next.put(name, new RegisteredTool(name, approved, kept));
                risks.put(name, risk);
                continue;
            }
            next.put(name, new RegisteredTool(name, approved, new RegisteredTool.Pending(entry, hash, version,
                    approved == null ? "new" : "changed", "ci", credentialJson)));
            changes.add(new Change("definition_submitted", name, hash));
            risks.put(name, risk);
        }
        existing.forEach((name, current) -> {
            if (!next.containsKey(name) && !lowered.contains(name)) {
                changes.add(new Change("tool_removed", name, current.approved() != null ? current.approved().hash() : current.pending().hash()));
            }
        });
        return new Plan(next, List.copyOf(changes), List.copyOf(lowered), risks);
    }
}
