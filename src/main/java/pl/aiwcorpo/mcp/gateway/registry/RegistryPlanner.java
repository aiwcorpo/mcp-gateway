package pl.aiwcorpo.mcp.gateway.registry;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import pl.aiwcorpo.mcp.gateway.server.Risk;
import tools.jackson.databind.JsonNode;

/**
 * What a pulled manifest does to the registry (C5/C6, CC-249), as a function of the stored tools and the manifest: nothing is approved,
 * whatever the risk. A tool whose hash is the approved one stays as it is; a new or changed tool, a {@code READ_ONLY} one included, waits
 * for an administrator (source {@code manifest}, or {@code adapter} for a server behind an adapter); a tool the manifest no longer has is
 * removed; a tool reported below the highest risk ever reported for it is marked {@code riskLowered}, which only
 * {@code acceptRiskLowering} on the approval lifts (CC-167). No I/O: the store applies the result under its lock.
 */
public final class RegistryPlanner {

    public static final String MANIFEST = "manifest";
    public static final String ADAPTER = "adapter";

    /** One audited consequence of a pull; {@code kind} is the C8 reason (definition_submitted, tool_removed). */
    public record Change(String kind, String tool, String hash) {
    }

    /**
     * @param tools   the registry after the pull
     * @param changes what to audit, in manifest order, removals last
     * @param risks   risk ordinal of every tool the manifest reported at a risk that is not below its floor, for the floors: the highest
     *                risk ever reported for a tool
     */
    public record Plan(Map<String, RegisteredTool> tools, List<Change> changes, Map<String, Integer> risks) {
    }

    /**
     * One audited consequence of a pull for a resource, a template or a prompt; {@code event} is the C8 reason ({@code definition_submitted},
     * {@code resource_removed}, {@code prompt_removed}).
     */
    public record EntryChange(PrimitiveKind kind, String event, String name, String hash) {
    }

    /** @param entries the resources, templates and prompts after the pull; a kind without entries has an empty map */
    public record EntryPlan(Map<PrimitiveKind, Map<String, RegisteredEntry>> entries, List<EntryChange> changes) {
    }

    private RegistryPlanner() {
    }

    /**
     * The same rule as for tools, for the other three kinds of entry (CC-258, CC-265): an entry whose hash is the approved one stays, a new
     * or changed one waits for an administrator whatever it holds, and an entry the manifest no longer has is removed. There is no risk to
     * compare, so nothing is ever marked lowered.
     */
    public static EntryPlan planEntries(JsonNode manifest, Map<PrimitiveKind, Map<String, RegisteredEntry>> existing, boolean adapter) {
        String version = manifest.path("version").asString();
        String source = adapter ? ADAPTER : MANIFEST;
        Map<PrimitiveKind, Map<String, RegisteredEntry>> next = new java.util.EnumMap<>(PrimitiveKind.class);
        List<EntryChange> changes = new ArrayList<>();
        for (PrimitiveKind kind : PrimitiveKind.values()) {
            Map<String, RegisteredEntry> before = existing.getOrDefault(kind, Map.of());
            Map<String, RegisteredEntry> after = new LinkedHashMap<>();
            for (JsonNode entry : manifest.path(kind.field())) {
                String name = entry.path("name").asString();
                String hash = entry.path("definitionHash").asString();
                RegisteredEntry current = before.get(name);
                RegisteredEntry.Approved approved = current == null ? null : current.approved();
                if (approved != null && approved.hash().equals(hash)) {
                    after.put(name, new RegisteredEntry(kind, name, approved, null));
                    continue;
                }
                RegisteredEntry.Pending kept = current == null ? null : current.pending();
                if (kept != null && kept.hash().equals(hash) && source.equals(kept.source())) {
                    after.put(name, new RegisteredEntry(kind, name, approved, kept));
                } else {
                    after.put(name, new RegisteredEntry(kind, name, approved, new RegisteredEntry.Pending(entry, hash, version,
                            approved == null ? "new" : "changed", source)));
                    changes.add(new EntryChange(kind, "definition_submitted", name, hash));
                }
            }
            before.forEach((name, current) -> {
                if (!after.containsKey(name)) {
                    changes.add(new EntryChange(kind, kind == PrimitiveKind.PROMPT ? "prompt_removed" : "resource_removed", name,
                            current.approved() != null ? current.approved().hash() : current.pending().hash()));
                }
            });
            next.put(kind, after);
        }
        return new EntryPlan(next, List.copyOf(changes));
    }

    /**
     * @param floors  the highest risk ever reported per tool (ordinal), pending entries included (CC-167); unused for an adapter, whose
     *                entries carry no risk (the administrator classifies when approving)
     * @param adapter the server is behind an adapter (derived from the first manifest, C5)
     */
    public static Plan plan(JsonNode manifest, String credentialJson, Map<String, RegisteredTool> existing, Map<String, Integer> floors,
                            boolean adapter) {
        String version = manifest.path("version").asString();
        String source = adapter ? ADAPTER : MANIFEST;
        Map<String, RegisteredTool> next = new LinkedHashMap<>();
        List<Change> changes = new ArrayList<>();
        Map<String, Integer> risks = new HashMap<>();
        for (JsonNode entry : manifest.path("tools")) {
            String name = entry.path("name").asString();
            String hash = entry.path("definitionHash").asString();
            RegisteredTool current = existing.get(name);
            RegisteredTool.Approved approved = current == null ? null : current.approved();
            Integer risk = adapter ? null : Risk.valueOf(entry.path("risk").asString()).ordinal();
            if (approved != null && approved.hash().equals(hash)) {
                next.put(name, new RegisteredTool(name, approved, null));
                continue;
            }
            int floor = Math.max(floors.getOrDefault(name, 0), current == null ? 0 : current.approvedRisk());
            boolean lowered = risk != null && risk < floor;
            RegisteredTool.Pending kept = current == null ? null : current.pending();
            if (kept != null && kept.hash().equals(hash) && source.equals(kept.source())) {
                next.put(name, new RegisteredTool(name, approved, kept));
            } else {
                next.put(name, new RegisteredTool(name, approved, new RegisteredTool.Pending(entry, hash, version,
                        approved == null ? "new" : "changed", source, credentialJson, lowered)));
                changes.add(new Change("definition_submitted", name, hash));
            }
            if (risk != null && !lowered) {
                risks.put(name, risk);
            }
        }
        existing.forEach((name, current) -> {
            if (!next.containsKey(name)) {
                changes.add(new Change("tool_removed", name, current.approved() != null ? current.approved().hash() : current.pending().hash()));
            }
        });
        return new Plan(next, List.copyOf(changes), risks);
    }
}
