package pl.aiwcorpo.mcp.gateway.support;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

import pl.aiwcorpo.mcp.manifest.PoliciesHash;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * The policy fragment and the resource type declarations of a test server, made from the Jira example of the contracts jar with the
 * namespace and the group names of the system in its place: {@code <System>::Project} (granted and checked early) and
 * {@code <System>::Issue} (a child of it). Every system gets a namespace of its own, because a namespace belongs to one server.
 */
public final class Fragments {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final String DIRECTORY = "/mcp-contracts/cedar/examples/systems/jira/";

    private Fragments() {
    }

    /** The Cedar namespace of a system: its id with a capital letter. */
    public static String namespace(String system) {
        return system.substring(0, 1).toUpperCase(Locale.ROOT) + system.substring(1);
    }

    public static ArrayNode resourceTypes(String system) {
        return (ArrayNode) JSON.readTree(adapt(read("resource-types.json"), system));
    }

    public static ObjectNode policies(String system) {
        ObjectNode policies = JSON.createObjectNode();
        policies.put("namespace", namespace(system));
        policies.put("schema", adapt(read("schema.cedarschema"), system));
        ArrayNode files = policies.putArray("files");
        for (String name : new String[] {"read.cedar", "update.cedar"}) {
            files.addObject().put("name", name).put("text", adapt(read(name), system));
        }
        return policies;
    }

    /** The hash a manifest with these policies and declarations must carry (C6 policiesHash). */
    public static String hash(ObjectNode policies, ArrayNode resourceTypes) {
        return PoliciesHash.of(JSON.writeValueAsString(policies), JSON.writeValueAsString(resourceTypes));
    }

    /** Puts {@code resourceTypes}, {@code policies} and {@code policiesHash} of the system into a manifest of a server that is no adapter. */
    public static void apply(ObjectNode manifest, String system) {
        ArrayNode types = resourceTypes(system);
        ObjectNode policies = policies(system);
        manifest.set("resourceTypes", types);
        manifest.set("policies", policies);
        manifest.put("policiesHash", hash(policies, types));
    }

    private static String adapt(String text, String system) {
        return text.replace("Jira", namespace(system)).replace("jira", system);
    }

    private static String read(String name) {
        try (InputStream in = Fragments.class.getResourceAsStream(DIRECTORY + name)) {
            if (in == null) {
                throw new IllegalStateException(DIRECTORY + name + " is not in the mcp-contracts jar");
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
