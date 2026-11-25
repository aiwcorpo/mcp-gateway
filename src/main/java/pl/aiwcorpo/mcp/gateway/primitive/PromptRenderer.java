package pl.aiwcorpo.mcp.gateway.primitive;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import pl.aiwcorpo.mcp.gateway.confirm.TextHygiene;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * {@code prompts/get} (CC-259): the result is composed here from the approved {@code messages} of the manifest entry, and no server is
 * called. Every refusal about an argument is one answer (the caller turns it into -32602 {@code Prompt not found}); the reason is for the
 * audit only. A value never carries an angle bracket or a curly brace, whatever pattern the author wrote, because the author wraps the
 * placeholder in markers and a value that could close or open one would escape them.
 */
public final class PromptRenderer {

    public static final String ARGUMENT_INVALID = "argument_invalid";

    private static final Pattern PLACEHOLDER = Pattern.compile("\\{\\{([A-Za-z][A-Za-z0-9]*)\\}\\}");

    private PromptRenderer() {
    }

    /** The manifest entry could not be rendered with these arguments. {@code problem} names the first check that failed, for the logs and tests. */
    public record Refused(String problem) implements Outcome {
    }

    public sealed interface Outcome permits Rendered, Refused {
    }

    /** @param messages the {@code messages} member of the result, as the client gets it */
    public record Rendered(String description, ArrayNode messages) implements Outcome {
    }

    /**
     * @param entry the approved manifest entry: {@code definition} with {@code description} and {@code arguments}, {@code argumentRules},
     *              {@code messages}
     * @param typePattern the {@code idPattern} of a resource type, empty for a type that is not declared
     * @param arguments {@code params.arguments}: an object, or null/missing
     */
    public static Outcome render(JsonMapper json, JsonNode entry, Function<String, Optional<String>> typePattern, JsonNode arguments) {
        JsonNode given = arguments == null || arguments.isMissingNode() || arguments.isNull() ? json.createObjectNode() : arguments;
        if (!given.isObject()) {
            return new Refused("arguments_not_an_object");
        }
        Set<String> declared = new HashSet<>();
        Set<String> required = new HashSet<>();
        entry.path("definition").path("arguments").forEach(argument -> {
            declared.add(argument.path("name").asString());
            if (argument.path("required").asBoolean(false)) {
                required.add(argument.path("name").asString());
            }
        });
        for (String name : given.propertyNames()) {
            if (!declared.contains(name)) {
                return new Refused("unknown_argument");
            }
        }
        for (String name : required) {
            if (!given.has(name)) {
                return new Refused("missing_argument");
            }
        }
        Map<String, String> values = new HashMap<>();
        for (String name : given.propertyNames()) {
            JsonNode rule = ruleOf(entry, name);
            if (rule == null) {
                return new Refused("no_rule");
            }
            String problem = problem(rule, given.get(name), typePattern);
            if (problem != null) {
                return new Refused(problem);
            }
            values.put(name, given.get(name).asString());
        }
        ArrayNode messages = json.createArrayNode();
        for (JsonNode message : entry.path("messages")) {
            ObjectNode out = messages.addObject();
            out.put("role", message.path("role").asString());
            out.putObject("content").put("type", "text").put("text", substitute(message.path("text").asString(), values));
        }
        return new Rendered(entry.path("definition").path("description").asString(""), messages);
    }

    /** Which check refuses the value first, or null; the order is the one of the contract's reference, which the vectors pin. */
    public static String problem(JsonNode rule, JsonNode value, Function<String, Optional<String>> typePattern) {
        if (!value.isString()) {
            return "not_a_string";
        }
        String text = value.asString();
        if (text.length() > rule.path("maxLength").asInt()) {
            return "too_long";
        }
        if (TextHygiene.containsForbiddenInIdentifier(text)) {
            return "text_hygiene";
        }
        if (text.indexOf('<') >= 0 || text.indexOf('>') >= 0 || text.indexOf('{') >= 0 || text.indexOf('}') >= 0) {
            return "forbidden_character";
        }
        if (!Pattern.compile(rule.path("pattern").asString()).matcher(text).matches()) {
            return "pattern";
        }
        if (rule.path("type").isString()) {
            Optional<String> idPattern = typePattern.apply(rule.path("type").asString());
            if (idPattern.isEmpty() || !Pattern.compile(idPattern.get()).matcher(text).matches()) {
                return "type";
            }
        }
        return null;
    }

    private static JsonNode ruleOf(JsonNode entry, String name) {
        for (JsonNode rule : entry.path("argumentRules")) {
            if (name.equals(rule.path("name").asString())) {
                return rule;
            }
        }
        return null;
    }

    private static String substitute(String text, Map<String, String> values) {
        Matcher placeholder = PLACEHOLDER.matcher(text);
        StringBuilder out = new StringBuilder();
        int at = 0;
        while (placeholder.find()) {
            out.append(text, at, placeholder.start()).append(values.getOrDefault(placeholder.group(1), ""));
            at = placeholder.end();
        }
        return out.append(text, at, text.length()).toString();
    }
}
