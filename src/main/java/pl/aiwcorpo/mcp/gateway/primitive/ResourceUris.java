package pl.aiwcorpo.mcp.gateway.primitive;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import pl.aiwcorpo.mcp.gateway.confirm.TextHygiene;

/**
 * Matching of a requested resource URI against a URI template of RFC 6570 level 1 (CC-259), the algorithm of
 * {@code test-vectors/resource-uri}: the gateway and the server use the same one, so what one accepts the other accepts with the same
 * variables. The expansion of a variable percent-encodes every character outside ALPHA, DIGIT and {@code -._~}, so a slash of a value is
 * in the URI only as {@code %2F}. Each variable is decoded exactly once (strict UTF-8), must match the whole of its pattern and pass the
 * hygiene of identifiers, and the template expanded with the decoded values must equal the requested URI byte for byte (up to the case of
 * the hexadecimal digits), which rules out a query, a fragment, userinfo, an upper-case scheme, an encoded slash that the type does not
 * allow and a double encoding.
 */
public final class ResourceUris {

    /** The longest URI of the contract ({@code ResourceUri}); a longer text is never matched, so no pattern is run against it. */
    public static final int MAX_URI_LENGTH = 2100;

    private static final String VALUE = "(?:[A-Za-z0-9\\-._~]|%[0-9A-Fa-f]{2})+";
    private static final Pattern HEX_CODE = Pattern.compile("%[0-9A-Fa-f]{2}");

    private ResourceUris() {
    }

    /** A variable of a template with the pattern of its type (or, for an adapter, the pattern and the length limit it declares). */
    public record Variable(String name, Pattern pattern, int maxLength) {

        public static Variable of(String name, String idPattern, int maxLength) {
            return new Variable(name, Pattern.compile(idPattern), maxLength);
        }
    }

    /** Why a requested URI did not match: its shape, or the value of a variable. */
    public enum Mismatch { SHAPE, VARIABLE }

    public record Match(Map<String, String> variables, Mismatch mismatch) {

        public boolean matched() {
            return mismatch == null;
        }

        static Match no(Mismatch why) {
            return new Match(Map.of(), why);
        }
    }

    /** Level 1 expansion of one value. */
    public static String encode(String value) {
        StringBuilder out = new StringBuilder();
        value.codePoints().forEach(cp -> {
            if (cp < 0x80 && (Character.isLetterOrDigit(cp) || cp == '-' || cp == '.' || cp == '_' || cp == '~')) {
                out.append((char) cp);
            } else {
                for (byte b : new String(Character.toChars(cp)).getBytes(StandardCharsets.UTF_8)) {
                    out.append('%').append(String.format("%02X", b & 0xff));
                }
            }
        });
        return out.toString();
    }

    /** The literal texts and the variable names of a template, in order; a variable is a {@link Part} with a null literal. */
    record Part(String literal, String variable) {
    }

    static List<Part> parts(String template) {
        List<Part> parts = new ArrayList<>();
        int at = 0;
        while (at < template.length()) {
            int open = template.indexOf('{', at);
            if (open < 0) {
                parts.add(new Part(template.substring(at), null));
                break;
            }
            if (open > at) {
                parts.add(new Part(template.substring(at, open), null));
            }
            int close = template.indexOf('}', open);
            if (close < 0) {
                throw new IllegalArgumentException("unterminated expression");
            }
            parts.add(new Part(null, template.substring(open + 1, close)));
            at = close + 1;
        }
        return parts;
    }

    public static String expand(String template, Map<String, String> values) {
        StringBuilder out = new StringBuilder();
        for (Part part : parts(template)) {
            out.append(part.literal() != null ? part.literal() : encode(values.get(part.variable())));
        }
        return out.toString();
    }

    /**
     * @param variables the variables of the template with the pattern of the type of each; a variable the template names and this list does not
     *                  is a mismatch of the variable
     */
    public static Match match(String template, List<Variable> variables, String uri) {
        if (uri.length() > MAX_URI_LENGTH || !printableAscii(uri)) {
            return Match.no(Mismatch.SHAPE);
        }
        List<Part> parts = parts(template);
        StringBuilder regex = new StringBuilder("^");
        List<String> names = new ArrayList<>();
        for (Part part : parts) {
            if (part.literal() != null) {
                regex.append(Pattern.quote(part.literal()));
            } else {
                regex.append('(').append(VALUE).append(')');
                names.add(part.variable());
            }
        }
        regex.append('$');
        Matcher found = Pattern.compile(regex.toString(), Pattern.DOTALL).matcher(uri);
        if (!found.matches()) {
            return Match.no(Mismatch.SHAPE);
        }
        Map<String, String> decoded = new LinkedHashMap<>();
        for (int i = 0; i < names.size(); i++) {
            String name = names.get(i);
            Variable declared = variables.stream().filter(v -> v.name().equals(name)).findFirst().orElse(null);
            Optional<String> value = decode(found.group(i + 1));
            if (declared == null || value.isEmpty()) {
                return Match.no(Mismatch.VARIABLE);
            }
            String text = value.get();
            if (text.length() > declared.maxLength() || !declared.pattern().matcher(text).matches() || TextHygiene.containsForbiddenInIdentifier(text)) {
                return Match.no(Mismatch.VARIABLE);
            }
            decoded.put(name, text);
        }
        if (!expand(template, decoded).equals(normalizeHex(uri))) {
            return Match.no(Mismatch.VARIABLE);
        }
        return new Match(decoded, null);
    }

    /** A static resource of a server: it matches by equality of the URI, byte for byte. */
    public record StaticEntry(String name, String uri) {
    }

    public record TemplateEntry(String name, String template, List<Variable> variables) {
    }

    /**
     * What a requested URI refers to: {@code kind} is {@code resource}, {@code template}, or null when nothing does, with the audit reason
     * ({@code uri_no_match}, or {@code variable_invalid} when a template had the shape and a value was not valid for its type).
     */
    public record Resolved(String kind, String name, Map<String, String> variables, String reason) {

        public boolean found() {
            return kind != null;
        }
    }

    /** The manifest rule {@code resource-uri-unambiguous} leaves at most one entry; a static resource is tried first. */
    public static Resolved resolve(List<StaticEntry> statics, List<TemplateEntry> templates, String uri) {
        for (StaticEntry entry : statics) {
            if (entry.uri().equals(uri)) {
                return new Resolved("resource", entry.name(), Map.of(), null);
            }
        }
        String reason = "uri_no_match";
        for (TemplateEntry entry : templates) {
            Match match = match(entry.template(), entry.variables(), uri);
            if (match.matched()) {
                return new Resolved("template", entry.name(), match.variables(), null);
            }
            if (match.mismatch() == Mismatch.VARIABLE) {
                reason = "variable_invalid";
            }
        }
        return new Resolved(null, null, Map.of(), reason);
    }

    private static boolean printableAscii(String uri) {
        for (int i = 0; i < uri.length(); i++) {
            char c = uri.charAt(i);
            if (c < 0x21 || c > 0x7e) {
                return false;
            }
        }
        return true;
    }

    private static String normalizeHex(String uri) {
        return HEX_CODE.matcher(uri).replaceAll(code -> code.group().toUpperCase(java.util.Locale.ROOT));
    }

    private static Optional<String> decode(String encoded) {
        ByteBuffer bytes = ByteBuffer.allocate(encoded.length());
        for (int i = 0; i < encoded.length(); ) {
            if (encoded.charAt(i) == '%') {
                bytes.put((byte) Integer.parseInt(encoded.substring(i + 1, i + 3), 16));
                i += 3;
            } else {
                bytes.put((byte) encoded.charAt(i));
                i += 1;
            }
        }
        bytes.flip();
        try {
            return Optional.of(StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(bytes).toString());
        } catch (CharacterCodingException e) {
            return Optional.empty();
        }
    }
}
