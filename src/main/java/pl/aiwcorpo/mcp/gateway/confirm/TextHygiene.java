package pl.aiwcorpo.mcp.gateway.confirm;

/**
 * The forbidden character set of CC-121, used here only to escape what the owner is shown:
 * a control or bidirectional character in an argument must not reshape the preview or the description.
 */
public final class TextHygiene {

    private TextHygiene() {
    }

    /** True when {@code text} holds a forbidden character; a lone U+FE0F is allowed only directly after an emoji (CC-121, CC-122). */
    public static boolean containsForbidden(String text) {
        int[] cps = text.codePoints().toArray();
        for (int i = 0; i < cps.length; i++) {
            if (forbiddenAt(cps, i)) {
                return true;
            }
        }
        return false;
    }

    /** The variation selector 16 is judged by its predecessor, so a second one in a row follows no emoji and is refused. */
    private static boolean forbiddenAt(int[] cps, int index) {
        if (cps[index] == 0xFE0F && index > 0 && Character.isExtendedPictographic(cps[index - 1])) {
            return false;
        }
        return forbidden(cps[index]);
    }

    private static boolean forbidden(int cp) {
        if (cp < 0x20) {
            return cp != '\t' && cp != '\n' && cp != '\r';
        }
        if ((cp >= 0x7f && cp <= 0x9f) || cp == 0x2028 || cp == 0x2029) {
            return true;
        }
        if (cp >= 0xD800 && cp <= 0xDFFF) {
            return true;
        }
        if ((cp >= 0xFDD0 && cp <= 0xFDEF) || (cp & 0xFFFE) == 0xFFFE) {
            return true;
        }
        if (Character.getType(cp) == Character.FORMAT) {
            return !(cp >= 0x200C && cp <= 0x200F);
        }
        return cp == 0x034F || cp == 0x115F || cp == 0x1160 || cp == 0x3164 || cp == 0xFFA0 || cp == 0x2800
                || (cp >= 0xFE00 && cp <= 0xFE0F) || (cp >= 0xE0100 && cp <= 0xE01EF);
    }

    /** Forbidden characters as {@code \\uXXXX}, so the text stays readable and cannot hide anything. */
    static String escape(String text) {
        StringBuilder out = new StringBuilder(text.length());
        int[] cps = text.codePoints().toArray();
        for (int i = 0; i < cps.length; i++) {
            int cp = cps[i];
            if (forbiddenAt(cps, i)) {
                if (cp > 0xFFFF) {
                    char[] pair = Character.toChars(cp);
                    out.append(String.format("\\u%04x\\u%04x", (int) pair[0], (int) pair[1]));
                } else {
                    out.append(String.format("\\u%04x", cp));
                }
            } else {
                out.appendCodePoint(cp);
            }
        }
        return out.toString();
    }
}
