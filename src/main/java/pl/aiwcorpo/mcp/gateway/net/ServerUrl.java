package pl.aiwcorpo.mcp.gateway.net;

import java.net.URI;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The address an administrator gives for a server ({@code internalUrl}): {@code http} or {@code https}, a host, an optional port and path,
 * no user info and no fragment, at most 255 characters. It is parsed here and not by {@link URI}, which gives no host for forms such as
 * {@code http://2130706433/}: those must reach the address check as the address they denote. A host that is a literal address is
 * stored in its normal form, so that the stored URL means what the check judged.
 *
 * @param host the host without brackets; for a literal address its normal form
 * @param port the port, or the default of the scheme
 */
public record ServerUrl(String scheme, String host, int port, String path, URI uri) {

    private static final Pattern PARTS = Pattern.compile("^(https?)://([^/?#@]*)(/[^?#]*)?(\\?[^#]*)?$", Pattern.CASE_INSENSITIVE);
    private static final Pattern HOST_NAME = Pattern.compile("^[A-Za-z0-9]([A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$");
    private static final int MAX_LENGTH = 255;

    public static Optional<ServerUrl> parse(String text) {
        if (text == null || text.length() > MAX_LENGTH || text.chars().anyMatch(c -> c <= ' ' || c >= 127)) {
            return Optional.empty();
        }
        Matcher parts = PARTS.matcher(text);
        if (!parts.matches()) {
            return Optional.empty();
        }
        String scheme = parts.group(1).toLowerCase(java.util.Locale.ROOT);
        String authority = parts.group(2);
        String hostText;
        String portText = null;
        if (authority.startsWith("[")) {
            int close = authority.indexOf(']');
            if (close < 0) {
                return Optional.empty();
            }
            hostText = authority.substring(0, close + 1);
            String rest = authority.substring(close + 1);
            if (!rest.isEmpty()) {
                if (!rest.startsWith(":")) {
                    return Optional.empty();
                }
                portText = rest.substring(1);
            }
        } else {
            int colon = authority.lastIndexOf(':');
            hostText = colon < 0 ? authority : authority.substring(0, colon);
            portText = colon < 0 ? null : authority.substring(colon + 1);
        }
        int port = "https".equals(scheme) ? 443 : 80;
        if (portText != null) {
            if (portText.isEmpty() || portText.length() > 5 || !portText.chars().allMatch(Character::isDigit)) {
                return Optional.empty();
            }
            port = Integer.parseInt(portText);
            if (port < 1 || port > 65535) {
                return Optional.empty();
            }
        }
        Optional<byte[]> literal = AddressPolicy.parseLiteral(hostText);
        String host;
        if (literal.isPresent()) {
            host = AddressPolicy.format(literal.get());
        } else if (!hostText.isEmpty() && !hostText.startsWith("[") && HOST_NAME.matcher(hostText).matches()) {
            host = hostText.toLowerCase(java.util.Locale.ROOT);
        } else {
            return Optional.empty();
        }
        String path = parts.group(3) == null ? "" : parts.group(3);
        String query = parts.group(4) == null ? "" : parts.group(4);
        String shownHost = host.indexOf(':') >= 0 ? "[" + host + "]" : host;
        boolean defaultPort = portText == null;
        String normal = scheme + "://" + shownHost + (defaultPort ? "" : ":" + port) + path + query;
        try {
            return Optional.of(new ServerUrl(scheme, host, port, path, URI.create(normal)));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    public boolean https() {
        return "https".equals(scheme);
    }
}
