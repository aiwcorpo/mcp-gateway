package pl.aiwcorpo.mcp.gateway.net;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.function.Function;

/**
 * Which addresses the gateway may connect to as the address of an MCP server (C5, CC-249). Loopback, link-local (which holds the cloud
 * metadata address), unspecified, multicast and broadcast addresses are refused, and so is the IPv6 form of the cloud metadata address,
 * which lies in a range that is otherwise allowed. An IPv6 address that carries an IPv4 address (mapped, compatible, NAT64) is judged as
 * that IPv4 address, and a literal in any of the forms of inet_aton ({@code 127.1}, {@code 2130706433}, {@code 0x7f.1}) as the address it
 * denotes. Private ranges are allowed: servers live in them.
 *
 * <p>The check is meant to run on the addresses a connection is really made to, so a name that resolved to a good address when the
 * server was added and to a bad one later (DNS rebinding) is refused when it is used.
 */
public final class AddressPolicy {

    /** {@code cls} is loopback, link_local, unspecified, multicast, broadcast, metadata or not_an_address; {@code judgedAs} the embedded IPv4 address, if any. */
    public record Verdict(boolean allowed, String cls, String judgedAs) {
        static final Verdict ALLOWED = new Verdict(true, null, null);

        static Verdict refused(String cls, String judgedAs) {
            return new Verdict(false, cls, judgedAs);
        }
    }

    /** Why a host cannot be connected to: the address that was refused with its class, or {@code host_not_resolved} (address null). */
    public record Refusal(String reason, String address, String cls) {
        public String message() {
            return address == null ? "the host does not resolve" : address + " is a " + cls.replace('_', '-') + " address";
        }
    }

    private static final byte[] METADATA_V6 = {(byte) 0xfd, 0, 0x0e, (byte) 0xc2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x54};

    private final boolean allowLoopback;
    private final Function<String, List<InetAddress>> resolver;

    /** @param allowLoopback the development stack only: the test servers listen on the loopback interface */
    public AddressPolicy(boolean allowLoopback) {
        this(allowLoopback, AddressPolicy::resolveWithJvm);
    }

    public AddressPolicy(boolean allowLoopback, Function<String, List<InetAddress>> resolver) {
        this.allowLoopback = allowLoopback;
        this.resolver = resolver;
    }

    private static List<InetAddress> resolveWithJvm(String host) {
        try {
            return List.of(InetAddress.getAllByName(host));
        } catch (UnknownHostException e) {
            return List.of();
        }
    }

    /**
     * Resolves {@code host} (a literal is not resolved) and judges every address; the first refused one decides. An empty answer is
     * {@code host_not_resolved}. The JVM keeps the answer for a while, so the connection that follows uses the addresses checked here.
     */
    public Optional<Refusal> check(String host) {
        Optional<byte[]> literal = parseLiteral(host);
        List<byte[]> addresses = new ArrayList<>();
        if (literal.isPresent()) {
            addresses.add(literal.get());
        } else {
            resolver.apply(host).forEach(address -> addresses.add(address.getAddress()));
        }
        return checkResolved(addresses);
    }

    /** The verdict over addresses that were resolved already (a connection reports the one it is made to). */
    public Optional<Refusal> checkResolved(List<byte[]> addresses) {
        if (addresses.isEmpty()) {
            return Optional.of(new Refusal("host_not_resolved", null, null));
        }
        for (byte[] address : addresses) {
            Verdict verdict = judge(address);
            if (!verdict.allowed()) {
                return Optional.of(new Refusal("address_refused", format(address), verdict.cls()));
            }
        }
        return Optional.empty();
    }

    /** The verdict of a literal address in text; anything that is not an address is {@code not_an_address}. */
    public Verdict judge(String address) {
        return parseLiteral(address).map(this::judge).orElse(Verdict.refused("not_an_address", null));
    }

    public Verdict judge(byte[] address) {
        if (address.length == 4) {
            return judgeV4(address, null);
        }
        if (address.length != 16) {
            return Verdict.refused("not_an_address", null);
        }
        byte[] embedded = embeddedV4(address);
        if (embedded != null) {
            return judgeV4(embedded, format(embedded));
        }
        if (isZero(address, 0, 15)) {
            return address[15] == 0 ? Verdict.refused("unspecified", null)
                    : address[15] == 1 ? loopback(null) : Verdict.ALLOWED;
        }
        if ((address[0] & 0xff) == 0xff) {
            return Verdict.refused("multicast", null);
        }
        if ((address[0] & 0xff) == 0xfe && (address[1] & 0xc0) == 0x80) {
            return Verdict.refused("link_local", null);
        }
        if (java.util.Arrays.equals(address, METADATA_V6)) {
            return Verdict.refused("metadata", null);
        }
        return Verdict.ALLOWED;
    }

    private Verdict loopback(String judgedAs) {
        return allowLoopback ? Verdict.ALLOWED : Verdict.refused("loopback", judgedAs);
    }

    private Verdict judgeV4(byte[] a, String judgedAs) {
        int first = a[0] & 0xff;
        if (first == 0) {
            return Verdict.refused("unspecified", judgedAs);
        }
        if (first == 127) {
            return loopback(judgedAs);
        }
        if (first == 169 && (a[1] & 0xff) == 254) {
            return Verdict.refused("link_local", judgedAs);
        }
        if (first >= 224 && first <= 239) {
            return Verdict.refused("multicast", judgedAs);
        }
        if (first == 255 && (a[1] & 0xff) == 255 && (a[2] & 0xff) == 255 && (a[3] & 0xff) == 255) {
            return Verdict.refused("broadcast", judgedAs);
        }
        return Verdict.ALLOWED;
    }

    /** The IPv4 address inside an IPv4-mapped (::ffff:a.b.c.d), IPv4-compatible (::a.b.c.d, above ::1) or NAT64 (64:ff9b::/96) address, else null. */
    private static byte[] embeddedV4(byte[] a) {
        boolean mapped = isZero(a, 0, 10) && (a[10] & 0xff) == 0xff && (a[11] & 0xff) == 0xff;
        boolean compatible = isZero(a, 0, 12) && !(isZero(a, 12, 15) && (a[15] == 0 || a[15] == 1));
        boolean nat64 = (a[0] == 0x00 && a[1] == 0x64 && (a[2] & 0xff) == 0xff && (a[3] & 0xff) == 0x9b) && isZero(a, 4, 12);
        if (!mapped && !compatible && !nat64) {
            return null;
        }
        return new byte[] {a[12], a[13], a[14], a[15]};
    }

    private static boolean isZero(byte[] a, int from, int to) {
        for (int i = from; i < to; i++) {
            if (a[i] != 0) {
                return false;
            }
        }
        return true;
    }

    /** Dotted decimal for IPv4, the compressed lower-case form of RFC 5952 for IPv6 (the last 32 bits stay hexadecimal). */
    public static String format(byte[] address) {
        if (address.length == 4) {
            return (address[0] & 0xff) + "." + (address[1] & 0xff) + "." + (address[2] & 0xff) + "." + (address[3] & 0xff);
        }
        int[] groups = new int[8];
        for (int i = 0; i < 8; i++) {
            groups[i] = ((address[2 * i] & 0xff) << 8) | (address[2 * i + 1] & 0xff);
        }
        int bestStart = -1;
        int bestLength = 0;
        for (int i = 0; i < 8; ) {
            if (groups[i] != 0) {
                i++;
                continue;
            }
            int j = i;
            while (j < 8 && groups[j] == 0) {
                j++;
            }
            if (j - i > bestLength) {
                bestStart = i;
                bestLength = j - i;
            }
            i = j;
        }
        if (bestLength < 2) {
            bestStart = -1;
        }
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            if (i == bestStart) {
                out.append(i == 0 ? "::" : ":");
                i += bestLength - 1;
                continue;
            }
            out.append(Integer.toHexString(groups[i]));
            if (i < 7) {
                out.append(':');
            }
        }
        return out.toString();
    }

    /**
     * An IPv4 address in the forms of inet_aton (one to four parts, each decimal, 0x hexadecimal or 0 octal, the last part filling the
     * rest of the address) or an IPv6 address (a zone after % is ignored); empty for anything else, which is a name.
     */
    public static Optional<byte[]> parseLiteral(String host) {
        if (host == null || host.isEmpty()) {
            return Optional.empty();
        }
        String text = host.startsWith("[") && host.endsWith("]") ? host.substring(1, host.length() - 1) : host;
        if (text.indexOf(':') >= 0) {
            return parseV6(text);
        }
        return parseV4(text);
    }

    private static Optional<byte[]> parseV4(String text) {
        String[] parts = text.split("\\.", -1);
        if (parts.length < 1 || parts.length > 4) {
            return Optional.empty();
        }
        long[] numbers = new long[parts.length];
        for (int i = 0; i < parts.length; i++) {
            Long value = number(parts[i]);
            if (value == null) {
                return Optional.empty();
            }
            numbers[i] = value;
        }
        long value = 0;
        for (int i = 0; i < numbers.length - 1; i++) {
            if (numbers[i] > 255) {
                return Optional.empty();
            }
            value |= numbers[i] << (8 * (3 - i));
        }
        long last = numbers[numbers.length - 1];
        long limit = 1L << (8 * (4 - (numbers.length - 1)));
        if (last >= limit) {
            return Optional.empty();
        }
        value |= last;
        return Optional.of(new byte[] {(byte) (value >> 24), (byte) (value >> 16), (byte) (value >> 8), (byte) value});
    }

    private static Long number(String part) {
        if (part.isEmpty() || part.length() > 12) {
            return null;
        }
        try {
            String lower = part.toLowerCase(Locale.ROOT);
            if (lower.startsWith("0x")) {
                return lower.length() == 2 ? null : Long.parseLong(lower.substring(2), 16);
            }
            if (lower.length() > 1 && lower.startsWith("0")) {
                return Long.parseLong(lower.substring(1), 8);
            }
            return Long.parseLong(lower, 10);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static Optional<byte[]> parseV6(String raw) {
        String text = raw;
        int zone = text.indexOf('%');
        if (zone >= 0) {
            text = text.substring(0, zone);
        }
        int gap = text.indexOf("::");
        if (gap >= 0 && text.indexOf("::", gap + 1) >= 0) {
            return Optional.empty();
        }
        List<Integer> head = new ArrayList<>();
        List<Integer> tail = new ArrayList<>();
        String left = gap >= 0 ? text.substring(0, gap) : text;
        String right = gap >= 0 ? text.substring(gap + 2) : "";
        if (!groups(left, head, gap < 0) || !groups(right, tail, true)) {
            return Optional.empty();
        }
        int total = head.size() + tail.size();
        if (gap < 0 ? total != 8 : total > 7) {
            return Optional.empty();
        }
        int[] all = new int[8];
        for (int i = 0; i < head.size(); i++) {
            all[i] = head.get(i);
        }
        for (int i = 0; i < tail.size(); i++) {
            all[8 - tail.size() + i] = tail.get(i);
        }
        byte[] out = new byte[16];
        for (int i = 0; i < 8; i++) {
            out[2 * i] = (byte) (all[i] >> 8);
            out[2 * i + 1] = (byte) all[i];
        }
        return Optional.of(out);
    }

    /** Hex groups separated by colons; a dotted IPv4 address may end the last part ({@code allowDotted}). */
    private static boolean groups(String text, List<Integer> into, boolean allowDotted) {
        if (text.isEmpty()) {
            return true;
        }
        String[] parts = text.split(":", -1);
        for (int i = 0; i < parts.length; i++) {
            String part = parts[i];
            if (part.indexOf('.') >= 0) {
                if (!allowDotted || i != parts.length - 1) {
                    return false;
                }
                Optional<byte[]> v4 = parseV4(part);
                if (v4.isEmpty() || part.split("\\.", -1).length != 4) {
                    return false;
                }
                into.add(((v4.get()[0] & 0xff) << 8) | (v4.get()[1] & 0xff));
                into.add(((v4.get()[2] & 0xff) << 8) | (v4.get()[3] & 0xff));
                continue;
            }
            if (part.isEmpty() || part.length() > 4 || !part.chars().allMatch(c -> Character.digit(c, 16) >= 0)) {
                return false;
            }
            into.add(Integer.parseInt(part, 16));
        }
        return true;
    }
}
