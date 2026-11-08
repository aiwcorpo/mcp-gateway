package pl.aiwcorpo.mcp.gateway.net;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The only way the gateway opens a TLS connection to an MCP server (CC-249: the address is checked at connect time). The JDK HTTP client
 * resolves a name on its own, so a check made before the request could pass on one answer of a rebinding DNS while the client connects on
 * the next. The client therefore goes through this tunnel (an HTTP CONNECT proxy on the loopback interface of the gateway): the tunnel
 * resolves the name once, judges every address with {@link AddressPolicy} and connects to one of the addresses it judged, never to the
 * name. TLS runs end to end between the client and the server, so the name still decides the SNI and the host name check.
 *
 * <p>A refused address is answered {@code 403 address_refused}; the client reports it as a failure to tunnel, which {@link #refused} reads.
 * Plain {@code http} cannot be tunnelled; {@link #pin} gives the address to connect to in the URL for it.
 */
public final class CheckedTunnel implements Closeable {

    private static final Logger log = LoggerFactory.getLogger(CheckedTunnel.class);
    private static final int MAX_HEAD_BYTES = 8192;
    private static final Duration HEAD_TIMEOUT = Duration.ofSeconds(10);
    private static final String REFUSED = "address_refused";
    private static final int REFUSED_STATUS = 403;

    /** Opens the connection to a checked address; replaced in tests to see where the tunnel connects. */
    @FunctionalInterface
    public interface Connector {
        Socket connect(InetSocketAddress target, int timeoutMillis) throws IOException;
    }

    private final AddressPolicy addresses;
    private final Duration connectTimeout;
    private final Connector connector;
    private final ServerSocket listener;
    private final Proxy proxy;
    private final Thread acceptor;

    public CheckedTunnel(AddressPolicy addresses, Duration connectTimeout) throws IOException {
        this(addresses, connectTimeout, (target, millis) -> {
            Socket socket = new Socket();
            try {
                socket.connect(target, millis);
                return socket;
            } catch (IOException e) {
                socket.close();
                throw e;
            }
        });
    }

    public CheckedTunnel(AddressPolicy addresses, Duration connectTimeout, Connector connector) throws IOException {
        this.addresses = addresses;
        this.connectTimeout = connectTimeout;
        this.connector = connector;
        this.listener = new ServerSocket(0, 128, InetAddress.getLoopbackAddress());
        this.proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(InetAddress.getLoopbackAddress(), listener.getLocalPort()));
        this.acceptor = Thread.ofVirtual().name("server-tunnel-accept").start(this::acceptLoop);
    }

    /** The proxy for an HTTP client: {@code https} goes through the tunnel, anything else is not proxied (see {@link #pin}). */
    public ProxySelector selector() {
        return new ProxySelector() {
            @Override
            public List<Proxy> select(URI uri) {
                return List.of("https".equalsIgnoreCase(uri.getScheme()) ? proxy : Proxy.NO_PROXY);
            }

            @Override
            public void connectFailed(URI uri, SocketAddress address, IOException failure) {
                // the failure reaches the caller of the request; there is no second proxy to fall back to
            }
        };
    }

    /**
     * Resolves the host of a plain {@code http} URL once, judges the addresses and returns the URL with the first of them as its host, so
     * that the connection the client makes is to the address that was judged.
     */
    public URI pin(URI url) throws AddressRefusedException {
        String host = url.getHost();
        host = host != null && host.startsWith("[") ? host.substring(1, host.length() - 1) : host;
        AddressPolicy.Resolution resolution = addresses.resolve(host);
        if (resolution instanceof AddressPolicy.Resolution.Refused refused) {
            throw new AddressRefusedException(refused.refusal());
        }
        InetAddress first = ((AddressPolicy.Resolution.Addresses) resolution).all().getFirst();
        String literal = AddressPolicy.format(first.getAddress());
        try {
            return new URI(url.getScheme(), url.getUserInfo(), literal.indexOf(':') >= 0 ? "[" + literal + "]" : literal, url.getPort(),
                    url.getPath(), url.getQuery(), url.getFragment());
        } catch (java.net.URISyntaxException e) {
            throw new IllegalStateException("cannot pin " + url, e);
        }
    }

    /**
     * Whether a failure of a request is the tunnel refusing the address. The JDK client reports no more than the status of a refused tunnel
     * ("Tunnel failed, got: 403") and the tunnel is the only proxy there is, and it answers 403 for this and nothing else.
     */
    public static boolean refused(Throwable failure) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause() == cause ? null : cause.getCause()) {
            if (cause.getMessage() != null && cause.getMessage().contains("Tunnel failed, got: " + REFUSED_STATUS)) {
                return true;
            }
        }
        return false;
    }

    /** The refusal of an address, for a caller that connects on its own. */
    public static final class AddressRefusedException extends IOException {
        private final transient AddressPolicy.Refusal refusal;

        public AddressRefusedException(AddressPolicy.Refusal refusal) {
            super(refusal.message());
            this.refusal = refusal;
        }

        public AddressPolicy.Refusal refusal() {
            return refusal;
        }
    }

    private void acceptLoop() {
        while (!listener.isClosed()) {
            try {
                Socket client = listener.accept();
                Thread.ofVirtual().name("server-tunnel").start(() -> serve(client));
            } catch (IOException e) {
                if (!listener.isClosed()) {
                    log.warn("server tunnel did not accept: {}", e.getClass().getSimpleName());
                }
            }
        }
    }

    private void serve(Socket client) {
        try (client) {
            client.setSoTimeout((int) HEAD_TIMEOUT.toMillis());
            String target = readConnectTarget(client.getInputStream());
            if (target == null) {
                answer(client, "400 bad_request");
                return;
            }
            int colon = target.lastIndexOf(':');
            String host = target.substring(0, colon);
            host = host.startsWith("[") && host.endsWith("]") ? host.substring(1, host.length() - 1) : host;
            int port;
            try {
                port = Integer.parseInt(target.substring(colon + 1));
            } catch (NumberFormatException e) {
                answer(client, "400 bad_request");
                return;
            }
            AddressPolicy.Resolution resolution = addresses.resolve(host);
            if (resolution instanceof AddressPolicy.Resolution.Refused refused) {
                log.warn("connection to {} refused: {}", host, refused.refusal().message());
                answer(client, REFUSED_STATUS + " " + REFUSED);
                return;
            }
            Socket upstream = connectToOne(((AddressPolicy.Resolution.Addresses) resolution).all(), port);
            if (upstream == null) {
                answer(client, "502 unreachable");
                return;
            }
            try (upstream) {
                answer(client, "200 Connection established");
                client.setSoTimeout(0);
                Thread back = Thread.ofVirtual().start(() -> copy(upstream, client));
                copy(client, upstream);
                back.join();
            }
        } catch (IOException e) {
            log.debug("tunnel ended: {}", e.getClass().getSimpleName());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private Socket connectToOne(List<InetAddress> judged, int port) {
        for (InetAddress address : judged) {
            try {
                return connector.connect(new InetSocketAddress(address, port), (int) connectTimeout.toMillis());
            } catch (IOException e) {
                log.debug("{} not connected: {}", AddressPolicy.format(address.getAddress()), e.getClass().getSimpleName());
            }
        }
        return null;
    }

    private static void copy(Socket from, Socket to) {
        try {
            from.getInputStream().transferTo(to.getOutputStream());
            to.shutdownOutput();
        } catch (IOException e) {
            try {
                to.close();
            } catch (IOException ignored) {
                // closing a half-dead connection that the other direction closes too
            }
        }
    }

    private static void answer(Socket client, String status) throws IOException {
        OutputStream out = client.getOutputStream();
        String headers = status.startsWith("200") ? "" : "Content-Length: 0\r\n";
        out.write(("HTTP/1.1 " + status + "\r\n" + headers + "\r\n").getBytes(StandardCharsets.US_ASCII));
        out.flush();
    }

    /** The authority of {@code CONNECT host:port HTTP/1.1}; the headers are read and ignored. Null for anything else. */
    private static String readConnectTarget(InputStream in) throws IOException {
        ByteArrayOutputStream head = new ByteArrayOutputStream();
        int state = 0;
        while (state < 4) {
            int next = in.read();
            if (next < 0 || head.size() >= MAX_HEAD_BYTES) {
                return null;
            }
            head.write(next);
            state = (next == '\r' && (state == 0 || state == 2)) || (next == '\n' && (state == 1 || state == 3)) ? state + 1
                    : next == '\r' ? 1 : 0;
        }
        String first = head.toString(StandardCharsets.US_ASCII).split("\r\n", 2)[0];
        String[] parts = first.split(" ");
        if (parts.length != 3 || !"CONNECT".equals(parts[0]) || parts[1].lastIndexOf(':') < 1) {
            return null;
        }
        return parts[1];
    }

    @Override
    public void close() throws IOException {
        listener.close();
        acceptor.interrupt();
    }

    public int port() {
        return listener.getLocalPort();
    }
}
