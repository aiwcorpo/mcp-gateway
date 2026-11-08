package pl.aiwcorpo.mcp.gateway.net;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** Where the tunnel connects (CC-249): to an address it judged itself, once per connection, never to a name. */
class CheckedTunnelTest {

    private final List<InetSocketAddress> connectedTo = new CopyOnWriteArrayList<>();
    private final AtomicInteger resolutions = new AtomicInteger();
    private final AtomicReference<List<String>> answer = new AtomicReference<>(List.of("198.51.100.7"));
    private CheckedTunnel tunnel;

    private CheckedTunnel start(boolean allowLoopback) throws IOException {
        AddressPolicy policy = new AddressPolicy(allowLoopback, host -> {
            resolutions.incrementAndGet();
            try {
                List<InetAddress> addresses = new java.util.ArrayList<>();
                for (String literal : answer.get()) {
                    addresses.add(InetAddress.getByAddress(host, AddressPolicy.parseLiteral(literal).orElseThrow()));
                }
                return addresses;
            } catch (java.net.UnknownHostException e) {
                throw new IllegalStateException(e);
            }
        });
        tunnel = new CheckedTunnel(policy, Duration.ofSeconds(1), (target, millis) -> {
            connectedTo.add(target);
            throw new IOException("the test connects to nothing");
        });
        return tunnel;
    }

    @AfterEach
    void stop() throws IOException {
        if (tunnel != null) {
            tunnel.close();
        }
    }

    private String connect(String target) throws IOException {
        try (Socket socket = new Socket(InetAddress.getLoopbackAddress(), tunnel.port())) {
            socket.setSoTimeout(5000);
            socket.getOutputStream().write(("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
            return new String(socket.getInputStream().readNBytes(64), StandardCharsets.US_ASCII).split("\r\n")[0];
        }
    }

    @Test
    void aNameIsResolvedOnceAndTheConnectionGoesToTheAddressThatWasJudgedNotToTheNextAnswer() throws Exception {
        start(false);

        assertThat(connect("rebind.test:8443")).isEqualTo("HTTP/1.1 502 unreachable");
        answer.set(List.of("127.0.0.1"));

        assertThat(resolutions.get()).as("one resolution for the connection").isEqualTo(1);
        assertThat(connectedTo).extracting(target -> target.getAddress().getHostAddress()).containsExactly("198.51.100.7");
        assertThat(connectedTo.getFirst().getPort()).isEqualTo(8443);
    }

    @Test
    void anAnswerThatChangedToAnAddressThatIsRefusedIsNeverConnectedTo() throws Exception {
        start(false);
        for (String refused : List.of("127.0.0.1", "169.254.169.254", "100.100.100.200", "192.0.0.192", "::ffff:100.100.100.200", "fd00:ec2::254")) {
            answer.set(List.of(refused));

            assertThat(connect("rebind.test:443")).as(refused).isEqualTo("HTTP/1.1 403 address_refused");
        }
        assertThat(connectedTo).as("the connector was never asked for a connection").isEmpty();
    }

    @Test
    void oneRefusedAddressAmongTheAnswersRefusesTheNameAndAnIpLiteralIsJudgedAsItIs() throws Exception {
        start(false);
        answer.set(List.of("198.51.100.7", "127.0.0.1"));
        assertThat(connect("rebind.test:443")).isEqualTo("HTTP/1.1 403 address_refused");

        assertThat(connect("169.254.169.254:80")).isEqualTo("HTTP/1.1 403 address_refused");
        assertThat(connect("[fe80::1]:443")).isEqualTo("HTTP/1.1 403 address_refused");
        assertThat(connectedTo).isEmpty();
    }

    @Test
    void whatIsNotAConnectRequestIsNotServed() throws Exception {
        start(false);
        try (Socket socket = new Socket(InetAddress.getLoopbackAddress(), tunnel.port())) {
            socket.setSoTimeout(5000);
            socket.getOutputStream().write("GET http://rebind.test/ HTTP/1.1\r\n\r\n".getBytes(StandardCharsets.US_ASCII));

            assertThat(new String(socket.getInputStream().readNBytes(32), StandardCharsets.US_ASCII)).startsWith("HTTP/1.1 400");
        }
        assertThat(resolutions.get()).isZero();
    }

    @Test
    void aPlainHttpUrlIsPinnedToTheAddressThatWasJudged() throws Exception {
        start(false);

        assertThat(tunnel.pin(java.net.URI.create("http://rebind.test:8080/mcp?x=1")).toString()).isEqualTo("http://198.51.100.7:8080/mcp?x=1");
        answer.set(List.of("2001:db8::7"));
        assertThat(tunnel.pin(java.net.URI.create("http://rebind.test/mcp")).toString()).isEqualTo("http://[2001:db8::7]/mcp");
        answer.set(List.of("169.254.169.254"));
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> tunnel.pin(java.net.URI.create("http://rebind.test/mcp")))
                .isInstanceOf(CheckedTunnel.AddressRefusedException.class).hasMessageContaining("169.254.169.254");
    }
}
