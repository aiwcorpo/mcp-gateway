package pl.aiwcorpo.mcp.gateway.support;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

/** The bundle server of the platform (static files, ETag on latest.json) with bundles that a test publishes. */
public final class PolicyServer implements AutoCloseable {

    private final HttpServer server;
    private final AtomicReference<TestBundles.Bundle> main = new AtomicReference<>();
    private final AtomicReference<TestBundles.Bundle> overrides = new AtomicReference<>();

    public PolicyServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/policies/main/", exchange -> serve(exchange, "/policies/main/", main));
        server.createContext("/policies/overrides/", exchange -> serve(exchange, "/policies/overrides/", overrides));
        server.start();
    }

    public void publishMain(TestBundles.Bundle bundle) {
        main.set(bundle);
    }

    public void publishOverrides(TestBundles.Bundle bundle) {
        overrides.set(bundle);
    }

    public void withdrawOverrides() {
        overrides.set(null);
    }

    public String mainUrl() {
        return "http://127.0.0.1:" + server.getAddress().getPort() + "/policies/main/";
    }

    public String overridesUrl() {
        return "http://127.0.0.1:" + server.getAddress().getPort() + "/policies/overrides/";
    }

    private void serve(HttpExchange exchange, String prefix, AtomicReference<TestBundles.Bundle> current) throws IOException {
        try (exchange) {
            TestBundles.Bundle bundle = current.get();
            String name = exchange.getRequestURI().getPath().substring(prefix.length());
            if (bundle == null || !"GET".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(404, -1);
                return;
            }
            if ("latest.json".equals(name)) {
                String etag = "\"" + bundle.revision() + "\"";
                if (etag.equals(exchange.getRequestHeaders().getFirst("If-None-Match"))) {
                    exchange.sendResponseHeaders(304, -1);
                    return;
                }
                exchange.getResponseHeaders().set("ETag", etag);
                send(exchange, "application/json", ("{\"revision\":\"" + bundle.revision() + "\",\"url\":\"policies-" + bundle.revision()
                        + ".tar.gz\",\"sigUrl\":\"policies-" + bundle.revision() + ".tar.gz.sig\"}").getBytes(StandardCharsets.UTF_8));
            } else if (("policies-" + bundle.revision() + ".tar.gz").equals(name)) {
                send(exchange, "application/octet-stream", bundle.archive());
            } else if (("policies-" + bundle.revision() + ".tar.gz.sig").equals(name)) {
                send(exchange, "application/octet-stream", bundle.signature());
            } else {
                exchange.sendResponseHeaders(404, -1);
            }
        }
    }

    private static void send(HttpExchange exchange, String type, byte[] body) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", type);
        exchange.sendResponseHeaders(200, body.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(body);
        }
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
