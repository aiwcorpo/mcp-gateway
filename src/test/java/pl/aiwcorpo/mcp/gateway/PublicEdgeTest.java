package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.web.filter.FormContentFilter;

import pl.aiwcorpo.mcp.gateway.support.GatewayTestEnvironment;
import tools.jackson.databind.JsonNode;

/** One public origin (CC-089): headers, content types, cookies and the RFC 9728 documents at the root. */
class PublicEdgeTest extends GatewayTestBase {

    private static final String METADATA = GatewayTestEnvironment.PUBLIC_URL + "/.well-known/oauth-protected-resource";
    private static final String CALL = "{\"name\":\"jira__get_issue\",\"arguments\":{\"issueKey\":\"ABC-1\"}}";
    private static final Pattern STATUS_LINE = Pattern.compile("(?m)^HTTP/1\\.[01] (\\d{3})");

    @Autowired
    ApplicationContext context;

    @Test
    void everyPublicResponseIsJsonWithNosniffAndCspAndNeverSetsACookie() throws Exception {
        String token = aliceToken();
        String session = initialize(token, "2025-11-25");
        List<Reply> replies = new ArrayList<>();
        replies.add(raw("POST /s/mcp-jira/mcp", Map.of("Authorization", "Bearer " + token), initializeBody()));
        replies.add(raw("POST /s/mcp-jira/mcp", Map.of("Authorization", "Bearer " + token, "Mcp-Session-Id", session,
                "MCP-Protocol-Version", "2025-11-25"), "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}"));
        replies.add(raw("POST /s/mcp-jira/mcp", Map.of("Authorization", "Bearer " + token), "{not json"));
        replies.add(raw("POST /s/mcp-jira/mcp", Map.of(), initializeBody()));
        replies.add(raw("POST /s/mcp-jira/mcp", Map.of("Authorization", "Bearer garbage"), initializeBody()));
        replies.add(raw("POST /s/mcp-nothing/mcp", Map.of("Authorization", "Bearer " + token), initializeBody()));
        replies.add(raw("POST /v/no-such-link/mcp", Map.of("Authorization", "Bearer " + token), initializeBody()));
        replies.add(raw("POST /mcp", Map.of("Authorization", "Bearer " + token), initializeBody()));
        replies.add(raw("POST /mcp?systems=jira&access=read", Map.of("Authorization", "Bearer " + token), initializeBody()));
        replies.add(raw("POST /mcp?system=jira", Map.of("Authorization", "Bearer " + token), initializeBody()));
        replies.add(raw("GET /mcp", Map.of("Authorization", "Bearer " + token), null));
        replies.add(raw("GET /.well-known/oauth-protected-resource/mcp", Map.of(), null));
        replies.add(raw("GET /.well-known/oauth-protected-resource/v/team-a-dev/mcp", Map.of(), null));
        replies.add(raw("GET /s/mcp-jira/mcp", Map.of("Authorization", "Bearer " + token), null));
        replies.add(raw("DELETE /s/mcp-jira/mcp", Map.of("Authorization", "Bearer " + token), null));
        replies.add(raw("POST /s/mcp-jira/mcp", Map.of("Authorization", "Bearer " + token, "Origin", "https://evil.test"), initializeBody()));
        replies.add(raw("GET /nothing/here", Map.of("Authorization", "Bearer " + token), null));
        replies.add(raw("GET /nothing/here", Map.of(), null));
        replies.add(raw("PUT /s/mcp-jira/mcp", Map.of("Authorization", "Bearer " + token), "{}"));
        replies.add(raw("GET /.well-known/oauth-protected-resource/s/mcp-jira/mcp", Map.of(), null));
        replies.add(raw("GET /.well-known/oauth-protected-resource/elsewhere", Map.of(), null));
        replies.add(raw("GET /.well-known/jwks.json", Map.of(), null));
        replies.add(raw("GET /actuator/prometheus", Map.of(), null));
        replies.add(raw("GET /admin/v1/catalog", Map.of("Authorization", "Bearer " + token), null));
        replies.add(raw("POST /s/mcp-jira/mcp", Map.of("Authorization", "Bearer " + token), "x".repeat(1024 * 1024 + 8)));

        for (Reply reply : replies) {
            assertThat(reply.status).as(reply.request).isBetween(200, 499);
            assertThat(reply.header("x-content-type-options")).as(reply.request).isEqualTo("nosniff");
            assertThat(reply.header("content-security-policy")).as(reply.request).isEqualTo("default-src 'none'; sandbox");
            assertThat(reply.header("set-cookie")).as(reply.request).isNull();
            String type = reply.header("content-type");
            if (!reply.body.isEmpty()) {
                assertThat(type).as(reply.request).isNotNull().matches("(?i)^application/json(;.*)?$");
            }
            assertThat(type == null ? "" : type).as(reply.request).doesNotContain("html");
            assertThat(reply.body).as(reply.request).doesNotContainIgnoringCase("<html");
        }
    }

    @Test
    void acceptHeaderNeverMakesTheGatewayAnswerHtml() throws Exception {
        String token = aliceToken();
        for (String accept : List.of("text/html", "text/html,application/xhtml+xml", "image/png", "*/*", "text/plain")) {
            for (String request : List.of("POST /s/mcp-jira/mcp", "POST /s/mcp-nothing/mcp", "GET /missing", "POST /v/x/mcp",
                    "GET /s/mcp-jira/mcp", "POST /.well-known/oauth-protected-resource")) {
                Reply reply = raw(request, Map.of("Authorization", "Bearer " + token, "Accept", accept),
                        request.startsWith("POST") ? initializeBody() : null);
                assertThat(reply.header("content-type") == null ? "" : reply.header("content-type"))
                        .as(request + " Accept: " + accept).doesNotContain("html").doesNotContain("text/plain");
                assertThat(reply.body).as(request).doesNotContainIgnoringCase("<html").doesNotContainIgnoringCase("<!doctype");
                assertThat(reply.status).as(request + " Accept: " + accept).isNotEqualTo(406);
            }
        }
    }

    @Test
    void containerLevelErrorsAreJsonToo() throws Exception {
        for (String request : List.of("GET /%zz HTTP/1.1", "GET /s/mcp-jira/mcp?%=1 HTTP/1.1", "GET /a b HTTP/1.1",
                "GET /\u0000 HTTP/1.1", "GET /s/%2f/mcp HTTP/1.1")) {
            Reply reply = rawText(request + "\r\nHost: localhost\r\nConnection: close\r\n\r\n");
            assertThat(reply.status).as(request).isBetween(400, 404);
            assertThat(reply.header("x-content-type-options")).as(request).isEqualTo("nosniff");
            assertThat(reply.header("content-security-policy")).as(request).isEqualTo("default-src 'none'; sandbox");
            assertThat(reply.header("content-type") == null ? "" : reply.header("content-type")).as(request)
                    .doesNotContain("html");
            assertThat(reply.body).as(request).doesNotContainIgnoringCase("<html").doesNotContainIgnoringCase("tomcat");
        }
    }

    @Test
    void clientCookiesNeverReachAnythingBehindTheGateway() throws Exception {
        String token = aliceToken();
        Reply init = raw("POST /s/mcp-jira/mcp", Map.of("Authorization", "Bearer " + token,
                "Cookie", "__Host-session=portal-session-value; __Host-XSRF-TOKEN=xsrf-value"), initializeBody());
        String session = init.header("mcp-session-id");
        Map<String, String> headers = Map.of("Authorization", "Bearer " + token, "Mcp-Session-Id", session,
                "MCP-Protocol-Version", "2025-11-25", "Cookie", "__Host-session=portal-session-value; JSESSIONID=abc");
        raw("POST /s/mcp-jira/mcp", headers, "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}");
        Reply call = raw("POST /s/mcp-jira/mcp", headers, "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":" + CALL + "}");
        assertThat(JSON.readTree(call.body).path("result").path("isError").asBoolean()).isFalse();
        assertThat(call.header("set-cookie")).isNull();

        assertThat(env.jira.requests()).isNotEmpty();
        env.jira.requests().forEach(request -> {
            assertThat(request.headers().keySet()).as(request.rpcMethod()).doesNotContain("cookie");
            assertThat(request.headers().values().toString()).doesNotContain("portal-session-value").doesNotContain("xsrf-value");
        });
        env.broker.received().forEach(received -> assertThat(received.body()).doesNotContain("portal-session-value"));
    }

    @Test
    void aFormBodyIsNotReadBeforeTheCallerIsAuthenticated() throws Exception {
        // The body is declared but never sent: the 401 comes without the gateway waiting for it.
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("localhost", port), 3000);
            assertThat(statusLineOfFormBodyNotSent(socket, "DELETE /mcp")).startsWith("HTTP/1.1 401");
        }
        assertThat(context.getBeansOfType(FormContentFilter.class)).isEmpty();
    }

    /** Sends a request that declares a form body of 1 MiB and sends one byte of it; the status line of the answer, read within 5 s. */
    static String statusLineOfFormBodyNotSent(Socket socket, String requestLine) throws IOException {
        socket.setSoTimeout(5000);
        socket.getOutputStream().write((requestLine + " HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                + "Content-Length: 1048576\r\n\r\na").getBytes(StandardCharsets.US_ASCII));
        socket.getOutputStream().flush();
        return new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII)).readLine();
    }

    @Test
    void anHttp10RequestWithTransferEncodingIsRefusedAndEndsItsConnection() throws Exception {
        for (String framing : List.of("Transfer-Encoding: chunked\r\n", "Transfer-Encoding: chunked\r\nContent-Length: 5\r\n")) {
            String answers = exchange("POST /mcp HTTP/1.0\r\nHost: localhost\r\n" + framing + "Connection: keep-alive\r\n\r\n0\r\n\r\n"
                    + "GET /.well-known/mcp-jwks.json HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
            assertThat(STATUS_LINE.matcher(answers).results().map(status -> status.group(1)).toList()).as(framing).containsExactly("400");
        }
    }

    /** Everything the gateway answers to these bytes on one connection, until it closes it. */
    private String exchange(String bytes) throws IOException {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("localhost", port), 3000);
            socket.setSoTimeout(5000);
            socket.getOutputStream().write(bytes.getBytes(StandardCharsets.US_ASCII));
            socket.getOutputStream().flush();
            return new String(socket.getInputStream().readAllBytes(), StandardCharsets.US_ASCII);
        }
    }

    @Test
    void clientCookiesDoNotAuthenticateOrChangeTheOutcome() throws Exception {
        Reply withCookieOnly = raw("POST /s/mcp-jira/mcp", Map.of("Cookie", "__Host-session=portal-session-value"), initializeBody());
        assertThat(withCookieOnly.status).isEqualTo(401);
        assertThat(withCookieOnly.header("set-cookie")).isNull();
        Reply adminPathWithCookie = raw("GET /admin/v1/catalog", Map.of("Cookie", "JSESSIONID=x"), null);
        assertThat(adminPathWithCookie.status).isEqualTo(404);
    }

    // --- RFC 9728 at the root of the public origin -----------------------------------------------------------

    @Test
    void metadataDocumentsUseThePublicOriginNeverTheHost() throws Exception {
        for (String path : List.of("/s/mcp-jira/mcp", "/mcp", "/s/mcp-gitlab/mcp")) {
            Reply forged = rawText("GET /.well-known/oauth-protected-resource" + path + " HTTP/1.1\r\nHost: evil.test:6666\r\n"
                    + "X-Forwarded-Host: evil.test\r\nX-Forwarded-Proto: http\r\nX-Forwarded-Port: 6666\r\nForwarded: host=evil.test\r\n"
                    + "Connection: close\r\n\r\n");
            assertThat(forged.status).as(path).isEqualTo(200);
            assertThat(forged.header("content-type")).as(path).startsWith("application/json");
            JsonNode document = JSON.readTree(forged.body);
            assertThat(document.path("resource").asString()).as(path).isEqualTo(GatewayTestEnvironment.PUBLIC_URL + path);
            assertThat(document.path("authorization_servers").get(0).asString()).isEqualTo("http://localhost:18080/realms/corp");
            assertThat(forged.body).doesNotContain("evil.test");
        }
        Reply root = raw("GET /.well-known/oauth-protected-resource", Map.of(), null);
        assertThat(root.status).isEqualTo(200);
        assertThat(JSON.readTree(root.body).path("resource").asString()).isEqualTo(GatewayTestEnvironment.PUBLIC_URL);
    }

    @Test
    void metadataExistsOnlyForShapesOfMcpEndpoints() throws Exception {
        for (String path : List.of("/.well-known/oauth-protected-resource/elsewhere", "/.well-known/oauth-protected-resource/s/mcp-jira",
                "/.well-known/oauth-protected-resource/s/mcp-jira/mcp/extra", "/.well-known/oauth-protected-resource/v/team-a-dev/mcp", "/.well-known/oauth-protected-resource/f/systems=jira/mcp",
                "/.well-known/oauth-protected-resource/mcp/extra",
                "/.well-known/oauth-protected-resource/admin/v1/catalog", "/.well-known/oauth-protected-resource/s/../v/x/mcp",
                "/.well-known/oauth-protected-resourcex", "/%2ewell-known/oauth-protected-resource/elsewhere",
                "/.well-known//oauth-protected-resource/elsewhere")) {
            Reply reply = raw("GET " + path, Map.of(), null);
            assertThat(reply.status).as(path).isIn(400, 404);
            assertThat(reply.body).as(path).doesNotContain("resource\"");
        }
    }

    @Test
    void challengeNamesTheEndpointThatWasCalledOnThePublicOrigin() throws Exception {
        Reply aggregate = rawText("POST /mcp?systems=jira HTTP/1.1\r\nHost: evil.test\r\nX-Forwarded-Host: evil.test\r\n"
                + "Content-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
        assertThat(aggregate.status).isEqualTo(401);
        assertThat(aggregate.header("www-authenticate")).as("the filter is not part of the resource (V2)")
                .isEqualTo("Bearer resource_metadata=\"" + METADATA + "/mcp\"");

        for (String path : List.of("/s/mcp-jira/mcp;x=%22y", "/s/mcp-jira/mcp%22", "/mcp/extra", "/anything")) {
            Reply odd = raw("POST " + path, Map.of(), "{}");
            // The firewall may refuse a path parameter before authentication is asked; both ends are fine.
            assertThat(odd.status).as(path).isIn(400, 401);
            if (odd.status == 400) {
                continue;
            }
            String challenge = odd.header("www-authenticate");
            assertThat(challenge).as(path).startsWith("Bearer resource_metadata=\"" + METADATA);
            assertThat(challenge.chars().filter(c -> c == '"').count()).as(path).isEqualTo(2);
            assertThat(challenge).as(path).doesNotContain("evil").doesNotContain("%22").doesNotContain(";");
        }
    }

    // --- helpers ---------------------------------------------------------------------------------------------

    private record Reply(String request, int status, Map<String, List<String>> headers, String body) {
        String header(String name) {
            List<String> values = headers.get(name.toLowerCase(Locale.ROOT));
            return values == null || values.isEmpty() ? null : values.getFirst();
        }
    }

    private Reply raw(String requestLine, Map<String, String> headers, String body) throws Exception {
        StringBuilder text = new StringBuilder(requestLine).append(" HTTP/1.1\r\nHost: localhost:").append(port).append("\r\n");
        headers.forEach((name, value) -> text.append(name).append(": ").append(value).append("\r\n"));
        if (!headers.containsKey("Accept")) {
            text.append("Accept: application/json, text/event-stream\r\n");
        }
        if (body != null) {
            text.append("Content-Type: application/json\r\nContent-Length: ").append(body.getBytes(StandardCharsets.UTF_8).length).append("\r\n");
        }
        text.append("Connection: close\r\n\r\n");
        if (body != null) {
            text.append(body);
        }
        return rawText(text.toString(), requestLine);
    }

    private Reply rawText(String request) throws Exception {
        return rawText(request, request.lines().findFirst().orElse(""));
    }

    private Reply rawText(String request, String label) throws Exception {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("localhost", port), 3000);
            socket.setSoTimeout(10_000);
            socket.getOutputStream().write(request.getBytes(StandardCharsets.UTF_8));
            socket.getOutputStream().flush();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            try {
                int read;
                while ((read = socket.getInputStream().read(buffer)) > 0) {
                    out.write(buffer, 0, read);
                }
            } catch (IOException e) {
                if (out.size() == 0) {
                    throw e;
                }
            }
            String response = out.toString(StandardCharsets.UTF_8);
            int split = response.indexOf("\r\n\r\n");
            String head = split < 0 ? response : response.substring(0, split);
            String body = split < 0 ? "" : response.substring(split + 4);
            String[] lines = head.split("\r\n");
            int status = Integer.parseInt(lines[0].split(" ")[1]);
            Map<String, List<String>> parsed = new java.util.LinkedHashMap<>();
            for (int i = 1; i < lines.length; i++) {
                int colon = lines[i].indexOf(':');
                if (colon > 0) {
                    parsed.computeIfAbsent(lines[i].substring(0, colon).trim().toLowerCase(Locale.ROOT), k -> new ArrayList<>())
                            .add(lines[i].substring(colon + 1).trim());
                }
            }
            if (parsed.containsKey("transfer-encoding")) {
                body = dechunk(body);
            }
            return new Reply(label, status, parsed, body);
        }
    }

    private static String dechunk(String body) {
        StringBuilder out = new StringBuilder();
        int index = 0;
        while (index < body.length()) {
            int lineEnd = body.indexOf("\r\n", index);
            if (lineEnd < 0) {
                break;
            }
            int size = Integer.parseInt(body.substring(index, lineEnd).trim().split(";")[0], 16);
            if (size == 0) {
                break;
            }
            out.append(body, lineEnd + 2, Math.min(body.length(), lineEnd + 2 + size));
            index = lineEnd + 2 + size + 2;
        }
        return out.toString();
    }
}
