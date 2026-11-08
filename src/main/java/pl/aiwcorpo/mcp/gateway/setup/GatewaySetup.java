package pl.aiwcorpo.mcp.gateway.setup;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.net.ConnectException;
import java.net.URI;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.CertPathValidatorException;
import java.time.Duration;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import javax.net.ssl.SSLException;

import com.nimbusds.jose.jwk.JWKSet;

import pl.aiwcorpo.mcp.gateway.jwt.SigningKeys;
import pl.aiwcorpo.mcp.gateway.tls.InternalTls;

/**
 * First-start setup of one gateway installation, run as {@code java -jar mcp-gateway.jar init [dir]} before the gateway starts
 * (the init service of deploy/compose.yaml, ExecStartPre of the systemd unit).
 *
 * <p>Every value the operator did not set in the environment and that nothing outside this installation needs to know is generated
 * once into {@code dir} and kept: the internal JWT keys, the two cursor keys and, when the installation runs its own PostgreSQL and
 * Redis, their passwords. A second run changes nothing. The gateway reads {@code dir/gateway/env} as a Spring config tree.
 *
 * <p>Then it checks what it cannot generate (addresses, certificates) and stops with exit code 1 and the likely cause when the gateway
 * could not work. The broker only warns, because it may be installed after the gateway. The MCP servers are not checked: they are data
 * of the registry (admin API), not of this environment.
 */
public final class GatewaySetup {

    static final List<String> REQUIRED = List.of("MCP_PUBLIC_URL", "MCP_OIDC_ISSUER", "MCP_OIDC_JWKS_URI", "MCP_DB_URL",
            "MCP_REDIS_HOST", "MCP_TLS_KEYSTORE", "MCP_TLS_TRUSTSTORE", "MCP_TLS_STORE_PASSWORD", "MCP_BROKER_URL",
            "MCP_BROKER_TLS_NAME", "MCP_DB_PASSWORD", "MCP_REDIS_PASSWORD");
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(5);

    private final Map<String, String> env;
    private final Path dir;
    private final PrintStream out;
    private int failures;

    GatewaySetup(Map<String, String> env, Path dir, PrintStream out) {
        this.env = new LinkedHashMap<>(env);
        this.dir = dir;
        this.out = out;
    }

    public static int run(String[] args) {
        Path dir = Path.of(args.length > 1 ? args[1] : "/secrets");
        return new GatewaySetup(System.getenv(), dir, System.out).run();
    }

    int run() {
        try {
            generate();
        } catch (IOException e) {
            out.println("FAIL  cannot write to " + dir + ": " + e.getMessage());
            return 1;
        }
        check();
        if (failures > 0) {
            out.println();
            out.println(failures + " problem(s): fix them in the configuration and start again. Generated values are kept.");
            return 1;
        }
        out.println();
        out.println("Ready to start.");
        return 0;
    }

    void generate() throws IOException {
        Path gatewayEnv = dir.resolve("gateway").resolve("env");
        Files.createDirectories(gatewayEnv);
        restrict(dir.resolve("gateway"));
        if (!env.containsKey("MCP_INTERNAL_JWT_KEYS_FILE")) {
            Path keys = dir.resolve("gateway").resolve("internal-jwt.jwks");
            if (Files.notExists(keys)) {
                JWKSet set = SigningKeys.newKeysFile();
                writeSecret(keys, set.toString(false));
                writeSecret(gatewayEnv.resolve("MCP_INTERNAL_JWT_ACTIVE_KID"), set.getKeys().getFirst().getKeyID());
                out.println("new   internal JWT keys " + keys);
            }
            writeIfMissing(gatewayEnv.resolve("MCP_INTERNAL_JWT_KEYS_FILE"), keys.toString());
        }
        for (String name : List.of("MCP_ACTIVITY_CURSOR_KEY", "MCP_LIST_CURSOR_KEY")) {
            generated(gatewayEnv, name);
        }
        String db = generated(gatewayEnv, "MCP_DB_PASSWORD");
        if (db != null) {
            Path postgres = dir.resolve("postgres").resolve("password");
            createSharedDirectory(postgres.getParent());
            writeShared(postgres, db);
        }
        String redis = generated(gatewayEnv, "MCP_REDIS_PASSWORD");
        if (redis != null) {
            writeRedis(redis);
        }
        // The checks below see what the gateway will see.
        try (var files = Files.list(gatewayEnv)) {
            for (Path file : files.filter(f -> !f.getFileName().toString().startsWith(".")).toList()) {
                env.putIfAbsent(file.getFileName().toString(), Files.readString(file).strip());
            }
        }
    }

    /**
     * Configuration of the installation's own Redis: a primary and the replica that the gateway waits for (MCP_REDIS_WAIT_REPLICAS=1),
     * so that a burned confirmation code survives the loss of the primary. Passwords stay in files, never in a command line.
     */
    private void writeRedis(String gatewayPassword) throws IOException {
        Path redisDir = dir.resolve("redis");
        createSharedDirectory(redisDir);
        Path replicationFile = redisDir.resolve("replication-password");
        if (Files.notExists(replicationFile)) {
            writeShared(replicationFile, randomSecret());
        }
        String replication = Files.readString(replicationFile).strip();
        writeShared(redisDir.resolve("users.acl"), "user default off resetkeys resetchannels -@all\n"
                + "user " + env.getOrDefault("MCP_REDIS_USER", "gateway") + " on #" + sha256(gatewayPassword) + " " + redisRules() + "\n"
                + "user replication on #" + sha256(replication) + " resetkeys resetchannels -@all +psync +replconf +ping\n");
        // noeviction: confirmations, counters and locks must never be evicted to make room; appendonly: they survive a restart.
        String common = "aclfile /secrets/redis/users.acl\ndir /data\nappendonly yes\nappendfsync everysec\nmaxmemory-policy noeviction\n";
        writeShared(redisDir.resolve("primary.conf"), common);
        writeShared(redisDir.resolve("replica.conf"), common + "replicaof redis 6379\nmasteruser replication\nmasterauth " + replication + "\n");
    }

    /** The value of {@code name} when this installation owns it (not set by the operator), generated on the first run. */
    private String generated(Path gatewayEnv, String name) throws IOException {
        if (env.containsKey(name)) {
            return null;
        }
        Path file = gatewayEnv.resolve(name);
        if (Files.exists(file)) {
            return Files.readString(file).strip();
        }
        String value = randomSecret();
        writeSecret(file, value);
        out.println("new   " + name);
        return value;
    }

    void check() {
        List<String> missing = REQUIRED.stream().filter(name -> blank(env.get(name))).toList();
        if (!missing.isEmpty()) {
            fail("not set: " + String.join(", ", missing));
            return;
        }
        for (String name : List.of("MCP_PUBLIC_URL", "MCP_OIDC_JWKS_URI")) {
            if (!env.get(name).startsWith("https://")) {
                fail(name + " " + env.get(name) + " must start with https://");
            }
        }
        if (!env.getOrDefault("MCP_REDIS_WAIT_REPLICAS", "0").matches("[1-9][0-9]*")) {
            fail("MCP_REDIS_WAIT_REPLICAS must be 1 or more, with a Redis replica: the gateway does not start without one");
        }
        InternalTls tls = tls();
        checkAllowedClients();
        checkServerCas();
        HttpClient jvmTrust = HttpClient.newBuilder().connectTimeout(CONNECT_TIMEOUT).followRedirects(HttpClient.Redirect.NEVER).build();
        checkJwks(jvmTrust);
        if (tls == null) {
            return;
        }
        reach("broker", env.get("MCP_BROKER_URL"), tls.clientFor(env.get("MCP_BROKER_TLS_NAME"), CONNECT_TIMEOUT), false,
                env.get("MCP_BROKER_TLS_NAME"));
    }

    private InternalTls tls() {
        Path keystore = Path.of(env.get("MCP_TLS_KEYSTORE"));
        Path truststore = Path.of(env.get("MCP_TLS_TRUSTSTORE"));
        for (Path file : List.of(keystore, truststore)) {
            if (!Files.isReadable(file)) {
                fail("certificate file " + file + " does not exist or cannot be read");
                return null;
            }
        }
        try {
            InternalTls tls = new InternalTls(keystore, truststore, env.get("MCP_TLS_STORE_PASSWORD").toCharArray());
            ok("gateway certificate " + keystore + " and internal CA " + truststore);
            return tls;
        } catch (IllegalStateException e) {
            // PKCS12 reports a wrong password as a failed decryption.
            boolean wrongPassword = inChain(e, javax.crypto.BadPaddingException.class) || inChain(e, java.security.UnrecoverableKeyException.class)
                    || chainMentions(e, "password");
            fail("cannot open " + keystore + " or " + truststore + ": "
                    + (wrongPassword ? "wrong MCP_TLS_STORE_PASSWORD (both files use it)" : rootMessage(e)));
            return null;
        }
    }

    /** The CA bundle for the {@code ca} trust of the MCP servers is optional; one that is named must be a PEM file with certificates. */
    private void checkServerCas() {
        String configured = env.get("MCP_SERVER_TRUSTED_CAS");
        if (blank(configured)) {
            ok("MCP server trust: the default trust store of the JVM (MCP_SERVER_TRUSTED_CAS not set)");
            return;
        }
        Path bundle = Path.of(configured);
        if (!Files.isReadable(bundle)) {
            fail("MCP_SERVER_TRUSTED_CAS " + configured + " does not exist or cannot be read");
            return;
        }
        try {
            new pl.aiwcorpo.mcp.gateway.tls.ServerTls(bundle);
            ok("MCP server trust: the default trust store of the JVM and the CAs in " + configured);
        } catch (IllegalStateException e) {
            fail("MCP_SERVER_TRUSTED_CAS " + configured + " holds no CA certificate in PEM form: " + rootMessage(e));
        }
    }

    /** The AI clients that may call tools; the default is claude-code and claude-ai, so only a value that was set can be wrong. */
    private void checkAllowedClients() {
        String configured = env.get("MCP_ALLOWED_CLIENTS");
        if (blank(configured)) {
            ok("allowed AI clients: claude-code, claude-ai (MCP_ALLOWED_CLIENTS not set)");
            return;
        }
        List<String> clients = List.of(configured.split(",")).stream().map(String::strip).toList();
        if (clients.stream().anyMatch(client -> !client.matches("[A-Za-z0-9._-]{1,128}"))) {
            fail("MCP_ALLOWED_CLIENTS " + configured + " must be client ids (the azp of the IdP token) separated by commas");
            return;
        }
        ok("allowed AI clients: " + String.join(", ", clients));
    }

    private void checkJwks(HttpClient http) {
        String url = env.get("MCP_OIDC_JWKS_URI");
        HttpResponse<String> response = get("identity provider keys", url, http, true, null);
        if (response == null) {
            return;
        }
        try {
            if (response.statusCode() != 200 || JWKSet.parse(response.body()).getKeys().isEmpty()) {
                fail("identity provider keys " + url + ": HTTP " + response.statusCode() + " without keys; check MCP_OIDC_JWKS_URI");
                return;
            }
            ok("identity provider keys " + url);
        } catch (java.text.ParseException e) {
            fail("identity provider keys " + url + ": not a JWKS document; check MCP_OIDC_JWKS_URI");
        }
    }

    private void reach(String what, String url, HttpClient http, boolean required, String tlsName) {
        if (get(what, url, http, required, tlsName) != null) {
            ok(what + " " + url);
        }
    }

    /** Any HTTP answer counts: it proves the name, the route and both certificates. */
    private HttpResponse<String> get(String what, String url, HttpClient http, boolean required, String tlsName) {
        try {
            return http.send(HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(10)).GET().build(),
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (IllegalArgumentException e) {
            report(required, what + " " + url + ": not a valid URL");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            report(required, what + " " + url + ": interrupted");
        } catch (IOException e) {
            report(required, what + " " + url + ": " + cause(e, tlsName));
        }
        return null;
    }

    /** The most specific cause anywhere in the chain wins: an unresolved name also arrives wrapped in a ConnectException. */
    static String cause(Throwable e, String tlsName) {
        if (inChain(e, UnknownHostException.class) || inChain(e, java.nio.channels.UnresolvedAddressException.class)) {
            return "the name does not resolve from this host (DNS or /etc/hosts)";
        }
        if (inChain(e, HttpConnectTimeoutException.class)) {
            return "no answer within " + CONNECT_TIMEOUT.toSeconds() + " s; a firewall drops the connection";
        }
        if (inChain(e, CertPathValidatorException.class) || chainMentions(e, "PKIX path")) {
            return tlsName == null
                    ? "its certificate is not signed by a CA this JVM trusts; add your CA with JAVA_TOOL_OPTIONS (see deploy/README.md)"
                    : "its certificate is not signed by the internal CA in MCP_TLS_TRUSTSTORE";
        }
        if (chainMentions(e, "no DNS SAN")) {
            return "its certificate does not name " + tlsName + " in subjectAltName";
        }
        if (inChain(e, ConnectException.class)) {
            return "connection refused; nothing listens on that port, or the service is not running yet";
        }
        if (inChain(e, HttpTimeoutException.class)) {
            return "connected, but no answer within 10 s";
        }
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (t instanceof SSLException) {
                return tlsName == null ? "TLS failed: " + t.getMessage()
                        : "TLS failed (" + t.getMessage() + "); the service may not accept the gateway certificate";
            }
        }
        return Objects.requireNonNullElse(rootMessage(e), e.getClass().getSimpleName());
    }

    private static boolean inChain(Throwable e, Class<? extends Throwable> type) {
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (type.isInstance(t)) {
                return true;
            }
        }
        return false;
    }

    private static boolean chainMentions(Throwable e, String text) {
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (String.valueOf(t.getMessage()).contains(text)) {
                return true;
            }
        }
        return false;
    }

    private void report(boolean required, String message) {
        if (required) {
            fail(message);
        } else {
            out.println("warn  " + message);
        }
    }

    private void ok(String message) {
        out.println("ok    " + message);
    }

    private void fail(String message) {
        failures++;
        out.println("FAIL  " + message);
    }

    private static String rootMessage(Throwable e) {
        Throwable t = e;
        while (t.getCause() != null) {
            t = t.getCause();
        }
        return t.getMessage() == null ? t.getClass().getSimpleName() : t.getMessage();
    }

    private static String randomSecret() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String redisRules() throws IOException {
        try (InputStream in = GatewaySetup.class.getResourceAsStream("redis-gateway.rules")) {
            return new String(Objects.requireNonNull(in, "redis-gateway.rules").readAllBytes(), StandardCharsets.UTF_8).strip();
        }
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }

    private static void writeIfMissing(Path file, String value) throws IOException {
        if (Files.notExists(file)) {
            writeSecret(file, value);
        }
    }

    private static void writeSecret(Path file, String value) throws IOException {
        write(file, value, "rw-------");
    }

    /**
     * Read by the PostgreSQL or Redis container, which mounts only its own volume: owner and group may read, nobody else. The
     * container joins the group of the gateway image (group_add in deploy/compose.yaml), so neither init nor the consumer needs root.
     */
    private static void writeShared(Path file, String value) throws IOException {
        write(file, value, "rw-r-----");
    }

    /** Created with its final mode and moved into place, so the content is never readable under a wider one. */
    private static void write(Path file, String value, String mode) throws IOException {
        FileAttribute<?>[] attributes = posix(file)
                ? new FileAttribute<?>[] {PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString(mode))}
                : new FileAttribute<?>[0];
        Path temp = Files.createTempFile(file.getParent(), "..", ".tmp", attributes);
        try {
            Files.writeString(temp, value);
            Files.move(temp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    /** Redis takes {@code #<sha256 hex>} in place of {@code ><password>}, so the ACL file never holds a password. */
    static String sha256(String password) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(password.getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static boolean posix(Path path) {
        return path.getFileSystem().supportedFileAttributeViews().contains("posix");
    }

    private static void createSharedDirectory(Path directory) throws IOException {
        Files.createDirectories(directory);
        setMode(directory, "rwxr-x---");
    }

    private static void restrict(Path directory) throws IOException {
        setMode(directory, "rwx------");
    }

    private static void setMode(Path path, String mode) throws IOException {
        if (posix(path)) {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(mode));
        }
    }
}
