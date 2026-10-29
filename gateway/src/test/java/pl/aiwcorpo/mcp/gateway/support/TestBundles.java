package pl.aiwcorpo.mcp.gateway.support;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.GZIPOutputStream;

/**
 * Signed policy bundles (C7) made in tests: the policies of {@code cedar/examples} of mcp-contracts without the step-up rule
 * (it is not in a production bundle), signed with the published test keys. Strict ustar, no extensions, as the receiver demands.
 */
public final class TestBundles {

    /** An archive and its detached Ed25519 signature. */
    public record Bundle(String revision, byte[] archive, byte[] signature) {
    }

    private static final String[] EXAMPLE_POLICIES = {"call-tool", "read", "update", "forbid-restricted", "virtual-server",
        "credential-type"};

    private TestBundles() {
    }

    /** The main bundle: the example policies plus {@code extraPolicies} (file name to Cedar text). */
    public static Bundle main(String revision, Map<String, String> extraPolicies) {
        Map<String, String> files = new LinkedHashMap<>();
        files.put("manifest.json", manifest(revision));
        files.put("schema.cedarschema", resource("cedar/mcp.cedarschema"));
        for (String name : EXAMPLE_POLICIES) {
            files.put("policies/" + name + ".cedar", resource("cedar/examples/" + name + ".cedar"));
        }
        extraPolicies.forEach((name, text) -> files.put("policies/" + name, text));
        files.put("entities/static.json", resource("cedar/examples/static-entities.json"));
        return sign(revision, files, "test-policy-bundle");
    }

    /** An overrides bundle: forbid rules only. */
    public static Bundle overrides(String revision, Map<String, String> policies) {
        Map<String, String> files = new LinkedHashMap<>();
        files.put("manifest.json", manifest(revision));
        policies.forEach((name, text) -> files.put("policies/" + name, text));
        return sign(revision, files, "test-policy-overrides");
    }

    /** The same archive signed by the wrong key (the overrides key for a main bundle). */
    public static Bundle mainSignedByTheWrongKey(String revision) {
        Bundle good = main(revision, Map.of());
        return new Bundle(revision, good.archive(), signWith(good.archive(), "test-policy-overrides"));
    }

    /** A byte of the archive changed after signing. */
    public static Bundle tampered(Bundle bundle) {
        byte[] changed = bundle.archive().clone();
        changed[changed.length / 2] ^= 0x01;
        return new Bundle(bundle.revision(), changed, bundle.signature());
    }

    public static String publicKeyPem(String keyName) {
        return resource("test-vectors/keys/" + keyName + ".public.pem");
    }

    /** Revisions that grow with {@code n}: 20261028 + n minutes, a fixed hash part. */
    public static String revision(int n) {
        return String.format("202610281%03d00-abcdef1", n);
    }

    private static String manifest(String revision) {
        return "{\"revision\":\"" + revision + "\",\"gitSha\":\"" + revision.substring(15) + "0".repeat(33) + "\",\"createdAt\":\"2026-10-28T12:00:00Z\","
                + "\"schemaVersion\":\"4.0.0\"}";
    }

    private static Bundle sign(String revision, Map<String, String> files, String keyName) {
        byte[] archive = archive(files);
        return new Bundle(revision, archive, signWith(archive, keyName));
    }

    private static byte[] signWith(byte[] archive, String keyName) {
        try {
            String pem = resource("test-vectors/keys/" + keyName + ".NOT-FOR-PRODUCTION.private.pem")
                    .replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
            PrivateKey key = KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(pem)));
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(key);
            signature.update(archive);
            return signature.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] archive(Map<String, String> files) {
        try {
            ByteArrayOutputStream tar = new ByteArrayOutputStream();
            for (Map.Entry<String, String> file : files.entrySet()) {
                byte[] content = file.getValue().getBytes(StandardCharsets.UTF_8);
                tar.write(header(file.getKey(), content.length));
                tar.write(content);
                tar.write(new byte[(512 - content.length % 512) % 512]);
            }
            tar.write(new byte[1024]);
            ByteArrayOutputStream gz = new ByteArrayOutputStream();
            try (GZIPOutputStream out = new GZIPOutputStream(gz)) {
                out.write(tar.toByteArray());
            }
            return gz.toByteArray();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static byte[] header(String name, int size) {
        byte[] header = new byte[512];
        put(header, 0, name, 100);
        put(header, 100, "0000644", 8);
        put(header, 108, "0000000", 8);
        put(header, 116, "0000000", 8);
        put(header, 124, String.format("%011o", size), 12);
        put(header, 136, String.format("%011o", 1_700_000_000L), 12);
        java.util.Arrays.fill(header, 148, 156, (byte) ' ');
        header[156] = '0';
        put(header, 257, "ustar", 6);
        put(header, 263, "00", 2);
        int sum = 0;
        for (byte b : header) {
            sum += b & 0xff;
        }
        put(header, 148, String.format("%06o", sum), 7);
        header[155] = ' ';
        return header;
    }

    private static void put(byte[] target, int offset, String value, int length) {
        byte[] bytes = value.getBytes(StandardCharsets.US_ASCII);
        if (bytes.length > length) {
            throw new IllegalArgumentException(value);
        }
        System.arraycopy(bytes, 0, target, offset, bytes.length);
    }

    private static String resource(String path) {
        try (InputStream in = TestBundles.class.getClassLoader().getResourceAsStream("mcp-contracts/" + path)) {
            if (in == null) {
                throw new IllegalArgumentException("no resource " + path);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
