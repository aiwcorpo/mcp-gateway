package pl.aiwcorpo.mcp.gateway.jwt;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.ParseException;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;

import pl.aiwcorpo.mcp.cedar.entities.PublishedTestKeys;

/**
 * ES256 keys of the internal JWT (C2): one active signing key and every published key (two kids, so a new key
 * can be published before it signs). Keys come from a private JWKS file or, without one, are generated at start.
 */
public final class SigningKeys {

    private static final Logger log = LoggerFactory.getLogger(SigningKeys.class);

    private final ECKey active;
    private final JWKSet publicSet;

    private SigningKeys(ECKey active, List<ECKey> all) {
        this.active = active;
        this.publicSet = new JWKSet(all.stream().map(k -> (JWK) k.toPublicJWK()).toList());
    }

    /**
     * @param devstackProfile true under the devstack profile; {@code dev-} keys need it together with {@code allowTestKeys}
     *                        (dev mode, CC-137), {@code test-} keys need {@code allowTestKeys} alone (CC-044)
     */
    public static SigningKeys load(String keysFile, String activeKid, boolean allowTestKeys, boolean devstackProfile) {
        List<ECKey> keys;
        ECKey active;
        if (keysFile == null || keysFile.isBlank()) {
            keys = generate();
            active = keys.getFirst();
            log.warn("No gateway.internal-jwt.keys-file: generated two ephemeral ES256 keys ({}, {}); receivers must "
                    + "refetch the JWKS after every restart", keys.get(0).getKeyID(), keys.get(1).getKeyID());
        } else {
            keys = read(Path.of(keysFile));
            active = keys.stream().filter(k -> k.getKeyID().equals(activeKid)).findFirst()
                    .orElseThrow(() -> new IllegalStateException("gateway.internal-jwt.active-kid not found in " + keysFile));
        }
        for (ECKey key : keys) {
            if (!allowTestKeys && key.getKeyID().startsWith("test-")) {
                throw new IllegalStateException("kid " + key.getKeyID() + ": test- keys are rejected outside tests (CC-044)");
            }
            if (!(allowTestKeys && devstackProfile) && key.getKeyID().startsWith("dev-")) {
                throw new IllegalStateException("kid " + key.getKeyID() + ": dev- keys need dev mode, the devstack profile and "
                        + "gateway.internal-jwt.allow-test-keys together (CC-137)");
            }
            if (!allowTestKeys && isPublishedTestKey(key)) {
                throw new IllegalStateException("kid " + key.getKeyID() + " is a published mcp-contracts test key");
            }
        }
        if (keys.size() < 2) {
            log.warn("Only one internal JWT key published; rotation needs a second kid published 24 h before use (C2)");
        }
        return new SigningKeys(active, keys);
    }

    private static boolean isPublishedTestKey(ECKey key) {
        try {
            return PublishedTestKeys.isPublishedTestKey(key.toECPublicKey());
        } catch (JOSEException e) {
            throw new IllegalStateException("unreadable key " + key.getKeyID(), e);
        }
    }

    public ECKey active() {
        return active;
    }

    public JWKSet publicJwks() {
        return publicSet;
    }

    private static List<ECKey> generate() {
        String date = LocalDate.now(ZoneOffset.UTC).format(DateTimeFormatter.BASIC_ISO_DATE);
        byte[] nonce = new byte[3];
        new SecureRandom().nextBytes(nonce);
        String base = "gw-" + date + "-" + HexFormat.of().formatHex(nonce);
        return List.of(generate(base + "-a"), generate(base + "-b"));
    }

    private static ECKey generate(String kid) {
        try {
            return new ECKeyGenerator(Curve.P_256).keyID(kid).algorithm(JWSAlgorithm.ES256).keyUse(KeyUse.SIGNATURE)
                    .generate();
        } catch (JOSEException e) {
            throw new IllegalStateException("ES256 key generation failed", e);
        }
    }

    private static List<ECKey> read(Path file) {
        try {
            JWKSet set = JWKSet.parse(Files.readString(file));
            List<ECKey> keys = set.getKeys().stream().map(k -> {
                if (!(k instanceof ECKey ec) || !Curve.P_256.equals(ec.getCurve()) || !ec.isPrivate() || ec.getKeyID() == null) {
                    throw new IllegalStateException(file + ": every key must be a private P-256 EC key with a kid");
                }
                return ec;
            }).toList();
            if (keys.isEmpty()) {
                throw new IllegalStateException(file + ": no keys");
            }
            return keys;
        } catch (IOException | ParseException e) {
            throw new IllegalStateException("Cannot read internal JWT keys from " + file, e);
        }
    }
}
