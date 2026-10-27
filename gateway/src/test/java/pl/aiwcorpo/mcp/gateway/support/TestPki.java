package pl.aiwcorpo.mcp.gateway.support;

import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/** Throw-away internal CA and PKCS12 files shaped like mcp-platform-dev's certs/. */
public final class TestPki {

    public static final char[] PASSWORD = "test-store-password".toCharArray();

    private final Path dir;
    private final KeyPair caKeys;
    private final X509Certificate caCert;

    public TestPki(Path dir) throws Exception {
        this.dir = dir;
        this.caKeys = keyPair();
        X500Name name = new X500Name("CN=test-internal-ca");
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(name, serial(), Date.from(Instant.now().minusSeconds(60)),
                Date.from(Instant.now().plus(Duration.ofDays(2))), name, caKeys.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        this.caCert = sign(builder, caKeys);
        KeyStore trust = KeyStore.getInstance("PKCS12");
        trust.load(null, null);
        trust.setCertificateEntry("ca", caCert);
        save(trust, truststore());
    }

    public Path truststore() {
        return dir.resolve("truststore.p12");
    }

    /** Keystore with a certificate CN={@code cn}, the given DNS/IP SANs and EKU server and/or client auth. */
    public Path issue(String file, String cn, List<String> dnsNames, boolean serverAuth, boolean clientAuth) throws Exception {
        KeyPair keys = keyPair();
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(new X500Name("CN=test-internal-ca"), serial(),
                Date.from(Instant.now().minusSeconds(60)), Date.from(Instant.now().plus(Duration.ofDays(1))),
                new X500Name("CN=" + cn), keys.getPublic());
        GeneralName[] sans = dnsNames.stream().map(n -> n.matches("^[0-9.]+$")
                ? new GeneralName(GeneralName.iPAddress, n) : new GeneralName(GeneralName.dNSName, n)).toArray(GeneralName[]::new);
        if (sans.length > 0) {
            builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(sans));
        }
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        List<KeyPurposeId> purposes = new java.util.ArrayList<>();
        if (serverAuth) {
            purposes.add(KeyPurposeId.id_kp_serverAuth);
        }
        if (clientAuth) {
            purposes.add(KeyPurposeId.id_kp_clientAuth);
        }
        builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(purposes.toArray(KeyPurposeId[]::new)));
        X509Certificate cert = sign(builder, caKeys);
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        store.setKeyEntry(cn, keys.getPrivate(), PASSWORD, new Certificate[] {cert, caCert});
        Path path = dir.resolve(file);
        save(store, path);
        return path;
    }

    private static KeyPair keyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    private static BigInteger serial() {
        return new BigInteger(64, new SecureRandom());
    }

    private static X509Certificate sign(X509v3CertificateBuilder builder, KeyPair issuer) throws Exception {
        return new JcaX509CertificateConverter().getCertificate(
                builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(issuer.getPrivate())));
    }

    private static void save(KeyStore store, Path path) throws Exception {
        try (OutputStream out = Files.newOutputStream(path)) {
            store.store(out, PASSWORD);
        }
    }
}
