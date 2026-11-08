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

/** Throw-away internal CA and PKCS12 files shaped like the certs/ of the dev stack. */
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
        return issue(file, cn, dnsNames, serverAuth, clientAuth, false);
    }

    /** As above; {@code ca} marks the certificate as a CA (basicConstraints), which no client may present as its own. */
    public Path issue(String file, String cn, List<String> dnsNames, boolean serverAuth, boolean clientAuth, boolean ca)
            throws Exception {
        KeyPair keys = keyPair();
        X509Certificate cert = certificate(keys, cn, dnsNames, serverAuth, clientAuth, ca);
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        store.setKeyEntry(cn, keys.getPrivate(), PASSWORD, new Certificate[] {cert, caCert});
        Path path = dir.resolve(file);
        save(store, path);
        return path;
    }

    /**
     * A server identity as PEM files, the way the public port takes it: {@code <name>.crt} (certificate and CA) and
     * {@code <name>.key} (PKCS#8, mode {@code keyMode}); returns the two paths in that order.
     */
    public List<Path> issuePem(String name, String cn, List<String> dnsNames, String keyMode) throws Exception {
        KeyPair keys = keyPair();
        X509Certificate cert = certificate(keys, cn, dnsNames, true, false, false);
        Path crt = dir.resolve(name + ".crt");
        Path key = dir.resolve(name + ".key");
        Files.writeString(crt, pem("CERTIFICATE", cert.getEncoded()) + pem("CERTIFICATE", caCert.getEncoded()));
        Files.writeString(key, pem("PRIVATE KEY", keys.getPrivate().getEncoded()));
        Files.setPosixFilePermissions(key, java.nio.file.attribute.PosixFilePermissions.fromString(keyMode));
        return List.of(crt, key);
    }

    /** As {@link #issuePem}, with the key as an encrypted PKCS#8 PEM (AES-256) under {@code password}. */
    public List<Path> issueEncryptedPem(String name, String cn, List<String> dnsNames, String password) throws Exception {
        KeyPair keys = keyPair();
        X509Certificate cert = certificate(keys, cn, dnsNames, true, false, false);
        Path crt = dir.resolve(name + ".crt");
        Path key = dir.resolve(name + ".key");
        Files.writeString(crt, pem("CERTIFICATE", cert.getEncoded()) + pem("CERTIFICATE", caCert.getEncoded()));
        org.bouncycastle.operator.OutputEncryptor encryptor = new org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder(
                org.bouncycastle.openssl.PKCS8Generator.AES_256_CBC).setPasssword(password.toCharArray())
                .setProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider()).build();
        java.io.StringWriter text = new java.io.StringWriter();
        try (org.bouncycastle.openssl.jcajce.JcaPEMWriter writer = new org.bouncycastle.openssl.jcajce.JcaPEMWriter(text)) {
            writer.writeObject(new org.bouncycastle.openssl.jcajce.JcaPKCS8Generator(keys.getPrivate(), encryptor));
        }
        Files.writeString(key, text.toString());
        Files.setPosixFilePermissions(key, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        return List.of(crt, key);
    }

    /**
     * A keystore with a self-signed certificate (no CA stands behind it), like the one the starter generates at its first start. Returns
     * the path; {@link #fingerprint} gives what an administrator pins.
     */
    public static Path selfSigned(Path dir, String file, String cn, List<String> names) throws Exception {
        KeyPair keys = keyPair();
        X500Name name = new X500Name("CN=" + cn);
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(name, serial(), Date.from(Instant.now().minusSeconds(60)),
                Date.from(Instant.now().plus(Duration.ofDays(30))), name, keys.getPublic());
        GeneralName[] sans = names.stream().map(n -> n.matches("^[0-9.]+$")
                ? new GeneralName(GeneralName.iPAddress, n) : new GeneralName(GeneralName.dNSName, n)).toArray(GeneralName[]::new);
        if (sans.length > 0) {
            builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(sans));
        }
        X509Certificate cert = sign(builder, keys);
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        store.setKeyEntry(cn, keys.getPrivate(), PASSWORD, new Certificate[] {cert});
        Path path = dir.resolve(file);
        save(store, path);
        return path;
    }

    /** The fingerprint (sha256 of the DER) of the certificate in a keystore, as the gateway shows and pins it. */
    public static String fingerprint(Path keystore) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (java.io.InputStream in = Files.newInputStream(keystore)) {
            store.load(in, PASSWORD);
        }
        String alias = store.aliases().nextElement();
        return pl.aiwcorpo.mcp.gateway.tls.ServerCertificate.fingerprintOf(store.getCertificate(alias).getEncoded());
    }

    /** The CA certificate alone, for a client that is to trust this PKI and nothing else. */
    public Path caPem(String name) throws Exception {
        Path path = dir.resolve(name + ".crt");
        Files.writeString(path, pem("CERTIFICATE", caCert.getEncoded()));
        return path;
    }

    private static String pem(String type, byte[] der) {
        return "-----BEGIN " + type + "-----\n" + java.util.Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(der)
                + "\n-----END " + type + "-----\n";
    }

    private X509Certificate certificate(KeyPair keys, String cn, List<String> dnsNames, boolean serverAuth, boolean clientAuth,
                                        boolean ca) throws Exception {
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(new X500Name("CN=test-internal-ca"), serial(),
                Date.from(Instant.now().minusSeconds(60)), Date.from(Instant.now().plus(Duration.ofDays(1))),
                new X500Name("CN=" + cn), keys.getPublic());
        GeneralName[] sans = dnsNames.stream().map(n -> n.matches("^[0-9.]+$")
                ? new GeneralName(GeneralName.iPAddress, n) : new GeneralName(GeneralName.dNSName, n)).toArray(GeneralName[]::new);
        if (sans.length > 0) {
            builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(sans));
        }
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        List<KeyPurposeId> purposes = new java.util.ArrayList<>();
        if (serverAuth) {
            purposes.add(KeyPurposeId.id_kp_serverAuth);
        }
        if (clientAuth) {
            purposes.add(KeyPurposeId.id_kp_clientAuth);
        }
        builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(purposes.toArray(KeyPurposeId[]::new)));
        return sign(builder, caKeys);
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
