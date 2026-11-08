package pl.aiwcorpo.mcp.gateway.tls;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HexFormat;
import java.util.List;

/**
 * What the administrator is shown of the certificate a server presents (C5 {@code PendingConnection}): subject, issuer, the names it
 * carries, its end of validity and the fingerprint, which is the SHA-256 of the DER encoding (never of the PEM text) as
 * {@code sha256:<64 lower-case hex digits>}.
 */
public record ServerCertificate(String fingerprint, String subject, String issuer, List<String> sans, Instant notAfter) {

    private static final int SAN_DNS = 2;
    private static final int SAN_IP = 7;

    public static ServerCertificate of(X509Certificate certificate) {
        try {
            return new ServerCertificate(fingerprintOf(certificate.getEncoded()), certificate.getSubjectX500Principal().getName(),
                    certificate.getIssuerX500Principal().getName(), names(certificate), certificate.getNotAfter().toInstant());
        } catch (CertificateEncodingException e) {
            throw new IllegalArgumentException("the certificate cannot be encoded", e);
        }
    }

    public static String fingerprintOf(byte[] der) {
        try {
            return "sha256:" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(der));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static List<String> names(X509Certificate certificate) {
        List<String> out = new ArrayList<>();
        try {
            Collection<List<?>> alternatives = certificate.getSubjectAlternativeNames();
            if (alternatives != null) {
                for (List<?> entry : alternatives) {
                    Object type = entry.get(0);
                    if (entry.size() >= 2 && (Integer.valueOf(SAN_DNS).equals(type) || Integer.valueOf(SAN_IP).equals(type))) {
                        out.add(String.valueOf(entry.get(1)));
                    }
                }
            }
        } catch (CertificateParsingException e) {
            // A certificate whose names cannot be read shows none; the fingerprint is what is approved.
            return List.of();
        }
        return out;
    }
}
