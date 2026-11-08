package pl.aiwcorpo.mcp.gateway.tls;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Pattern;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import pl.aiwcorpo.mcp.gateway.support.Vectors;
import tools.jackson.databind.JsonNode;

/** The vectors of {@code certificate-fingerprint/} (CC-249): the fingerprint is the SHA-256 of the DER, never of a text of it. */
class ServerCertificateVectorsTest {

    private static final Pattern FORMAT = Pattern.compile("^sha256:[0-9a-f]{64}$");

    private static X509Certificate parse(String pem) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
    }

    @TestFactory
    List<DynamicTest> theVectors() {
        List<DynamicTest> tests = new ArrayList<>();
        for (Vectors.Vector vector : Vectors.of("certificate-fingerprint")) {
            tests.add(DynamicTest.dynamicTest(vector.name(), () -> run(vector.document())));
        }
        assertThat(tests).hasSize(12);
        return tests;
    }

    private void run(JsonNode vector) throws Exception {
        JsonNode expected = vector.path("expected");
        String why = vector.path("description").asString();
        if (vector.has("fingerprint") && !vector.has("certificatePem")) {
            assertThat(FORMAT.matcher(vector.path("fingerprint").asString()).matches()).as(why).isEqualTo(expected.path("valid").asBoolean());
            return;
        }
        if (vector.has("approved")) {
            ServerCertificate presented = ServerCertificate.of(parse(vector.path("presented").path("certificatePem").asString()));
            assertThat(presented.fingerprint().equals(vector.path("approved").asString())).as(why).isEqualTo(expected.path("matches").asBoolean());
            return;
        }
        X509Certificate certificate = parse(vector.path("certificatePem").asString());
        ServerCertificate shown = ServerCertificate.of(certificate);
        assertThat(ServerCertificate.fingerprintOf(Base64.getDecoder().decode(vector.path("derBase64").asString()))).as(why).isEqualTo(shown.fingerprint());
        assertThat(shown.fingerprint()).as(why).isEqualTo(expected.path("fingerprint").asString());
        String claimed = vector.path("claimedFingerprint").asString(vector.path("fingerprint").asString(shown.fingerprint()));
        assertThat(claimed.equals(shown.fingerprint())).as(why).isEqualTo(expected.path("matches").asBoolean());
        if (vector.has("subject")) {
            assertThat(shown.subject()).isEqualTo(vector.path("subject").asString());
            assertThat(shown.issuer()).isEqualTo(vector.path("issuer").asString());
            List<String> sans = new ArrayList<>();
            vector.path("sans").forEach(name -> sans.add(name.asString()));
            assertThat(shown.sans()).isEqualTo(sans);
            assertThat(shown.notAfter()).isEqualTo(Instant.parse(vector.path("notAfter").asString()));
        }
    }
}
