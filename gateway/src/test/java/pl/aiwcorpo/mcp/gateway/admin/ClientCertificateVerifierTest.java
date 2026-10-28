package pl.aiwcorpo.mcp.gateway.admin;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import pl.aiwcorpo.mcp.gateway.support.TestPki;

class ClientCertificateVerifierTest {

    private static Path dir;
    private static TestPki pki;
    private static TestPki foreign;
    private static ClientCertificateVerifier verifier;

    @BeforeAll
    static void setUp(@TempDir Path temp) throws Exception {
        dir = temp;
        pki = new TestPki(Files.createDirectory(dir.resolve("own")));
        foreign = new TestPki(Files.createDirectory(dir.resolve("foreign")));
        verifier = new ClientCertificateVerifier(pki.truststore(), TestPki.PASSWORD);
    }

    @Test
    void acceptsAClientAuthCertificateOfTheInternalCaWithOrWithoutTheCaInTheChain() throws Exception {
        X509Certificate[] full = chain(pki.issue("bff.p12", "mcp-portal-bff", List.of(), false, true));
        assertThat(full).hasSize(2);
        assertThat(verifier.verified(full, Instant.now())).isPresent();
        assertThat(verifier.verified(new X509Certificate[] {full[0]}, Instant.now())).isPresent();
    }

    @Test
    void rejectsServerOnlyForeignAndExpiredCertificates() throws Exception {
        X509Certificate[] serverOnly = chain(pki.issue("jira.p12", "mcp-jira", List.of("mcp-jira.internal"), true, false));
        assertThat(verifier.verified(serverOnly, Instant.now())).as("serverAuth only").isEmpty();

        X509Certificate[] foreignClient = chain(foreign.issue("bff.p12", "mcp-portal-bff", List.of(), false, true));
        assertThat(verifier.verified(foreignClient, Instant.now())).as("other CA").isEmpty();

        X509Certificate[] own = chain(pki.issue("ci.p12", "mcp-registry-ci", List.of(), false, true));
        assertThat(verifier.verified(own, Instant.now().plus(Duration.ofDays(3)))).as("expired").isEmpty();
        assertThat(verifier.verified(own, Instant.now().minus(Duration.ofDays(3)))).as("not yet valid").isEmpty();

        assertThat(verifier.verified(new X509Certificate[0], Instant.now())).isEmpty();
        assertThat(verifier.verified(null, Instant.now())).isEmpty();
    }

    @Test
    void aCertificateClaimingTheCaNameButSignedByAnotherKeyIsRejected() throws Exception {
        X509Certificate[] fake = chain(foreign.issue("fake.p12", "mcp-portal-bff", List.of(), false, true));
        X509Certificate[] withOwnCaAppended = {fake[0], chain(pki.issue("x.p12", "x", List.of(), false, true))[1]};
        assertThat(verifier.verified(withOwnCaAppended, Instant.now())).isEmpty();
    }

    private static X509Certificate[] chain(Path keystore) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (var in = Files.newInputStream(keystore)) {
            store.load(in, TestPki.PASSWORD);
        }
        String alias = store.aliases().nextElement();
        Certificate[] raw = store.getCertificateChain(alias);
        X509Certificate[] out = new X509Certificate[raw.length];
        for (int i = 0; i < raw.length; i++) {
            out[i] = (X509Certificate) raw[i];
        }
        return out;
    }
}
