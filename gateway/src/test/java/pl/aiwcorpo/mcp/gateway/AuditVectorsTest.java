package pl.aiwcorpo.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;

import pl.aiwcorpo.mcp.gateway.support.Contracts;
import pl.aiwcorpo.mcp.gateway.support.Vectors;

/** The C8 vectors of mcp-contracts 3.0.1 (CC-120, CC-125 among them) against the schema the gateway's events are checked with. */
class AuditVectorsTest {

    @Test
    void everyAuditVectorIsJudgedAsTheContractExpects() {
        List<Vectors.Vector> vectors = Vectors.of("audit-events");
        assertThat(vectors).hasSizeGreaterThan(70);
        assertThat(vectors.stream().map(Vectors.Vector::name)).contains("gateway-authentication-denied-expired.json",
                "gateway-authentication-denied-wrong-audience.json", "gateway-authentication-denied-jwks-unavailable.json",
                "gateway-authentication-denied-admin-client-certificate.json", "gateway-authentication-denied-admin-bff-token.json",
                "invalid-authentication-replay-store-unavailable-gateway.json", "invalid-authentication-with-backend-user.json",
                "invalid-authentication-jwks-unavailable-unauthenticated.json");
        for (Vectors.Vector vector : vectors) {
            boolean expectedValid = vector.document().path("expected").path("valid").asBoolean();
            List<String> errors = Contracts.schemaErrors("schemas/audit-event.schema.json", vector.document().path("event"));
            assertThat(errors.isEmpty()).as(vector.name() + " " + errors).isEqualTo(expectedValid);
        }
    }
}
