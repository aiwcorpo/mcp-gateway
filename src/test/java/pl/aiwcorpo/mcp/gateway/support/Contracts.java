package pl.aiwcorpo.mcp.gateway.support;

import java.util.List;

import com.networknt.schema.Schema;
import com.networknt.schema.SchemaLocation;
import com.networknt.schema.SchemaRegistry;
import com.networknt.schema.SpecificationVersion;

import tools.jackson.databind.JsonNode;

/** JSON Schema checks against the mcp-contracts jar on the test classpath. */
public final class Contracts {

    private static final SchemaRegistry SCHEMAS = SchemaRegistry.withDefaultDialect(SpecificationVersion.DRAFT_2020_12);

    private Contracts() {
    }

    /** Errors of {@code value} against e.g. {@code schemas/audit-event.schema.json}; empty = valid. */
    public static List<String> schemaErrors(String schemaPath, JsonNode value) {
        Schema schema = SCHEMAS.getSchema(SchemaLocation.of("classpath:mcp-contracts/" + schemaPath));
        return schema.validate(value).stream().map(Object::toString).toList();
    }

    /** Errors of {@code value} against a schema of the C5 OpenAPI document, e.g. {@code Catalog} or {@code VirtualServer}. */
    public static List<String> gatewayAdminErrors(String component, JsonNode value) {
        Schema schema = SCHEMAS.getSchema(SchemaLocation.of(
                "classpath:mcp-contracts/openapi/gateway-admin.v1.yaml#/components/schemas/" + component));
        return schema.validate(value).stream().map(Object::toString).toList();
    }
}
