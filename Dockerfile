# Build the jars first: ./mvnw -B verify (or install -DskipTests), then: docker build -t mcp-gateway:dev .
FROM eclipse-temurin:25-jre-alpine@sha256:b7528962e65d43064d8a8b67ba175367896bc948363ea2d3fcd7f10d34e1f048

RUN addgroup -S gateway && adduser -S -G gateway -H -h /app gateway
WORKDIR /app
COPY --chown=root:root gateway/target/mcp-gateway.jar /app/app.jar

USER gateway
# 8080: MCP clients (C1, /s/<serverId>/mcp, /v/<slug>/mcp, RFC 9728); 8443: internal TLS (JWKS of C2, actuator, C5 admin API).
EXPOSE 8080 8443
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-XX:+ExitOnOutOfMemoryError", "-jar", "/app/app.jar"]
