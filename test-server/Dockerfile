# Test MCP server for the M1 demo in place of mcp-jira. Not a product.
# From the repository root: ./mvnw -B install -DskipTests && docker build -t mcp-gateway-test-server:dev -f test-server/Dockerfile .
FROM eclipse-temurin:25-jre-alpine@sha256:b7528962e65d43064d8a8b67ba175367896bc948363ea2d3fcd7f10d34e1f048

RUN addgroup -S mcp && adduser -S -G mcp -H -h /app mcp
WORKDIR /app
COPY --chown=root:root test-server/target/mcp-gateway-test-server-exec.jar /app/app.jar

USER mcp
EXPOSE 8443
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-XX:+ExitOnOutOfMemoryError", "-jar", "/app/app.jar"]
