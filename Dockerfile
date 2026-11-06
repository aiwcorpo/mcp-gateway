# Build the jars first: ./mvnw -B verify (or install -DskipTests), then: docker build -t mcp-gateway:dev .
# A glibc image: cedar-java (policies, C7) ships native libraries for glibc, not for musl (Alpine).
FROM eclipse-temurin:25-jre@sha256:78f1f183913482ef390c2722f46c3f0ce76ada341d69590e7c482ec943ee72d5
LABEL org.opencontainers.image.source="https://github.com/aiwcorpo/mcp-gateway" \
      org.opencontainers.image.licenses="Apache-2.0"

RUN groupadd --system gateway && useradd --system --gid gateway --no-create-home --home-dir /app gateway \
    && mkdir -p /secrets/gateway /secrets/postgres /secrets/redis \
    && chown gateway:gateway /secrets/gateway /secrets/postgres /secrets/redis
WORKDIR /app
COPY --chown=root:root target/mcp-gateway.jar /app/app.jar

USER gateway
# Heap 60% of the container limit: the rest is for metaspace, threads, direct buffers and Cedar's native library (measured about 250 MB
# outside the heap under 128 requests in flight); 75% left no room under a 2 GiB limit. G1 is explicit because the JVM picks Serial under 1 CPU or 1792 MB, where G1PeriodicGCInterval would do nothing; the periodic GC lets G1 return heap after a peak.
# 8080: MCP clients (C1, /s/<serverId>/mcp, /v/<slug>/mcp, RFC 9728); 8443: internal TLS (JWKS of C2, actuator, C5 admin API).
# Cedar unpacks its native library into java.io.tmpdir: a read-only root file system needs a writable /tmp.
# /secrets/*: written by "init" on the first start (deploy/compose.yaml); a new named volume takes this owner from the image.
EXPOSE 8080 8443
ENTRYPOINT ["java", "--enable-native-access=ALL-UNNAMED", "-XX:+UseG1GC", "-XX:MaxRAMPercentage=60", "-XX:G1PeriodicGCInterval=60000", "-XX:+ExitOnOutOfMemoryError", "-jar", "/app/app.jar"]
