# Build the jars first: ./mvnw -B verify (or install -DskipTests), then: docker build -t mcp-gateway:dev .
# A glibc image: cedar-java (policies, C7) ships native libraries for glibc, not for musl (Alpine).
FROM eclipse-temurin:25-jre@sha256:78f1f183913482ef390c2722f46c3f0ce76ada341d69590e7c482ec943ee72d5

RUN groupadd --system gateway && useradd --system --gid gateway --no-create-home --home-dir /app gateway \
    && mkdir -p /app/state && chown gateway:gateway /app/state
WORKDIR /app
COPY --chown=root:root gateway/target/mcp-gateway.jar /app/app.jar

USER gateway
# Heap 60% of the container limit: the rest is for metaspace, threads, direct buffers and Cedar's native library (measured about 250 MB
# outside the heap under 128 requests in flight); 75% left no room under a 2 GiB limit. The periodic GC lets G1 return heap after a peak.
# 8080: MCP clients (C1, /s/<serverId>/mcp, /v/<slug>/mcp, RFC 9728); 8443: internal TLS (JWKS of C2, actuator, C5 admin API).
# Cedar unpacks its native library into java.io.tmpdir: a read-only root file system needs a writable /tmp.
# /app/state holds the rollback protection of the policy bundles (MCP_POLICY_STATE_DIR): mount a volume per instance.
EXPOSE 8080 8443
ENTRYPOINT ["java", "--enable-native-access=ALL-UNNAMED", "-XX:MaxRAMPercentage=60", "-XX:G1PeriodicGCInterval=60000", "-XX:+ExitOnOutOfMemoryError", "-jar", "/app/app.jar"]
