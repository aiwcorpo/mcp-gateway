# mcp-gateway

Part of [MCP Platform](https://github.com/aiwcorpo/mcp-platform), a self-hosted MCP gateway for companies. Documentation: [mcp.aiwcorpo.pl](https://mcp.aiwcorpo.pl/).

The single entry point for AI clients on the aiwcorpo MCP platform: it signs the user in with the identity provider token, takes the user's credential from the credential broker and forwards the call to the MCP server.

## Quick start

The gateway is normally installed with the rest of the platform, through the Compose bundle in `mcp-platform`:

```bash
cd mcp-platform
cp platform.env .env        # set MCP_DOMAIN
docker compose up -d
```

Steps: [mcp-platform/README.md](https://github.com/aiwcorpo/mcp-platform#readme).

To run the gateway alone (with its own PostgreSQL and Redis, against an identity provider and a broker you already have):

```bash
cd deploy
# put certs/keystore.p12 and certs/truststore.p12 in place, fill in the empty values in gateway.env
docker compose up -d
docker compose logs init
```

Full steps: [deploy/README.md](deploy/README.md).

## Ports and endpoints

| Port | Who calls it | What it serves |
| --- | --- | --- |
| 8080 | AI clients, through your reverse proxy | `/mcp`, `/s/`, `/.well-known/oauth-protected-resource`, `/.well-known/mcp-jwks.json` (the keys that MCP servers use to verify the gateway) |
| 8443 | the platform, over TLS | `/admin/v1/*` (the portal), `/actuator/health`, `/actuator/prometheus` |

The public port serves no actuator, and the internal one serves no MCP paths. MCP servers are not listed in the configuration: an administrator adds one by its address in the portal.

## Configuration

Required, in `deploy/gateway.env`. The Compose files set the database, Redis and keystore settings and generate keys and passwords.

| Variable | Description |
| --- | --- |
| `MCP_PUBLIC_URL` | public address of the gateway, `https://<domain>` |
| `MCP_OIDC_ISSUER` | issuer of the identity provider |
| `MCP_OIDC_JWKS_URI` | key set of the identity provider |
| `MCP_BROKER_URL` | address of the credential broker, `https://<host>:8443` |
| `MCP_BROKER_TLS_NAME` | name in the broker certificate (default in the file: `mcp-credential-broker.internal`) |
| `MCP_TLS_STORE_PASSWORD` | password of both stores in `certs/` |

Optional settings (allowed AI clients, rate limits, own certificate on the public port, refused server addresses) are listed in `src/main/resources/application.yml`.

## Tracing

Off by default; no collector is needed. Set `MCP_OTLP_ENDPOINT` to the OTLP/HTTP traces URL of your collector, with the path, for example
`http://collector:4318/v1/traces`, and restart. Spans are exported under the service name `mcp-gateway`.

- A W3C `traceparent` (and `tracestate`) from the client is continued: the gateway's request span is a child of the client's span. The
  credential broker and the MCP server get a `traceparent` with the same trace id and a span id of the gateway's own call to them
  (`tracestate` is passed on as received). Without a header from the client the gateway starts a trace and sends it on in the same way.
  Baggage is not read or sent.
- Of the traces that start at the gateway 10 % are sampled; change it with `MANAGEMENT_TRACING_SAMPLING_PROBABILITY` (0.0 to 1.0). A trace
  whose `traceparent` the client marked as sampled is kept, and one marked unsampled stays unsampled on every hop. The gateway does not
  tell a trusted client from any other: a caller of the public port can force sampling of its requests, and chooses the trace id. Treat the
  collector as accepting that load, or keep the exposed port behind a proxy that rewrites or drops `traceparent`. Spring Boot propagates the trace context only while span export is on, so
  `MANAGEMENT_TRACING_EXPORT_ENABLED=false` also stops the headers.
- Calls the gateway makes outside a client request (start-up check of the broker, manifest and policy data pushes to servers, the identity
  provider) start no span and carry no `traceparent`.
- `MANAGEMENT_OPENTELEMETRY_ENABLED=false` (the SDK and exporter) or `MANAGEMENT_TRACING_EXPORT_ENABLED=false` (the spans and the headers)
  switches tracing off even when `MCP_OTLP_ENDPOINT` is set. `management.tracing.enabled` has no effect in Spring Boot 4. Other exporter settings (headers for the
  collector, TLS bundle, timeouts, gRPC) are the Spring Boot properties under `management.opentelemetry.tracing.export.otlp.*`.

Recorded on the spans, and nothing else:

| Span | Attributes |
| --- | --- |
| request (server) | HTTP method, route template (`/s/{serverId}/mcp`, never the path with the real ids), status, outcome, exception class |
| call to the broker or to an MCP server (client) | `peer.service` (`mcp-credential-broker` or `mcp-server`), HTTP method, `server.address`, `server.port`, status, `error.type` on a failure |

No token, header, request or response body, tool name, tool argument or result, user id or URL path is recorded. The client span ends when
the response headers arrive. Spring Security, Redis and scheduled-task spans are switched off. A request that ends in an exception no handler
answers has it recorded on its span as Spring Boot does (type, message, stack); exception messages are held to the same rule as log lines.

## Build

```bash
export JAVA_HOME=<path to JDK 25>
./mvnw -B verify
```

The jar is `target/mcp-gateway.jar`; `docker build -t mcp-gateway:dev .` builds the image. The tests start PostgreSQL and Redis with Testcontainers, so they need Docker. Working on the code: [CONTRIBUTING.md](CONTRIBUTING.md).

## More

- [deploy/README.md](deploy/README.md): installation, adding servers, upgrade
- [CHANGELOG.md](CHANGELOG.md), [SECURITY.md](SECURITY.md)

Apache License 2.0.
