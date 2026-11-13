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
