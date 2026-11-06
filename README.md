# mcp-gateway

The single entry point for AI clients on the MCP platform. The gateway authenticates the user with the identity
provider token, fetches the user's credential for the target system from the credential broker, issues a short-lived
internal JWT and forwards the call to the MCP server over mutual TLS. Every tool call produces audit events that share one
`requestId`.

It is a deployable component (container image `mcp-gateway`), not a library. The intended readers are platform operators.
Installation: [deploy/README.md](deploy/README.md) (Docker Compose, or systemd on a virtual machine).

Contracts: `mcp-contracts` 7.0.0. What works, what is missing and the known deviations: [STATUS.md](STATUS.md) (in Polish).
License: Apache-2.0 ([LICENSE](LICENSE), [NOTICE](NOTICE)). Changes: [CHANGELOG.md](CHANGELOG.md). Contributing:
[CONTRIBUTING.md](CONTRIBUTING.md). Reporting vulnerabilities: [SECURITY.md](SECURITY.md).

## What it needs

PostgreSQL (registry, kill switches, activity; Flyway creates the schema at start), Redis with a `gateway` account
(sessions, confirmations, rate limits; `noeviction`, `appendonly yes`), an OIDC identity provider (Keycloak or Entra),
`mcp-credential-broker` and MCP servers reachable over mTLS with certificates from one internal CA. There is no list of servers in
the configuration: servers are added and removed at runtime (see "Servers and policies").
`deploy/compose.yaml` brings its own PostgreSQL and Redis with a replica.

Ports: `8080` for MCP clients (public) and `8443` for TLS with the gateway certificate (internal JWKS, `/actuator/health`,
`/actuator/prometheus`, `/admin/v1/*`). The internal port does not serve MCP paths and the public one serves neither JWKS nor
actuator.

## Build and test

JDK 25 and Docker are required (Testcontainers starts Redis with an ACL and PostgreSQL 18.6). On Windows use WSL2.

```bash
./mvnw -B verify                                     # tests and target/mcp-gateway.jar
docker build -t mcp-gateway:dev .
```

Run it locally without anything else than Docker: the run configuration `LocalGateway` (`.run/`, IntelliJ picks it up) or
`MCP_DEVSTACK_ACKNOWLEDGED=true ./mvnw spring-boot:test-run -Dspring-boot.run.mainClass=pl.aiwcorpo.mcp.gateway.LocalGatewayApplication`.
It starts Redis and PostgreSQL in containers and the stand-ins of the integration tests (IdP, broker, test MCP servers), adds the test
servers to the registry through the admin service, then starts the gateway on `http://localhost:18600/mcp`, and writes a user token for it
to `target/local-gateway.token`.

One Maven module (Spring Boot 4.1.0, Java 25); IntelliJ opens the directory as a Maven project. `src/test/java/.../testserver` is a
minimal MCP server and a broker stub that the integration tests start in place of the real components; it is test code, not a
product. The gateway was load tested in a separate private suite; the method and results are in the scaling chapter of `mcp-docs`.

The `mcp-contracts` artifacts come from Maven Central, so no registry login is needed. The GitHub, GitLab and Jenkins files run
`./mvnw -B verify`; write access and the Docker socket are granted by the CI system, not by files in a branch. The release
workflow (`release.yml`) has three jobs: build (read-only), publish (`packages: write`, only `docker load` and `docker push`) and
release (`contents: write`, only `gh release create`).

## Configuration

All settings are environment variables read from `src/main/resources/application.yml`. The generated table of
variables, defaults and which ones are mandatory is in mcp-docs: `docs/reference/env-gateway.md`. Do not copy it here.

The shortest set that is needed to start outside the dev profile:

- `MCP_PUBLIC_URL`: the public origin. It is the only source of `resource_metadata`, RFC 9728 `resource` and `connectUrl`;
  the `Host` and `X-Forwarded-*` headers are ignored.
- `MCP_OIDC_ISSUER`, `MCP_OIDC_JWKS_URI`: issuer and keys of the identity provider.
- `MCP_DB_URL`, `MCP_DB_USER`, `MCP_DB_PASSWORD`; `MCP_REDIS_HOST`, `MCP_REDIS_USER`, `MCP_REDIS_PASSWORD`.
- `MCP_TLS_KEYSTORE`, `MCP_TLS_TRUSTSTORE`, `MCP_TLS_STORE_PASSWORD`: the gateway certificate (CN `mcp-gateway`) and the internal CA.
- `MCP_BROKER_URL`, `MCP_BROKER_TLS_NAME`.
- `MCP_INTERNAL_JWT_KEYS_FILE`, `MCP_INTERNAL_JWT_ACTIVE_KID`, `MCP_LIST_CURSOR_KEY`, `MCP_ACTIVITY_CURSOR_KEY`: shared by all instances.
  `java -jar mcp-gateway.jar init <dir>` generates the ones that are not set (and the PostgreSQL and Redis passwords) into `<dir>`
  once, then checks the configuration and the connections; the gateway reads them with
  `SPRING_CONFIG_IMPORT=optional:configtree:<dir>/gateway/env/`. Both files in `deploy/` do this.
- `MCP_ALLOWED_CLIENTS`: the AI clients (`azp`) that may call, default `claude-code,claude-ai`; the same on every instance.

With two or more instances, share Redis, PostgreSQL, the C2 key file and the cursor keys. Changes of servers, approvals, the scope mapping,
overrides and kill switches reach the other instances within a second (`MCP_CHANGE_POLL_INTERVAL`).

### Servers and policies

The list of servers, the scope mapping and the emergency overrides are data in PostgreSQL, changed through the admin API
(`/admin/v1/servers`, `/admin/v1/policy/*`, the portal calls them) and never through the environment. Adding a server: `POST
/admin/v1/servers`; its pipeline registers the manifest (`PUT /admin/v1/registry/servers/{serverId}`), an administrator approves the policies
and the tools that wait; it has tools for nobody before that. Removing it: `DELETE /admin/v1/servers/{serverId}`. Nothing restarts.

Gateway decisions on `call` use the platform policies of `mcp-contracts` (a user needs the group `mcp-<system>-read`, `-write` or
`-destructive`, and a write needs the scopes of the resources it names) and the overrides of the administrator. The policies of a system
live in its MCP server, are part of its manifest and take effect only after approval; the server gets the scope mapping and the overrides
for it from `GET /internal/v1/policy-data`. `deploy/README.md` has the procedure.

Optional TLS on the public port: `MCP_PUBLIC_TLS_ENABLED=true` with `MCP_PUBLIC_TLS_CERTIFICATE` and `MCP_PUBLIC_TLS_PRIVATE_KEY` (PEM, PKCS#8).
Start is refused when either is missing or unreadable. The proxy in front should verify this certificate against the internal CA.

Upgrades, rolling updates, rollback notes and the kill switch procedure are in `docs/operator/upgrades.md` and the other pages of the operator guide.

### Development profile

Relaxations meant only for a dev stack (`test-*` signing keys, plain http, taking the manifest and the policies a server serves itself on
first use) work only when the profile is exactly `devstack` and two acknowledgements are set: the property
`aiwcorpo.mcp.platform.devstack.acknowledged=true` and the process environment variable `MCP_DEVSTACK_ACKNOWLEDGED=true`.
Otherwise the gateway refuses to start. A start with the profile logs `event=devstack_profile` at WARN and sets the gauge
`mcp_gateway_devstack_active` to 1. Details: `docs/operator/dev-profile.md`.

## Security

Invariants of this component. The platform-wide list is in `docs/security/invariants.md`.

- The AI client is untrusted. Policy is checked on every call; the filter in the `/mcp` address only narrows the tool list.
- The IdP token is never passed to a target system. The gateway swaps it for a credential from the broker and sends the server a new
  ES256 JWT (30 s lifetime) with headers built from scratch; no client header is copied.
- Fail closed: no policy data, an unreachable broker, an unreadable kill switch state or an unknown tool means refusal.
- A tool that does not exist and one the user may not use get the same answer, `not_found_or_denied`.
- A tool definition is pinned by hash. If the server serves a different one, the tool is hidden (`definition_changed`).
- `DESTRUCTIVE` actions need a one-time TOTP confirmation bound to user, tool and arguments.
- Secret values do not reach logs or audit events; audit records only `argsLength`, not argument values.
- A server evaluates only policies that an administrator approved (`approvedPoliciesHash`), and a running server that presents others is
  blocked. Policy data that cannot be used makes every decision a deny.
- Keys published for tests are refused outside the dev profile.
- The admin API (`/admin/v1/*`) is on the internal port only and needs a client certificate with an allowed CN plus a token with `aud=mcp-gateway-admin`.
- Rejected tokens are audited without a rate limit, so limit their number at the edge (for example nginx `limit_req` per address).

## Source layout

Packages under `pl.aiwcorpo.mcp.gateway`: `admin`, `auth`, `authz`, `policy`, `confirm`, `activity`, `registry`, `killswitch`,
`stream`, `edge`, `audit`, `broker`, `config`, `jwt`, `mcp`, `server`, `tls`, `upstream`.
