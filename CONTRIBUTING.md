# Contributing

Changes go through a pull request.

- Behaviour that a client or another component sees follows `mcp-contracts` (`openapi/gateway-admin.v1.yaml`, `schemas/`,
  `test-vectors/`). A change of an operation, a status code, an audit reason or a vector is made there first
  (`CONTRACT_CHANGES.md`); here you bump `mcp-contracts.version` and follow it. The vector tests must pass.
- Do not put secret values, tokens or confirmation codes in logs, audit events or error bodies; the tests check this.
- Commits: English subject up to 72 characters in the imperative mood, a body that describes the change.
- Never commit key material, `.env` files or the output of a build.

## Setup

JDK 25 and Docker (Testcontainers starts Redis with an ACL and PostgreSQL 18.6). On Windows use WSL2. One Maven module (Spring
Boot 4.1.0); IntelliJ opens the directory as a Maven project. The `mcp-contracts` artifacts come from Maven Central, so no registry
login is needed.

```bash
./mvnw -B verify                                     # tests and target/mcp-gateway.jar
docker build -t mcp-gateway:dev .
```

`src/test/java/.../testserver` holds a minimal MCP server and a broker stub that the integration tests start in place of the real
components. It is test code, not a product.

## Running locally

The run configuration `LocalGateway` (`.run/`, IntelliJ picks it up) or:

```bash
MCP_DEVSTACK_ACKNOWLEDGED=true ./mvnw spring-boot:test-run -Dspring-boot.run.mainClass=pl.aiwcorpo.mcp.gateway.LocalGatewayApplication
```

It starts Redis and PostgreSQL in containers and the stand-ins of the integration tests (identity provider, broker, test MCP
servers), adds the test servers by their address, starts the gateway on `http://localhost:18600/mcp` and writes a user token to
`target/local-gateway.token`.

Relaxations meant only for a dev stack (`test-*` signing keys, plain http, servers on the loopback interface, approval of a server
on first use) work only with the profile `devstack` and two acknowledgements: the property
`aiwcorpo.mcp.platform.devstack.acknowledged=true` and the environment variable `MCP_DEVSTACK_ACKNOWLEDGED=true`. Otherwise the
gateway refuses to start. A start with the profile logs `event=devstack_profile` at WARN and sets the gauge
`mcp_gateway_devstack_active` to 1.

## CI and release

The GitHub, GitLab and Jenkins files run `./mvnw -B verify`; write access and the Docker socket come from the CI system, not from
files in a branch. The release workflow (`release.yml`) has three jobs: build (read-only), publish (`packages: write`, only
`docker load` and `docker push`) and release (`contents: write`, only `gh release create`).

## How servers and policies work

Servers, the scope mapping and the emergency overrides are rows in PostgreSQL, changed through the admin API
(`/admin/v1/servers`, `/admin/v1/policy/*`). With several instances they share Redis, PostgreSQL, the internal JWT key file and the
cursor keys; a change reaches the other instances within `MCP_CHANGE_POLL_INTERVAL` (1 s).

- Adding a server (`POST /admin/v1/servers`): the gateway refuses loopback, link-local, unspecified and multicast addresses (every
  address a name resolves to, and again before every connection), reads the certificate with a handshake that sends no client
  certificate, pulls `GET /.well-known/mcp-manifest` and derives the `serverId` (`mcp-<system>`). The connection, the policies
  and every tool start pending. A tool is listed and callable only when all three are approved.
- Trust of a connection: `ca` (chain to the JVM store or `MCP_SERVER_TRUSTED_CAS`, certificate names the host), `pinned` (the exact
  certificate by SHA-256) or `plain` (`http`, only with `allowPlainHttp`).
- The gateway pulls the manifest at least every 60 s; a changed definition or policies hash makes the entry pending again. It
  pushes the policy data to `POST /.well-known/mcp-policy-data` after each change and at least every 60 s. A server that answers
  `409 policy_data_stale` to a tool call gets a push and the call once more with a new token.
- Every internal JWT carries `use`: `call` or `policy-data`; a server refuses a token of another purpose.
- Decisions on `call` use the platform policies of `mcp-contracts` (the group `mcp-<system>-read`, `-write` or `-destructive`, and
  the scopes a write names) and the overrides of the administrator.

## Invariants to keep

- The AI client is untrusted. Policy is checked on every call; the filter in the `/mcp` address only narrows the tool list.
- The identity provider token never reaches a target system. The server gets a new ES256 JWT (30 s) with headers built from scratch.
- Fail closed: no policy data, an unreachable broker, an unreadable kill switch state or an unknown tool means refusal.
- A tool that does not exist and one the user may not use get the same answer, `not_found_or_denied`.
- A tool definition is pinned by hash; a different one hides the tool (`definition_changed`).
- `DESTRUCTIVE` actions need a one-time TOTP confirmation bound to user, tool and arguments.
- Secret values do not reach logs or audit events; audit records `argsLength`, not argument values.
- The admin API is on the internal port only and needs a client certificate with an allowed CN and a token with
  `aud=mcp-gateway-admin`.

## Source layout

Packages under `pl.aiwcorpo.mcp.gateway`: `admin`, `auth`, `authz`, `policy`, `confirm`, `activity`, `registry`, `killswitch`,
`stream`, `edge`, `audit`, `broker`, `config`, `jwt`, `link` (manifest pull and policy data push), `mcp`, `net` (address rules),
`server`, `tls`, `upstream`.

## License

Contributions are licensed under Apache-2.0 (see `LICENSE`).
