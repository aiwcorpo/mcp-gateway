# mcp-gateway

The single entry point for AI clients on the MCP platform. The gateway authenticates the user with the identity
provider token, fetches the user's credential for the target system from the credential broker, issues a short-lived
internal JWT and forwards the call to the MCP server over mutual TLS. Every tool call produces audit events that share one
`requestId`.

It is a deployable component (container image `mcp-gateway`), not a library. The intended readers are platform operators.
Installation and day-to-day operation of the whole platform are described in
[mcp-docs](https://github.com/aiwcorpo/mcp-docs), starting from `docs/operator/index.md`.

Contracts: `mcp-contracts` 6.3.2. What works, what is missing and the known deviations: [STATUS.md](STATUS.md) (in Polish).
License: Apache-2.0 ([LICENSE](LICENSE), [NOTICE](NOTICE)). Changes: [CHANGELOG.md](CHANGELOG.md). Contributing:
[CONTRIBUTING.md](CONTRIBUTING.md). Reporting vulnerabilities: [SECURITY.md](SECURITY.md).

## What it needs

PostgreSQL (registry, kill switches, activity; Flyway creates the schema at start), Redis with a `gateway` account
(sessions, confirmations, rate limits; `noeviction`, `appendonly yes`), an OIDC identity provider (Keycloak or Entra),
`mcp-credential-broker`, a policy server with signed bundles (`mcp-policies`) and MCP servers reachable over mTLS with
certificates from one internal CA. `mcp-platform-dev` gives a single-machine stack for trying it out, not for production.

Ports: `8080` for MCP clients (public) and `8443` for TLS with the gateway certificate (internal JWKS, `/actuator/health`,
`/actuator/prometheus`, `/admin/v1/*`). The internal port does not serve MCP paths and the public one serves neither JWKS nor
actuator.

## Build and test

JDK 25 and Docker are required (Testcontainers starts Redis with an ACL and PostgreSQL 18.6). On Windows use WSL2.

```bash
./mvnw -B install                                    # tests and jars of both modules
docker build -t mcp-gateway:dev .
make ci                                              # ci/run.sh verify: text checks, mvnw clean verify, zero-test guard
```

Modules: `gateway` (Spring Boot 4.1.0, Java 25) and `test-server` (a minimal MCP server plus a broker stub for tests and demos;
not a product). Load tests live in `mcp-load-tests`.

`ci/run.sh` has the steps `verify`, `hygiene` and `image` (image `mcp-gateway:<MCP_IMAGE_STAGE>-<sha>`, built from a clean tree).
An unknown or empty step exits with 2. On a clean runner the `mcp-contracts` artifacts come from the registry set in
`MCP_MAVEN_REPOSITORY_URL`, `MCP_MAVEN_REPOSITORY_USER` and `MCP_MAVEN_REPOSITORY_PASSWORD` (see `.ci/settings.xml`).
The GitLab, Jenkins and GitHub files only call this script; write access and the Docker socket are granted by the CI system,
not by files in a branch. The release workflow (`release.yml`) has three jobs: build (read-only), publish (`packages: write`,
only `docker load` and `docker push`) and release (`contents: write`, only `gh release create`).

## Configuration

All settings are environment variables read from `gateway/src/main/resources/application.yml`. The generated table of
variables, defaults and which ones are mandatory is in mcp-docs: `docs/reference/env-gateway.md`. Do not copy it here.

The shortest set that is needed to start outside the dev profile:

- `MCP_PUBLIC_URL`: the public origin. It is the only source of `resource_metadata`, RFC 9728 `resource` and `connectUrl`;
  the `Host` and `X-Forwarded-*` headers are ignored.
- `MCP_OIDC_ISSUER`, `MCP_OIDC_JWKS_URI`: issuer and keys of the identity provider.
- `MCP_DB_URL`, `MCP_DB_USER`, `MCP_DB_PASSWORD`; `MCP_REDIS_HOST`, `MCP_REDIS_USER`, `MCP_REDIS_PASSWORD`.
- `MCP_TLS_KEYSTORE`, `MCP_TLS_TRUSTSTORE`, `MCP_TLS_STORE_PASSWORD`: the gateway certificate (CN `mcp-gateway`) and the internal CA.
- `MCP_BROKER_URL`, `MCP_BROKER_TLS_NAME`.
- `MCP_POLICY_MAIN_URL`, `MCP_POLICY_MAIN_KEY_ID`, `MCP_POLICY_MAIN_KEY_FILE`, `MCP_POLICY_STATE_DIR` (one state directory per instance).
- `MCP_INTERNAL_JWT_KEYS_FILE`, `MCP_INTERNAL_JWT_ACTIVE_KID`, `MCP_LIST_CURSOR_KEY`, `MCP_ACTIVITY_CURSOR_KEY`: shared by all instances.
- `MCP_SERVER_<SYSTEM>_MCP_URL` and, for a foreign server behind the adapter, `MCP_SERVER_<SYSTEM>_ADAPTER=true`.

With two or more instances, share Redis, PostgreSQL, the C2 key file and the cursor keys. Registry and kill switch changes reach the
other instances within a second (`MCP_CHANGE_POLL_INTERVAL`).

Optional TLS on the public port: `MCP_PUBLIC_TLS_ENABLED=true` with `MCP_PUBLIC_TLS_CERTIFICATE` and `MCP_PUBLIC_TLS_PRIVATE_KEY` (PEM, PKCS#8).
Start is refused when either is missing or unreadable. The proxy in front should verify this certificate against the internal CA.

Upgrades, rolling updates, rollback notes and the kill switch procedure are in `docs/operator/upgrades.md` and the other pages of the operator guide.

### Development profile

Relaxations meant only for a dev stack (`test-*` signing keys, plain http, a static tool registry, manifest bootstrap, an empty
policy state directory) work only when the profile is exactly `devstack` and two acknowledgements are set: the property
`aiwcorpo.mcp.platform.devstack.acknowledged=true` and the process environment variable `MCP_DEVSTACK_ACKNOWLEDGED=true`.
Otherwise the gateway refuses to start. A start with the profile logs `event=devstack_profile` at WARN and sets the gauge
`mcp_gateway_devstack_active` to 1. Details: `docs/operator/dev-profile.md`.

## Security

Invariants of this component. The platform-wide list is in `docs/security/invariants.md`.

- The AI client is untrusted. Policy is checked on every call; the filter in the `/mcp` address only narrows the tool list.
- The IdP token is never passed to a target system. The gateway swaps it for a credential from the broker and sends the server a new
  ES256 JWT (30 s lifetime) with headers built from scratch; no client header is copied.
- Fail closed: no policy, an unreachable broker, an unreadable kill switch state or an unknown tool means refusal.
- A tool that does not exist and one the user may not use get the same answer, `not_found_or_denied`.
- A tool definition is pinned by hash. If the server serves a different one, the tool is hidden (`definition_changed`).
- `DESTRUCTIVE` actions need a one-time TOTP confirmation bound to user, tool and arguments.
- Secret values do not reach logs or audit events; audit records only `argsLength`, not argument values.
- Policy bundles are verified (Ed25519) and a lower revision is refused, also after a restart.
- Keys published for tests are refused outside the dev profile.
- The admin API (`/admin/v1/*`) is on the internal port only and needs a client certificate with an allowed CN plus a token with `aud=mcp-gateway-admin`.
- Rejected tokens are audited without a rate limit, so limit their number at the edge (for example nginx `limit_req` per address).

## Source layout

Packages under `pl.aiwcorpo.mcp.gateway`: `admin`, `auth`, `authz`, `policy`, `confirm`, `activity`, `registry`, `killswitch`,
`stream`, `edge`, `audit`, `broker`, `config`, `jwt`, `mcp`, `server`, `tls`, `upstream`.
