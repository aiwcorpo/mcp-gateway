# Changelog

The gateway ships as a container image (`ghcr.io/aiwcorpo/mcp-gateway`); the version in `pom.xml` follows SemVer. Local and
integration builds tag the image `m6-<short sha>`.

## 2.0.0

Built on `mcp-contracts` 7.0.0. Servers, the scope mapping and emergency overrides are runtime data: a new MCP server is added to a running
platform, and removed again, without restarting anything and without a policy repository. Breaking change; read the upgrade notes.

- **Registry of servers in PostgreSQL** (`servers`, Flyway `V11`), the only list of servers. `GET`, `POST /admin/v1/servers` and `GET`,
  `PATCH`, `DELETE /admin/v1/servers/{serverId}` with `ETag` and `If-Match`; reserved system ids (`gateway`, `offboarding`, `portal`, `broker`,
  `prometheus`, `platform`, `admin`, `registry`, `adapter`, `internal`, `ci`) are refused. A change is visible to every instance within
  `MCP_CHANGE_POLL_INTERVAL`. Deleting a server removes its tools (`listChanged` to the clients), manifests, approvals, emergency switches,
  policy fragment and overrides aimed at it, the entries of the scope mapping for the types of its namespace (audited one by one), and frees its
  namespace. Every change is an `admin_change` event.
- **Policies of a server are approved with its tools.** The manifest brings the policy fragment and the resource type declarations;
  `policiesHash` covers both. A new or changed hash waits for `POST /admin/v1/registry/servers/{serverId}/policies/approve`
  (`GET .../policies/pending` shows the difference) and until then the tools of the server are blocked. The definition check of a running server
  also reads its `GET /mcp-manifest`: other policies than the approved ones put the server back in `pending_approval` (source `server`). The
  resource types are the union of the approved declarations only; a namespace belongs to the first server that declared it
  (`namespace_conflict`).
- **Decisions on `call`** use the base schema, the platform policies of the contracts and the overrides aimed at the gateway. `User.scopes`
  comes from the scope mapping (entries that are no longer valid are skipped and audited), `Tool.requiredGroup` from the risk, `context.refs` is
  always present. Data that cannot be used (a namespace in two servers, an override that does not parse, a duplicate policy id) makes every
  decision a deny with an audit event. The AI clients that may call are `MCP_ALLOWED_CLIENTS` (default `claude-code,claude-ai`), checked in code
  before Cedar. Resource identifiers longer than 1024 characters are refused before any pattern is matched.
- **Scope mapping and overrides** (`/admin/v1/policy/scope-mapping`, `/admin/v1/policy/overrides/{id}`) with `If-Match`, validated against the
  approved declarations and against the base schema and the fragment of the target (`gateway`, `all-servers` or a `serverId`). One revision
  (an integer that only rises) is raised by every change of the mapping, the overrides, the allowed clients and the approvals; the internal JWT
  carries it as `prv`.
- **`GET /internal/v1/policy-data`** on the internal port for servers: the certificate must come from the internal CA and its CN must be a
  registered `serverId`; the answer holds the revision, the scope mapping reduced to the namespace of the server, the allowed clients, the
  overrides for that server and for all servers and the policies hash approved for it; `ETag` and `If-None-Match`.
- `InvalidationListener` and the other places that listed systems use the generic pattern of a system id.
- **Removed:** the policy bundles (`mcp-policy-bundle`, `BundleFetcher`, the state directory, `MCP_POLICY_*`), the five static servers and their
  tool lists in `application.yml` (`MCP_SERVER_<SYSTEM>_*`, `MCP_REGISTRY_MODE`), `registry.mode=static`, the tool switches of the configuration.
  The `resource.parent` of a confirmation is no longer derived from an issue key: it knows no system.
- `deploy/`: no policy server or key in `gateway.env`, `compose.yaml` and the systemd file; `init` no longer checks MCP servers (they are
  registry data) and checks `MCP_ALLOWED_CLIENTS`. `deploy/README.md` says how to add and remove a server.
- `deploy/`: installation next to the component. `compose.yaml` with the gateway's own PostgreSQL and Redis (primary and replica),
  one configuration file `gateway.env` and the certificates in `certs/`; `systemd/` for a virtual machine. The release attaches it
  as `mcp-gateway-deploy.tar.gz`, together with the jar.
- `init` (`java -jar mcp-gateway.jar init <dir>`) runs before every start: it generates once what nothing outside the installation
  needs to know (PostgreSQL and Redis passwords, internal JWT keys, cursor keys) and checks the settings, the certificate files and the
  connections to the identity provider and the broker, with the likely cause of each failure.
- One Maven module instead of three; the test MCP server is test code. The image creates `/secrets/*` for the volumes of `init`.

### Upgrade from 1.x

1. Servers: nothing of `MCP_SERVER_<SYSTEM>_*` is read any more and the migration cannot copy it. Before users return, add each server with
   `POST /admin/v1/servers` (or in the portal) with the address, `tlsName` (default `<serverId>.internal`) and the credential
   (`required`, `acceptedTypes`, `type`) that the old configuration had; an adapter server gets `adapter: true`. Manifests and approvals
   stored under the same `serverId` are taken again, but a 1.x manifest has no policies: build the server with the starter 4.0.0, register
   its manifest and approve its policies.
2. The tool lists, titles and risks of the static configuration are gone: tools come from approved manifests only.
3. Policies: stop the policy server for the gateway. Gateway decisions are the platform policies of `mcp-contracts` plus overrides; policies of a
   system live in its server and are approved here. Group names are derived from the risk (`mcp-<system>-read`, `-write`, `-destructive`).
   Resource grants are the scope mapping (`PUT /admin/v1/policy/scope-mapping`), not group names inside a bundle.
4. Delete `MCP_POLICY_*`, `MCP_REGISTRY_MODE`, `MCP_SERVER_*` and `certs/policies-main.public.pem` from your configuration, and the
   volume that held `/app/state`. Set `MCP_ALLOWED_CLIENTS` only if the AI clients are not `claude-code` and `claude-ai` (it was a Cedar
   policy of the bundle). Every instance needs the same value.
5. `prv` in the internal JWT and `policyRevision` in the audit events are integers now; a server on starter 3.x does not understand them.

## 1.0.0

First public release. Built on `mcp-contracts` 6.3.2.

- Single entry point for MCP clients: `/mcp` (all servers the user may see) and `/s/<serverId>/mcp` (one server), over the
  stateful and the stateless protocol. RFC 9728 metadata, `connectUrl` and `resource_metadata` come from `MCP_PUBLIC_URL` only.
- Authenticates the user with the token of an OIDC identity provider (Keycloak or Entra), fetches the user's credential for the
  target system from the credential broker, issues a short-lived internal JWT and forwards the call to the MCP server over
  mutual TLS. Public TLS on the client port is optional (`MCP_PUBLIC_TLS_ENABLED`, off by default).
- Authorizes every tool call with Cedar policies from signed bundles served by `mcp-policies`; rollback of a bundle is refused.
  The tool list a user sees is filtered by the same decisions. Destructive tools need a confirmation with the code of the
  authenticator app.
- Registry of servers and tools (PostgreSQL, Flyway migrations): static configuration, manifests approved by an administrator,
  hashes of definitions, `pending_approval` after a change, and servers behind an adapter whose tools an administrator
  classifies as read only. Admin API under `/admin/v1/*` on the internal port.
- Emergency switch of a server or a tool, checked after authorization, fail-closed, with a cache of at most 5 s.
- `listChanged` notifications on a stream (`GET` with a session, or `POST subscriptions/listen`), at most one per second and
  session, counted by `mcp_gateway_open_streams` and limited by `MCP_MAX_OPEN_STREAMS`.
- Rate and concurrency limits per user and instance; `503` carries `Retry-After`.
- Audit events for every call share one `requestId`; throttled audit summaries list `suppressedTargets`. Prometheus metrics and
  health on the internal port.
- Claims of the IdP token that nobody reads are never copied into the internal JWT.
- Catalog titles of the static registry match the titles the servers report.
- Licensed under Apache-2.0, with SBOM profile `release` and a release workflow for ghcr.io.
