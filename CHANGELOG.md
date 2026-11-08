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
  also reads its manifest: other policies than the approved ones put the server back in `pending_approval` (source `server`). The
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
- **Policy data is pushed** to every server (`POST /.well-known/mcp-policy-data`, purpose `policy-data`, CC-249): the revision, the scope mapping
  reduced to the namespace of the server, the allowed clients, the overrides for that server and for all servers and the policies hash approved
  for it; after every change of the revision and at least every 60 s. A tool call answered `409 policy_data_stale` gets a push and one
  repetition with a new token.
- **A server is added by its address** (`createServer`, CC-249, contracts 7.0.0): the gateway checks the address (loopback, link-local,
  unspecified, multicast and broadcast refused for every resolved address and again at every connection; the metadata addresses 169.254.169.254,
  fd00:ec2::254, 100.100.100.200 and 192.0.0.192 too, in their embedded IPv6 forms as well, and whatever `MCP_SERVER_REFUSED_ADDRESSES` lists;
  the address is judged again right before each connection; TLS protects `ca` and `pinned` servers against DNS rebinding and `plain` accepts
  the remaining window), reads the certificate with a handshake
  that sends no client certificate, pulls `GET /.well-known/mcp-manifest` and takes `serverId` = `mcp-<system>` from it. The server starts
  `pending_approval` with everything pending, the `READ_ONLY` tools included; a pulled manifest approves nothing. The trust is chosen per server by
  `POST /admin/v1/servers/{serverId}/connection/approve` (fresh MFA): `ca` (default JVM trust store plus `MCP_SERVER_TRUSTED_CAS`, standard
  host name check), `pinned` (SHA-256 of the DER of one certificate) or `plain` (`http` with `allowPlainHttp`). `adapter` is derived from
  `source: adapter` of the first manifest and never changes. `POST .../refresh` (no MFA, one per 5 s per server, `429 refresh_too_frequent`).
  The gateway pulls the manifest again at least every 60 s: a changed hash is pending and the tools wait; a pinned server that presents another
  certificate is `certificate_changed` with the new fingerprint as `pendingConnection`; a `ca` renewal needs nothing. Flyway `V14` adds the
  connection to `servers` and renames the source `ci` to `manifest`.
- **Internal JWT purpose** (`use`): `call` for the MCP endpoint of a server and for the broker, `policy-data` for the push of policy data. The manifest is
  pulled without a token (add, refresh and the runtime loop): a server serves it openly, so there is no `use: manifest` and no `mcp-pending` audience. The public key set is served at `/.well-known/mcp-jwks.json` on the public port (servers fetch their keys from it).
- **Removed:** `PUT /admin/v1/registry/servers/{serverId}` and the certificate `mcp-registry-ci-<serverId>`, `PUT
  /admin/v1/registry/adapters/{serverId}` and `mcp-adapter-<serverId>`, `GET /internal/v1/policy-data` and its client certificate check, the
  pinning of the CN and SAN `<serverId>.internal` of a server (the broker keeps its pinned name), the `internalUrl` of `PATCH`, the automatic
  approval of `READ_ONLY` tools by a registration, and the `definition_registered` event.
- **Fresh MFA:** `approveServerPolicies`, `putScopeMapping`, `deleteOverride`, `createServer`, `deleteServer` and every `updateServer` except a
  body that only sets `enabled: false` need `auth_time` within 300 s and proof of a second factor in the token (an `amr` of `mfa`, `otp`, `hwk`
  or `totp`, or an `acr` listed in `MCP_ADMIN_MFA_ACR_VALUES`; `MCP_ADMIN_MFA_AMR_VALUES`); otherwise `401 step_up_required`, audited.
- **Namespaces** are claimed by the approval of policies, not by a registration; an approval that changes or frees one removes the grants of
  the freed namespace from the scope mapping (audited per entry). Risk floors survive `DELETE /admin/v1/servers/{serverId}`; rows a removal
  leaves behind are purged when the id is added again (rows of 1.x are taken again, once).
- **Allowed clients** are policy data in the database: `MCP_ALLOWED_CLIENTS` only seeds them, once, and a different value is logged; every
  instance enforces and serves the same list. The revision is `max(previous + 1, clock in ms)` and the policy state is read in one
  repeatable-read transaction.
- A running server whose `/mcp-manifest` could not be verified for `MCP_REGISTRY_POLICY_CHECK_FAILURES` (3) checks in a row, or for
  `MCP_REGISTRY_POLICY_CHECK_MAX_AGE` (5m), has its tools blocked (`policies_unverified`, audited) until a check finds it intact.
- Audit: override events carry `overrideId`, `overrideTarget` and `textSha256` (`textSha256Before`), `server_updated` the `changedFields`, the
  removal of a server one event for each tool, switch, policy, namespace, override and mapping entry (with its `group`); `policies_approved`
  is written before the data is read back. Overrides that an approval makes invalid are in the audit only (the answer has no place for them).
- Admin API input rules (CC-243, CC-244): a malformed `If-Match` or `If-None-Match` and a path identifier that does not fit its pattern are
  `400 invalid_request`, never `404`; replacing an override needs a fresh MFA (creating one does not); `GET
  /admin/v1/registry/servers/{serverId}/policies` returns the approved policies and declarations (null when nothing is approved); an override
  cannot target a reserved id such as `mcp-gateway`. A tool may name an `additionalGroup` in its manifest entry (CC-242): callers need it next
  to the group of the risk, and a change of it waits for approval with the definition. A registration that removes or changes the `additionalGroup` of a registered tool holds the entry for an administrator whatever its risk (it would widen access); adding one follows the normal rule (CC-245). The group is a floor (`registry_group_floor`, `V13`) like the risk floor: it outlives the tool and the server, so removing the tool and registering it again without the group, or deleting and adding the server, waits as well; an approval by an administrator updates it (CC-246).
- `deploy/`: no `gateway-state` volume or `/app/state` mount (nothing uses it); the systemd `StateDirectory` stays, it holds the generated secrets.
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
   `POST /admin/v1/servers` (or in the portal) with the address and the credential
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
5. Server certificates: each MCP server needs CN `<serverId>` and SAN `<serverId>.internal`, with `serverAuth` and `clientAuth`.
6. The portal token for the gateway must carry `auth_time` and `amr` (or an `acr` you list); without them the operations above are refused.
7. `prv` in the internal JWT and `policyRevision` in the audit events are integers now; a server on starter 3.x does not understand them.

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
