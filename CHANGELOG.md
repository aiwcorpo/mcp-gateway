# Changelog

The gateway ships as a container image (`mcp-gateway`); the version in `pom.xml` follows SemVer and the image tag
names the milestone and the commit (`m6-<short sha>`).

## Unreleased

Moves to `mcp-contracts` 6.3.2. Behaviour that clients and other components see changes as follows.

- Optional TLS on the public port: `MCP_PUBLIC_TLS_ENABLED` (default `false`), `MCP_PUBLIC_TLS_CERTIFICATE` and
  `MCP_PUBLIC_TLS_PRIVATE_KEY` (PEM files), `MCP_PUBLIC_TLS_PRIVATE_KEY_PASSWORD` for an encrypted key. TLS 1.3 and 1.2, JDK
  default ciphers. The start is refused without a readable certificate and key; a key readable by "others" is allowed only in the
  `devstack` profile. The internal port is unchanged. Off by default, so existing deployments need no change.
- `listChanged: true` on `/mcp` and `/s/<serverId>/mcp` for both protocols. `GET` with a session and
  `Accept: text/event-stream` opens a stream; `POST subscriptions/listen` is the stateless one. The reference of the
  comparison is the list of the user when the stream was opened; at most one `notifications/tools/list_changed` per
  second and session; heartbeat `: keepalive` every 15 s (`MCP_SSE_HEARTBEAT_INTERVAL`); streams are outside
  `MCP_MAX_CONCURRENT_REQUESTS`, counted by `mcp_gateway_open_streams` and limited per instance by `MCP_MAX_OPEN_STREAMS`
  (default 2000, 503 over it); opening one counts for the request limits of the user; lists are recomputed after a burst
  of changes once per stream, a few at a time (`MCP_STREAM_RECOMPUTE_PARALLELISM`). `GET` without a session is `405` with
  `Allow: POST, DELETE, GET`.
- Emergency switch of a server or a tool: table `kill_switches`, five C5 operations, checked after authorization and
  the filter, cache of at most 5 s, fail-closed, `disabledBy` in the catalog, audit reasons `kill_switch`,
  `kill_switch_set` and `kill_switch_cleared`.
- Servers behind an adapter (`gateway.servers.<id>.adapter`): `PUT /admin/v1/registry/adapters/{serverId}`
  (certificate `mcp-adapter-<serverId>`), `source: adapter`, classification (`risk`, `action`) by an administrator
  when approving, `classification_required`, `classification_not_allowed`, `classification_inconsistent`,
  `adapter_mode_mismatch`; the hash of an adapter entry does not cover `risk` and `action`.
- Streams compute the list of an identity once and keep its Cedar decisions until the policies change; they use slots of their
  own, apart from `tools/list`. A tool of an adapter that leaves the manifest loses its classification but not the floor of
  the risk. `/s/<serverId>/mcp` streams compare the tools of that system only.
- Tools of an adapter are read only (CC-227): `approve` takes `READ_ONLY` with `read` and refuses `UPDATE`, `DESTRUCTIVE` and
  `admin` (`classification_not_allowed`). Migration V10 voids stored `UPDATE` and `DESTRUCTIVE` classifications of adapter
  tools: the entry is `pending_approval` again and the voided classification stays the floor of the risk, so approving it
  as `READ_ONLY` needs `acceptRiskLowering`.
- The internal JWT of a call to a server in adapter mode carries `mcp_risk` and `mcp_action` (a pair that fits, with `tool`),
  for the sidecar of the adapter only (CC-226).
- `GET /admin/v1/catalog` is `503` with `Retry-After` when the emergency switches cannot be read (CC-224), `cursor: null` is
  `-32602` (CC-225), `list_changed` after a change of the policies has no 5 s promise (CC-228).
- A forbid at the level of the tool is audited as `policy_forbid` (the client still gets `not_found_or_denied`).
- Summaries of the audit throttle carry `suppressedTargets`.
- `503` has `Retry-After`: 2 s when the gateway is busy, 10 s when the store of the sessions does not answer.
- `tools/list` with `cursor: ""` is `-32602`.
- Claims of the IdP token that nobody reads (`vs`, `vsc`, unknown ones) are ignored and never copied into the internal JWT.
- The gateway does not send a `tools/call` of an `UPDATE` or `DESTRUCTIVE` tool again on a new session when the
  server lost the old one.
- The decisions of Cedar for the tools of one server run side by side, once per tool: 253 tools list in 162 ms
  instead of 883 ms on 12 cores.
- Housekeeping for the public release: Apache-2.0 (LICENSE, NOTICE, license in `pom.xml`), SECURITY.md,
  CONTRIBUTING.md, SBOM profile `release`, release workflow for ghcr.io (not run), `distributionManagement` for
  GitHub Packages, portable build instructions, image tag prefix `m6-`.
