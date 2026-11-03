# Changelog

The gateway ships as a container image (`mcp-gateway`); the version in `pom.xml` follows SemVer and the image tag
names the milestone and the commit (`m6-<short sha>`).

## Unreleased

Moves to `mcp-contracts` 6.2.0. Behaviour that clients and other components see changes as follows.

- `listChanged: true` on `/mcp` and `/s/<serverId>/mcp` for both protocols. `GET` with a session and
  `Accept: text/event-stream` opens a stream; `POST subscriptions/listen` is the stateless one. The reference of the
  comparison is the list of the user when the stream was opened; at most one `notifications/tools/list_changed` per
  second and session; heartbeat `: keepalive` every 15 s (`MCP_SSE_HEARTBEAT_INTERVAL`); streams are outside
  `MCP_MAX_CONCURRENT_REQUESTS` and counted by `mcp_gateway_open_streams`. `GET` without a session is `405` with
  `Allow: POST, DELETE, GET`.
- Emergency switch of a server or a tool: table `kill_switches`, five C5 operations, checked after authorization and
  the filter, cache of at most 5 s, fail-closed, `disabledBy` in the catalog, audit reasons `kill_switch`,
  `kill_switch_set` and `kill_switch_cleared`.
- Servers behind an adapter (`gateway.servers.<id>.adapter`): `PUT /admin/v1/registry/adapters/{serverId}`
  (certificate `mcp-adapter-<serverId>`), `source: adapter`, classification (`risk`, `action`) by an administrator
  when approving, `classification_required`, `classification_not_allowed`, `classification_inconsistent`,
  `adapter_mode_mismatch`; the hash of an adapter entry does not cover `risk` and `action`.
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
