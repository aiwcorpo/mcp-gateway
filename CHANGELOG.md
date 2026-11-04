# Changelog

The gateway ships as a container image (`ghcr.io/aiwcorpo/mcp-gateway`); the version in `pom.xml` follows SemVer. Local and
integration builds tag the image `m6-<short sha>`.

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
