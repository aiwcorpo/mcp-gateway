# Security policy

## Reporting a vulnerability

Do not open a public issue for a vulnerability. Use the private vulnerability reporting of the repository (the
"Security" tab, "Report a vulnerability"). Include the commit or image tag, the route or operation involved (an MCP
endpoint or an operation of the C5 admin API) and a request that shows the problem. Do not attach real secrets or tokens.

This repository has no bug bounty.

## What counts

- A tool call that reaches a server, or a tool that is listed, for a user whom the policy does not allow, or past an
  emergency switch, or past the filter of the address (the filter may only narrow).
- A response, log or audit line that carries the value of a credential, a token of the IdP, a confirmation code or a
  header the client sent (`Authorization`, `X-MCP-*`, `X-PAT-*`).
- A different answer for "does not exist" and "not allowed" where the contract wants `not_found_or_denied`.
- A session, a stream, a cursor or a pending confirmation of one user that another user can use.
- A caller without the right client certificate name that gets through on the admin port, or a manifest that an
  adapter or a pipeline of another server can store.
- A request that makes the gateway call a server without a credential or without the checks after Redis, the database,
  the broker or the policy store failed (the gateway is meant to fail closed), or an emergency switch that does not
  hold on every instance within 5 seconds.

## Not in scope

The published test keys of `mcp-contracts` are refused unless the development profile and its acknowledgement are set;
findings that need them enabled in production are configuration errors. The credentials of the development stack
(the local dev stack) and the test server and stand-in broker of this repository are not production material.

## Supported versions

The `main` branch and the latest tagged image.
