# Contributing

Changes go through a pull request. Read the README sections "Build and test" first.

- Run `./mvnw -B verify` before pushing. It needs JDK 25 and a container runtime for the integration tests
  (Testcontainers); on Windows use WSL2.
- Behaviour that a client or another component sees follows `mcp-contracts` (`openapi/gateway-admin.v1.yaml`,
  `schemas/`, `test-vectors/`). A change of an operation, a status code, an audit reason or a vector is made there first
  (`CONTRACT_CHANGES.md`); here you bump `mcp-contracts.version` and follow it. The vector tests must pass.
- Do not put secret values, tokens or confirmation codes in logs, audit events or error bodies; the tests check this.
- Commits: English subject up to 72 characters in the imperative mood, a body that describes the change.
- Never commit key material, `.env` files or the output of a build.
