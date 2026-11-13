# AGENTS.md

mcp-gateway is the single entry point for AI clients of [MCP Platform](https://github.com/aiwcorpo/mcp-platform): it
validates the identity provider token, gets the user's credential from the credential broker, checks policy and forwards the
call to an MCP server with a fresh internal JWT. The portal calls its admin API. Its interfaces are governed by
`mcp-contracts` (`openapi/gateway-admin.v1.yaml`, `schemas/`, `test-vectors/`); the version is `mcp-contracts.version` in
`pom.xml`. Code-level detail: [CONTRIBUTING.md](CONTRIBUTING.md).

## Commands

Java 25 and Docker are required. Maven fails with "release version 25 not supported" under an older JDK, so point
`JAVA_HOME` at a JDK 25 first (macOS with Homebrew: `export JAVA_HOME=$(brew --prefix openjdk@25)`).

```bash
./mvnw -B verify                              # all tests + target/mcp-gateway.jar; what CI runs
./mvnw -B test -Dtest=KillSwitchesTest        # one test class
./mvnw -B test -Dtest='KillSwitchesTest#aSwitchOfAToolAndOfAServer'
./mvnw -B -DskipTests verify                  # compile and package only (the Jenkins change-request job)
docker build -t mcp-gateway:dev .             # after verify; the image copies target/mcp-gateway.jar
```

The full `verify` runs about 1340 tests and starts PostgreSQL and Redis with Testcontainers; it takes about 7 minutes on a laptop.
There is no separate lint or formatter step. Running the gateway locally against test stand-ins: CONTRIBUTING.md,
"Running locally".

## Layout

- `src/main/resources/db/migration/`: Flyway migrations, append-only. `V16` is the latest; add `V17__<what>.sql` and never
  edit, rename or delete a migration that exists on main.
- `src/test/java/pl/aiwcorpo/mcp/testserver/`: a minimal MCP server and a broker stub that the integration tests start. Test
  code, not a product.
- `src/test/java/pl/aiwcorpo/mcp/gateway/support/`: shared test infrastructure (`Vectors` reads the mcp-contracts
  `test-vectors` jar from the classpath, `TestIdp`, `TestPki`, `BrokerStub`). `*VectorsTest` classes run contract vectors.
- `deploy/`: the standalone Compose bundle shipped with each release; `gateway.env` there is a template with empty values.

## Rules

- Contract first. A change to an admin operation, a status code, an error or audit reason or a vector starts in
  `mcp-contracts` as a `CC-<n>` entry in `CONTRACT_CHANGES.md` that a person approves. Here you bump
  `mcp-contracts.version` and follow it; the vector tests must keep passing. Do not edit vectors to match gateway code.
- Every user-visible or operator-visible change gets a line under `## Unreleased` in `CHANGELOG.md`, written for an
  operator: what changes, what to check before upgrading.
- Test method names are full sentences in camelCase that state the behaviour (`aFailedReadIsNotAnExtensionOfTheCopy`).
- Keep the invariants listed in CONTRIBUTING.md ("Invariants to keep"). In short: fail closed (no policy data, an
  unreachable broker, an unreadable kill switch state or an unknown tool is a refusal); an unknown tool and a forbidden one
  both answer `not_found_or_denied`; the identity provider token never reaches a server; the admin API stays on port 8443.
- Never put secret values, tokens, TOTP codes or tool argument values in logs, audit events or error bodies; audit records
  `argsLength`. Tests assert this.
- Dev-only relaxations stay behind the `devstack` profile plus both acknowledgements; do not add another way to enable them.
- Base and third-party images are pinned by digest (`Dockerfile`, `deploy/compose.yaml`), GitHub Actions by commit SHA,
  CI images by exact tag. Keep the pins when updating a version.

## Boundaries

Ask a person before: pushing to main, tagging, changing the version in `pom.xml` or `deploy/compose.yaml`, running or
editing the release workflow, publishing an image (images go to `ghcr.io/aiwcorpo` only), or touching a running stack or
a real identity provider, broker or MCP server.

Never commit secrets, tokens, keystores, generated keys, `.env` files, internal host names or IP addresses. Tests use the
test keys and dummy data only. Do not delete the untracked `.claude/` directory in a checkout.

## Pull requests

One change per PR. Commit subject in English, imperative, up to 72 characters; the body says why the change was made
(see `git log`). `./mvnw -B verify` must pass (GitHub job `merge-request` on a PR, `verify` on main). Update `CHANGELOG.md`,
`README.md` or `deploy/README.md` when behaviour or configuration that users see changes. Details: CONTRIBUTING.md.
