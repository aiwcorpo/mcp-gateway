#!/usr/bin/env bash
# Runs the test broker (a stand-in for the C4 resolve of the credential broker, not the broker) on the host:
# https://localhost:18703 with the broker certificate of the dev stack and the JWKS of the gateway started by
# run-dev-host.sh. Users in BROKER_PATS ("alice=alice-pat,bob=bob-pat") get that PAT as a user-secret credential,
# everybody else gets 409 credential_required with a link to the portal on the public origin.
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
dev="${MCP_PLATFORM_DEV:-$here/../mcp-platform-dev}"
jar="$here/test-server/target/mcp-gateway-test-server-exec.jar"

[[ -f "$jar" ]] || { echo "no $jar: run ./mvnw -B install first" >&2; exit 1; }
TLS_STORE_PASSWORD="$(grep '^TLS_STORE_PASSWORD=' "$dev/.secrets/dev.env" | cut -d= -f2-)"

export MCP_PORT="${MCP_PORT:-18703}"
export MCP_TLS_KEYSTORE="$dev/certs/mcp-credential-broker/keystore.p12"
export MCP_TLS_TRUSTSTORE="$dev/certs/ca/truststore.p12"
export MCP_TLS_STORE_PASSWORD="$TLS_STORE_PASSWORD"
export MCP_GATEWAY_JWKS_URI="${MCP_GATEWAY_JWKS_URI:-https://localhost:18701/.well-known/jwks.json}"
export MCP_PORTAL_CONNECT_URL="${MCP_PORTAL_CONNECT_URL:-http://localhost:18700/connections?system=jira}"
export MCP_TEST_BROKER_PATS="${BROKER_PATS:-alice=alice-pat}"

exec "${JAVA_HOME:+$JAVA_HOME/bin/}java" -Dloader.main=pl.aiwcorpo.mcp.testserver.TestBrokerMain \
  -cp "$jar" org.springframework.boot.loader.launch.PropertiesLauncher
