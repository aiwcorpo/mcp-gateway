#!/usr/bin/env bash
# Runs the test MCP server (in place of mcp-jira) on the host: https://localhost:18702/mcp with the mcp-jira
# certificate of the dev stack, the gateway JWKS from run-dev-host.sh and the Jira mock. Not a product.
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
dev="${MCP_PLATFORM_DEV:-$here/../mcp-platform-dev}"
jar="$here/test-server/target/mcp-gateway-test-server-exec.jar"

[[ -f "$jar" ]] || { echo "no $jar: run ./mvnw -B install first" >&2; exit 1; }
TLS_STORE_PASSWORD="$(grep '^TLS_STORE_PASSWORD=' "$dev/.secrets/dev.env" | cut -d= -f2-)"

export MCP_PORT="${MCP_PORT:-18702}"
export MCP_TLS_KEYSTORE="$dev/certs/mcp-jira/keystore.p12"
export MCP_TLS_TRUSTSTORE="$dev/certs/ca/truststore.p12"
export MCP_TLS_STORE_PASSWORD="$TLS_STORE_PASSWORD"
export MCP_GATEWAY_JWKS_URI="${MCP_GATEWAY_JWKS_URI:-https://localhost:18701/.well-known/jwks.json}"
export MCP_GATEWAY_TLS_NAME="${MCP_GATEWAY_TLS_NAME:-localhost}"
export MCP_JIRA_URL="${MCP_JIRA_URL:-http://localhost:18081}"

exec "${JAVA_HOME:+$JAVA_HOME/bin/}java" -jar "$jar"
