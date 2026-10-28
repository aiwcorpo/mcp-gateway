#!/usr/bin/env bash
# Runs the gateway on the host against mcp-platform-dev started with `make up` (Keycloak, Redis, PostgreSQL,
# certificates). Ports of the M2 wave: public MCP endpoint http://localhost:18700 (/s/<serverId>/mcp,
# /v/<slug>/mcp, /.well-known/oauth-protected-resource*), internal TLS endpoint https://localhost:18701 (JWKS of
# C2, actuator, C5 admin API with mTLS). The public URL is configuration (MCP_PUBLIC_URL), not the Host header.
# Secrets are read from the environment's .secrets/dev.env at start, never copied into this repository.
# Broker and MCP server: MCP_BROKER_URL (default https://localhost:18703, scripts/run-test-broker-host.sh) and
# MCP_SERVER_JIRA_MCP_URL (default https://localhost:18702/mcp, scripts/run-test-server-host.sh).
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
dev="${MCP_PLATFORM_DEV:-$here/../mcp-platform-dev}"
jar="$here/gateway/target/mcp-gateway.jar"

[[ -f "$dev/.secrets/dev.env" ]] || { echo "no $dev/.secrets/dev.env: run make up in mcp-platform-dev" >&2; exit 1; }
[[ -f "$jar" ]] || { echo "no $jar: run ./mvnw -B install first" >&2; exit 1; }

set -a
# shellcheck disable=SC1091
. "$dev/.secrets/dev.env"
set +a

export MCP_GATEWAY_PORT="${MCP_GATEWAY_PORT:-18700}"
export MCP_INTERNAL_PORT="${MCP_INTERNAL_PORT:-18701}"
export MCP_PUBLIC_URL="${MCP_PUBLIC_URL:-http://localhost:$MCP_GATEWAY_PORT}"
export MCP_OIDC_ISSUER=http://localhost:18080/realms/corp
export MCP_OIDC_JWKS_URI=http://localhost:18080/realms/corp/protocol/openid-connect/certs
export MCP_OIDC_TOKEN_URI=http://localhost:18080/realms/corp/protocol/openid-connect/token
export MCP_OIDC_CLIENT_ID=mcp-gateway
export MCP_OIDC_CLIENT_SECRET="$KC_CLIENT_MCP_GATEWAY_SECRET"
# Keycloak of the dev stack speaks plain http (token exchange only).
export MCP_ALLOW_PLAIN_HTTP=true
export MCP_BROKER_URL="${MCP_BROKER_URL:-https://localhost:18703}"
export MCP_BROKER_TLS_NAME="${MCP_BROKER_TLS_NAME:-mcp-credential-broker.internal}"
export MCP_SERVER_JIRA_MCP_URL="${MCP_SERVER_JIRA_MCP_URL:-https://localhost:18702/mcp}"
export MCP_REDIS_HOST=localhost MCP_REDIS_PORT=16379 MCP_REDIS_USER=gateway MCP_REDIS_PASSWORD="$REDIS_GATEWAY_PASSWORD"
export MCP_DB_URL=jdbc:postgresql://localhost:15432/gateway MCP_DB_USER=gateway MCP_DB_PASSWORD="$GATEWAY_DB_PASSWORD"
export MCP_TLS_KEYSTORE="$dev/certs/mcp-gateway/keystore.p12"
export MCP_TLS_TRUSTSTORE="$dev/certs/ca/truststore.p12"
export MCP_TLS_STORE_PASSWORD="$TLS_STORE_PASSWORD"

exec "${JAVA_HOME:+$JAVA_HOME/bin/}java" -jar "$jar"
