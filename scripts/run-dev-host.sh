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
export MCP_OIDC_ISSUER="${MCP_OIDC_ISSUER:-https://localhost:18746/realms/corp}"
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
# A process on the host has its own schema in the stack's database: it must not write into the tables of the gateway
# container (registry rows, links, activity of the compose stack). Flyway creates the schema.
db_schema="${MCP_DB_SCHEMA:-host_gateway}"
export MCP_DB_URL="jdbc:postgresql://localhost:15432/gateway?currentSchema=$db_schema" MCP_DB_USER=gateway MCP_DB_PASSWORD="$GATEWAY_DB_PASSWORD"
export SPRING_FLYWAY_SCHEMAS="$db_schema" SPRING_FLYWAY_CREATE_SCHEMAS=true
export MCP_TLS_KEYSTORE="$dev/certs/mcp-gateway/keystore.p12"
export MCP_TLS_TRUSTSTORE="$dev/certs/ca/truststore.p12"
export MCP_TLS_STORE_PASSWORD="$TLS_STORE_PASSWORD"
# Signed policy bundles (ws-09): the bundle server of the dev stack (POLICIES_PORT, 18747) and the dev public keys of
# mcp-policies. The gateway does not start without a main bundle.
policies="${MCP_POLICIES_REPO:-$here/../mcp-policies}"
export MCP_POLICY_MAIN_URL="${MCP_POLICY_MAIN_URL:-http://127.0.0.1:18747/policies/main/}"
export MCP_POLICY_OVERRIDES_URL="${MCP_POLICY_OVERRIDES_URL:-http://127.0.0.1:18747/policies/overrides/}"
export MCP_POLICY_MAIN_KEY_ID=test-policies-main-dev
export MCP_POLICY_MAIN_KEY_FILE="$policies/keys/dev/test-policies-main-dev.public.pem"
export MCP_POLICY_OVERRIDES_KEY_ID=test-policies-overrides-dev
export MCP_POLICY_OVERRIDES_KEY_FILE="$policies/keys/dev/test-policies-overrides-dev.public.pem"
export MCP_POLICY_ALLOW_TEST_KEYS=true
# The relaxations of a development stack (test keys, http, bootstrap of manifests) need the devstack profile, acknowledged twice.
export SPRING_PROFILES_ACTIVE=devstack MCP_DEVSTACK_ACKNOWLEDGED=true AIWCORPO_MCP_PLATFORM_DEVSTACK_ACKNOWLEDGED=true
export MCP_REGISTRY_BOOTSTRAP="${MCP_REGISTRY_BOOTSTRAP:-true}"
export MCP_POLICY_STATE_DIR="${MCP_POLICY_STATE_DIR:-$here/gateway/target/policy-state}"
mkdir -p "$MCP_POLICY_STATE_DIR"

exec "${JAVA_HOME:+$JAVA_HOME/bin/}java" -jar "$jar"
