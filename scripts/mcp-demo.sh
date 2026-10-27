#!/usr/bin/env bash
# MCP session through the gateway with a user token, printing what a client sees and each X-Request-Id.
#   TOKEN=$(make -s -C ../mcp-platform-dev token USER=alice) scripts/mcp-demo.sh [gateway-url]
# Legacy flow (2025-11-25: initialize, session, tools/list, tools/call) and the modern flow (2026-07-28).
set -euo pipefail

: "${TOKEN:?set TOKEN to an access token of the claude-code client}"
url="${1:-http://localhost:18000}/s/mcp-jira/mcp"
issue="${ISSUE:-ABC-1}"
headers="$(mktemp)"
trap 'rm -f "$headers"' EXIT

post() {
  curl -sS -D "$headers" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' "$@" "$url"
  echo
  echo "  X-Request-Id: $(grep -i '^x-request-id:' "$headers" | tr -d '\r' | cut -d' ' -f2)"
}

echo "== no token"
curl -sS -o /dev/null -D - -X POST "$url" | grep -iE '^(HTTP|www-authenticate)'

echo "== legacy initialize"
post -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"mcp-demo","version":"1"}}}'
session="$(grep -i '^mcp-session-id:' "$headers" | tr -d '\r' | cut -d' ' -f2)"
post -H "Mcp-Session-Id: $session" -H 'MCP-Protocol-Version: 2025-11-25' -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'

echo "== legacy tools/list"
post -H "Mcp-Session-Id: $session" -H 'MCP-Protocol-Version: 2025-11-25' -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'

echo "== legacy tools/call jira__get_issue $issue (with a forged X-PAT-Jira and X-MCP-Credential)"
post -H "Mcp-Session-Id: $session" -H 'MCP-Protocol-Version: 2025-11-25' -H 'X-PAT-Jira: forged' \
  -H 'X-MCP-Credential: Bearer forged' -H 'X-Request-Id: demo-client-1' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"jira__get_issue\",\"arguments\":{\"issueKey\":\"$issue\"}}}"

echo "== modern tools/call jira__get_issue $issue (2026-07-28, no session)"
post -H 'MCP-Protocol-Version: 2026-07-28' -H 'Mcp-Method: tools/call' -H 'Mcp-Name: jira__get_issue' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"jira__get_issue\",\"arguments\":{\"issueKey\":\"$issue\"},\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{}}}}"

curl -sS -o /dev/null -X DELETE -H "Authorization: Bearer $TOKEN" -H "Mcp-Session-Id: $session" "$url"
