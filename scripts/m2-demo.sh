#!/usr/bin/env bash
# M2 walk-through against the gateway of run-dev-host.sh: what the portal BFF does through C5 (mTLS with the
# mcp-portal-bff certificate, user token for aud mcp-gateway-admin) and what Claude Code does on the link.
#   ADMIN_TOKEN=... TOKEN=... scripts/m2-demo.sh
# TOKEN: access token of the user for the claude-code client; ADMIN_TOKEN: the same user's token exchanged for
# aud=mcp-gateway-admin (python3 ../mcp-platform-dev/scripts/mcpdev.py exchange <user> --audience mcp-gateway-admin
# --requester mcp-portal-bff). Nothing is printed that is a token.
set -euo pipefail

: "${TOKEN:?set TOKEN}" "${ADMIN_TOKEN:?set ADMIN_TOKEN}"
here="$(cd "$(dirname "$0")/.." && pwd)"
dev="${MCP_PLATFORM_DEV:-$here/../mcp-platform-dev}"
public="${PUBLIC_URL:-http://localhost:18700}"
internal="${INTERNAL_URL:-https://localhost:18701}"
slug="${SLUG:-m2-demo}"

admin() {
  curl -sS --cacert "$dev/certs/ca/ca.crt" --cert "$dev/certs/mcp-portal-bff/tls.crt" --key "$dev/certs/mcp-portal-bff/tls.key" \
    -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' "$@"
}
mcp() {
  local path="$1"; shift
  curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' "$@" "$public$path"
}
modern() {
  local path="$1" method="$2" name="$3" params="$4"
  local meta='"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}'
  mcp "$path" -H 'MCP-Protocol-Version: 2026-07-28' -H "Mcp-Method: $method" ${name:+-H "Mcp-Name: $name"} \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":{${params:+$params,}$meta}}"
}

echo "== catalog (tools of the user, access from policy)"
admin "$internal/admin/v1/catalog" | python3 -c '
import json, sys
for s in json.load(sys.stdin)["servers"]:
    tools = ["%s:%s%s" % (t["name"].split("__")[1], t["access"], "(disabled)" if t["disabled"] else "") for t in s["tools"]]
    print(" ", s["serverId"], s["version"], " ".join(tools))
'

echo "== create link $slug (jira__get_issue, jira__search_issues)"
admin -X DELETE -o /dev/null "$internal/admin/v1/virtual-servers/$slug" || true
admin -w ' HTTP %{http_code}\n' -d "{\"slug\":\"$slug\",\"displayName\":\"M2 demo\",\"tools\":[\"jira__get_issue\",\"jira__search_issues\"]}" \
  "$internal/admin/v1/virtual-servers"
echo "== the same slug again"
admin -w ' HTTP %{http_code}\n' -d "{\"slug\":\"$slug\",\"displayName\":\"again\",\"tools\":[\"jira__get_issue\"]}" "$internal/admin/v1/virtual-servers"
echo "== resourceDefaults"
admin -w ' HTTP %{http_code}\n' -d '{"slug":"narrowed","displayName":"x","tools":["jira__get_issue"],"resourceDefaults":{"Jira::Project":["ABC"]}}' \
  "$internal/admin/v1/virtual-servers"
echo "== list"
admin "$internal/admin/v1/virtual-servers"; echo

echo "== no token on the link: 401 with metadata"
curl -sS -o /dev/null -D - -X POST "$public/v/$slug/mcp" | grep -iE '^(HTTP|www-authenticate|x-content-type|content-security|content-type)'
echo "== RFC 9728 document"
curl -sS "$public/.well-known/oauth-protected-resource/v/$slug/mcp"; echo

echo "== tools/list on the link"
modern "/v/$slug/mcp" tools/list "" "" | python3 -c 'import json,sys; print(" ", [t["name"] for t in json.load(sys.stdin)["result"]["tools"]])'
echo "== tools/call jira__get_issue on the link"
modern "/v/$slug/mcp" tools/call jira__get_issue '"name":"jira__get_issue","arguments":{"issueKey":"ABC-1"}'; echo
echo "== a tool the user may call but the link does not name"
modern "/v/$slug/mcp" tools/call jira__add_comment '"name":"jira__add_comment","arguments":{"issueKey":"ABC-1","body":"x"}'; echo

echo "== delete the link"
admin -X DELETE -w 'HTTP %{http_code}\n' "$internal/admin/v1/virtual-servers/$slug"
modern "/v/$slug/mcp" tools/list "" "" | head -c 200; echo
