#!/usr/bin/env bash
# M3 walk-through against run-dev-host.sh, run-test-server-host.sh and run-test-broker-host.sh (the broker started with
# MCP_TEST_BROKER_TOTP=<sub of alice>=<dev seed of alice>, so that `mcpdev.py otp alice` makes valid codes):
# a DESTRUCTIVE call confirmed with the code of the authenticator app, the owner's preview, "first wins after the preview",
# cancel, the replay of a used code, and the activity of the calls. Tokens are never printed.
#   scripts/m3-demo.sh
# The gateway burns the codes of a user at the first DESTRUCTIVE call after its start (the state of confirmations has no
# continuity marker yet); the script waits out that window before it types a code.
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
dev="${MCP_PLATFORM_DEV:-$here/../mcp-platform-dev}"
public="${PUBLIC_URL:-http://localhost:18700}"
internal="${INTERNAL_URL:-https://localhost:18701}"
mcpdev() { python3 "$dev/scripts/mcpdev.py" "$@"; }

TOKEN="${TOKEN:-$(mcpdev token alice --client claude-code)}"
ADMIN_TOKEN="${ADMIN_TOKEN:-$(mcpdev exchange alice --audience mcp-gateway-admin --requester mcp-portal-bff)}"

admin() {
  curl -sS --cacert "$dev/certs/ca/ca.crt" --cert "$dev/certs/mcp-portal-bff/tls.crt" --key "$dev/certs/mcp-portal-bff/tls.key" \
    -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' "$@"
}
call() {
  local method="$1" name="$2" params="$3"
  local meta='"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}'
  curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    -H 'MCP-Protocol-Version: 2026-07-28' -H "Mcp-Method: $method" ${name:+-H "Mcp-Name: $name"} \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":{${params:+$params,}$meta}}" "$public/s/mcp-jira/mcp"
}
delete() { # issue key, optional code
  local args="{\"issueKey\":\"$1\"${2:+,\"confirmation_code\":\"$2\"}}"
  call tools/call jira__delete_issue "\"name\":\"jira__delete_issue\",\"arguments\":$args"
}
show() { python3 -c '
import json, sys
r = json.load(sys.stdin)["result"]
text = json.loads(r["content"][0]["text"]) if r.get("isError") else r["content"][0]["text"]
print("  ", "ERROR" if r.get("isError") else "OK", json.dumps(text)[:300])'; }
field() { python3 -c 'import json,sys; r=json.load(sys.stdin)["result"]; print(json.loads(r["content"][0]["text"])["'"$1"'"])'; }

echo "== tools/list: the destructive tool offers the code field"
call tools/list "" "" | python3 -c '
import json, sys
for t in json.load(sys.stdin)["result"]["tools"]:
    if t["name"] == "jira__delete_issue":
        print("  ", t["name"], "confirmation_code" in t["inputSchema"]["properties"], t["inputSchema"]["properties"]["confirmation_code"]["pattern"])'

echo "== first call: a pending confirmation, nothing deleted"
first="$(delete ABC-123)"; echo "$first" | show
id="$(echo "$first" | field confirmationId)"

echo "== the owner opens the preview (BFF, mTLS) and the view is recorded"
admin "$internal/admin/v1/confirmations/$id" | python3 -m json.tool | sed 's/^/   /'
admin -o /dev/null -w '   viewed HTTP %{http_code}\n' -X POST "$internal/admin/v1/confirmations/$id/viewed"
echo "== another destructive operation while the preview is open: refused, not replaced"
delete ABC-999 | show
echo "== someone else's token cannot see it: 404"
bob="$(mcpdev exchange bob --audience mcp-gateway-admin --requester mcp-portal-bff 2>/dev/null || true)"
if [[ -n "$bob" ]]; then
  curl -sS -o /dev/null -w '   bob HTTP %{http_code}\n' --cacert "$dev/certs/ca/ca.crt" --cert "$dev/certs/mcp-portal-bff/tls.crt" \
    --key "$dev/certs/mcp-portal-bff/tls.key" -H "Authorization: Bearer $bob" "$internal/admin/v1/confirmations/$id"
fi
echo "== a wrong code"
delete ABC-123 000000 | show
echo "== the owner cancels; the retry is cancelled; the codes of the moment are burned"
admin -o /dev/null -w '   cancel HTTP %{http_code}\n' -X POST "$internal/admin/v1/confirmations/$id/cancel"
delete ABC-123 "$(mcpdev otp alice | cut -d' ' -f1)" | show

echo "== a new operation; waiting for a code that is not burned (30 to 60 s)"
delete ABC-124 | show
sleep 65
code="$(mcpdev otp alice | cut -d' ' -f1)"
echo "== the right code: the tool runs once, the server never sees the code"
delete ABC-124 "$code" | show
echo "== the same code again: nothing is pending; and a used code does not confirm the next operation"
delete ABC-124 "$code" | show
delete ABC-125 | show
delete ABC-125 "$code" | show

echo "== activity: one row per call"
admin "$internal/admin/v1/activity/calls?limit=20" | python3 -c '
import json, sys
for r in json.load(sys.stdin):
    print("  ", r["ts"], r["tool"], r.get("resource", {}).get("id", "-"), r["result"], r.get("wrongCodeCount", "-"), r["errorCode"])'
