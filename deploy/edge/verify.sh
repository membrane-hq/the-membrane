#!/usr/bin/env bash
# Check the required-path reference deployment (docs/edge-deployment.md):
# direct connections to the gate and model backend fail, production routes
# refuse requests without a valid edge assertion, the caller-proof check
# still applies on top, and the authorized path reaches the real backend.
#
# Prereqs: docker compose, jq, openssl; the membrane CLI and the
# operator-request example built (cargo build --locked -p membrane-cli
# --bin membrane --example operator-request). MEMBRANE_GATE_IMAGE selects
# the gate image (default membrane-gate:local).
set -euo pipefail
cd "$(dirname "$0")"
ROOT=$(cd ../.. && pwd)
export PATH="$ROOT/target/debug:$PATH"
WORK=$(mktemp -d)
trap 'docker compose down -v --remove-orphans >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT

fail() { echo "FAIL: $1" >&2; exit 1; }

command -v membrane >/dev/null || fail "membrane CLI not on PATH (build first)"
command -v operator-request >/dev/null || fail "operator-request example not on PATH (build first)"

echo "== generate ephemeral operator/caller keys, grant and IAC =="
operator-request setup "$WORK/edge"
sed -i 's#http://127.0.0.1:8080#http://model:8080#' "$WORK/edge/registry.yaml"
export NOSTR_NSEC_FILE="$WORK/edge/operator.nsec"
membrane iac issue --caller-pubkey "$(jq -r .caller_pubkey "$WORK/edge/keys.json")" \
  --scope-id pilot-scope --model sha256:demo-model --ttl-secs 900 --out "$WORK/edge/iac.json"
mkdir -p config
cp "$WORK/edge/registry.yaml" "$WORK/edge/iac.json" "$WORK/edge/operator.nsec" config/
chmod 600 config/operator.nsec
# First install of the policy generation record (explicit trust reset);
# without it the gate refuses dispatch for an unrecorded registry.
membrane registry migrate --to config/registry.yaml >/dev/null

echo "== start the stack =="
docker compose up -d
body=""; ready=""
for i in $(seq 1 90); do
  body=$(curl -fsS http://127.0.0.1:8081/health 2>/dev/null) && \
    [ "$(echo "$body" | jq -r .status)" = "ok" ] && { ready=1; break; }
  sleep 2
done
echo "$body" | jq '{status, edge_auth, journal_available, router_stale}' || true
[ "$ready" = 1 ] || fail "gate never reported status=ok through the edge"
# /health stays reachable without an assertion and reports the mode.
[ "$(echo "$body" | jq -r .edge_auth.enabled)" = "true" ] \
  || fail "/health does not report edge_auth.enabled=true"

echo "== direct connections from the agent network must fail =="
if docker compose exec -T agent curl -sS --connect-timeout 3 http://gate:8787/health >/dev/null 2>&1; then
  fail "agent reached the gate directly"
fi
echo "ok: no direct agent -> gate route"
if docker compose exec -T agent curl -sS --connect-timeout 3 -X POST http://model:8080/v1/chat/completions >/dev/null 2>&1; then
  fail "agent reached the model backend directly"
fi
echo "ok: no direct agent -> model backend route"

echo "== edge assertion enforced =="
chat_body='{"model":"sha256:demo-model","messages":[{"role":"user","content":"hi"}],"stream":false}'
# No assertion: refused before any caller check.
out=$(docker compose exec -T agent curl -s -w '\n%{http_code}' http://edge/v1/chat/completions \
  -H 'Content-Type: application/json' -d "$chat_body")
code=$(printf '%s' "$out" | tail -1)
[ "$code" = 403 ] || fail "no-assertion request returned $code, want 403"
printf '%s' "$out" | head -1 | jq -e '.error.message | test("edge assertion required")' >/dev/null \
  || { echo "$out"; fail "no-assertion 403 missing its reason"; }
echo "ok: request without assertion refused"

# Assertion signed by the wrong key: refused.
wrong_key="$WORK/wrong.pem"
openssl genrsa -out "$wrong_key" 2048 2>/dev/null
wrong=$(./mint-assertion.sh "$wrong_key" \
  https://edge.membrane.example/required-path-reference membrane-gate agent-7 300)
code=$(docker compose exec -T agent curl -s -o /dev/null -w '%{http_code}' http://edge/v1/chat/completions \
  -H 'Content-Type: application/json' -H "Cf-Access-Jwt-Assertion: $wrong" -d "$chat_body")
[ "$code" = 403 ] || fail "wrong-key assertion returned $code, want 403"
echo "ok: wrong-key assertion refused"

# Valid assertion but no caller proof: the second check still refuses.
assertion=$(./mint-assertion.sh test-keys/edge-test-key.pem \
  https://edge.membrane.example/required-path-reference membrane-gate agent-7 300)
out=$(docker compose exec -T agent curl -s -w '\n%{http_code}' http://edge/v1/chat/completions \
  -H 'Content-Type: application/json' -H "Cf-Access-Jwt-Assertion: $assertion" -d "$chat_body")
code=$(printf '%s' "$out" | tail -1)
[ "$code" = 403 ] || fail "assertion-only request returned $code, want 403"
printf '%s' "$out" | head -1 | jq -e '.error.message | test("caller proof")' >/dev/null \
  || { echo "$out"; fail "assertion-only 403 missing the caller-proof reason"; }
echo "ok: assertion alone does not authorize an action"

echo "== authorized path crosses edge -> gate -> backend =="
printf '%s' "$chat_body" > "$WORK/edge/chat.json"
export NOSTR_NSEC_FILE="$WORK/edge/caller.nsec"
operator-request sign http://127.0.0.1:8081 \
  "$(jq -r .operator_pubkey "$WORK/edge/keys.json")" \
  "$WORK/edge/iac.json" /v1/chat/completions "$WORK/edge/chat.json" "$WORK/edge/request"
printf 'Cf-Access-Jwt-Assertion: %s\n' "$assertion" >> "$WORK/edge/request/headers.txt"
send() { curl -s -o "$1" -w '%{http_code}' http://127.0.0.1:8081/v1/chat/completions \
  --header @"$WORK/edge/request/headers.txt" --data-binary @"$WORK/edge/request/body.json"; }
first=$(send "$WORK/edge/first.json")
[ "$first" = 200 ] || { cat "$WORK/edge/first.json"; fail "authorized request returned $first"; }
jq -e '.id == "edge-ref-upstream"' "$WORK/edge/first.json" >/dev/null \
  || { cat "$WORK/edge/first.json"; fail "reply missing the backend marker"; }
echo "ok: authorized request reached the real backend through the gate"
second=$(send "$WORK/edge/replay.json")
[ "$second" = 403 ] || fail "replay returned $second, want 403"
echo "ok: replay of the same caller proof refused"

echo "== agent holds no downstream credentials =="
if docker compose exec -T agent sh -c 'env | grep -Eiq "nsec|token|secret|password|model_api"'; then
  fail "agent environment carries a credential"
fi
docker compose exec -T agent test ! -e /config/registry.yaml \
  || fail "agent can see the gate config"
echo "ok: agent has no keys, tokens or upstream configuration"

echo "== refusals are recorded in the gate log =="
docker compose logs gate 2>&1 | grep -q "edge assertion required" \
  || fail "gate log has no edge refusal entry"
echo "ok: edge refusals recorded"

echo "EDGE REQUIRED-PATH CHECKS PASSED"
