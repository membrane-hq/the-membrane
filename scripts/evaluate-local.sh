#!/usr/bin/env bash
# Disposable authorization check. No real model or upstream write is exercised.
set -euo pipefail
cd "$(dirname "$0")/.."
for command in cargo curl jq python3; do
  command -v "$command" >/dev/null || { echo "Missing prerequisite: $command" >&2; exit 1; }
done
cargo build --locked -p membrane-cli --bin membrane --example operator-request
root="$PWD"
scratch="$(mktemp -d)"
gate_pid=''
cleanup() {
  if [ -n "$gate_pid" ]; then kill "$gate_pid" 2>/dev/null || true; wait "$gate_pid" 2>/dev/null || true; fi
  rm -rf "$scratch"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
umask 077
mkdir "$scratch/home"
# A fresh environment prevents inherited credentials, relays and telemetry from
# changing the local check. Never print the ephemeral private key files.
local_env=(PATH="$PATH" HOME="$scratch/home"
  MEMBRANE_OPERATION_DIR="$scratch/operations" MEMBRANE_DEV_MOCK_MODEL=1)
local_run() {
  env -i "${local_env[@]}" NOSTR_NSEC_FILE="$scratch/$key.nsec" "$@"
}
key=operator
local_run "$root/target/debug/examples/operator-request" setup "$scratch"
# Bootstrap this new disposable registry, not an existing operator policy.
local_run "$root/target/debug/membrane" registry migrate --to "$scratch/registry.yaml" > "$scratch/migrate.log" 2>&1
operator_pubkey="$(jq -r .operator_pubkey "$scratch/keys.json")"
caller_pubkey="$(jq -r .caller_pubkey "$scratch/keys.json")"
# Port 9 is only a loopback relay target, not an external service. An unavailable
# relay causes retry warnings; this check does not test published evidence.
local_run "$root/target/debug/membrane" iac issue \
  --relay ws://127.0.0.1:9 --caller-pubkey "$caller_pubkey" \
  --scope-id pilot-scope --model sha256:demo-model --ttl-secs 900 \
  --out "$scratch/iac.json" > "$scratch/issue.log" 2>&1
# Select an unused loopback port. There is a small bind race; a failed start is
# reported as a failed check, never as a successful authorization result.
port="$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(('127.0.0.1', 0))
    print(sock.getsockname()[1])
PY
)"
url="http://127.0.0.1:$port"
env -i "${local_env[@]}" NOSTR_NSEC_FILE="$scratch/operator.nsec" \
  "$root/target/debug/membrane" gate start \
  --relay ws://127.0.0.1:9 --registry "$scratch/registry.yaml" \
  --iac "$scratch/iac.json" --listen "127.0.0.1:$port" > "$scratch/gate.log" 2>&1 &
gate_pid=$!
ready=0
for _ in $(seq 1 90); do
  if ! kill -0 "$gate_pid" 2>/dev/null; then echo 'FAIL: gate exited before readiness' >&2; exit 1; fi
  if curl --noproxy '*' --max-time 2 -fsS "$url/health" > /dev/null 2>&1; then ready=1; break; fi
  sleep 1
done
[ "$ready" = 1 ] || { echo 'FAIL: gate did not become ready' >&2; exit 1; }
key=caller
printf '%s\n' '{"model":"sha256:demo-model","messages":[{"role":"user","content":"local evaluation"}],"stream":false}' > "$scratch/chat.json"
local_run "$root/target/debug/examples/operator-request" sign \
  "$url" "$operator_pubkey" "$scratch/iac.json" /v1/chat/completions \
  "$scratch/chat.json" "$scratch/request" > /dev/null
send() {
  curl --noproxy '*' --max-time 45 -sS -D "$scratch/response.headers" \
    -o "$scratch/response.json" -w '%{http_code}' \
    "$url/v1/chat/completions" --header @"$scratch/request/headers.txt" \
    --data-binary @"$scratch/request/body.json"
}
expect() {
  [ "$2" = "$3" ] || { printf 'FAIL: %s expected %s, got %s\n' "$1" "$3" "$2" >&2; exit 1; }
  printf 'PASS: %s (%s)\n' "$1" "$2"
}
status="$(send)"
if [ "$status" != 200 ]; then cat "$scratch/response.json" >&2; fi
expect 'signed, in-scope request' "$status" 200
grep -qi '^x-membrane-cp-hash:' "$scratch/response.headers" || { echo 'FAIL: missing receipt hash header' >&2; exit 1; }
jq -e '.choices | length > 0' "$scratch/response.json" > /dev/null
expect 'identical caller proof replay refused' "$(send)" 403
grep -qi 'replay' "$scratch/response.json" || { echo 'FAIL: replay refused for unexpected reason' >&2; exit 1; }
sed '/^X-Membrane-Caller-Proof:/d' "$scratch/request/headers.txt" > "$scratch/no-proof.headers"
status="$(curl --noproxy '*' --max-time 45 -sS -o "$scratch/response.json" -w '%{http_code}' \
  "$url/v1/chat/completions" --header @"$scratch/no-proof.headers" \
  --data-binary @"$scratch/request/body.json")"
expect 'missing caller proof refused' "$status" 403
grep -qi 'missing caller proof' "$scratch/response.json" || { echo 'FAIL: missing-proof call refused for unexpected reason' >&2; exit 1; }
printf '%s\n' 'Local authorization check passed. Model reply is canned; no upstream write, relay export, revocation, or production deployment was tested.'
