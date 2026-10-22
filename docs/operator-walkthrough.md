# Operator walkthrough

Run from the repository root with Rust, jq and curl installed. Docker is needed only for the local relay in step 1; the signed call and replay refusal in steps 3 to 5 work without a relay (see the [quickstart](quickstart.md)). The relay is required to publish receipts, sever a session and export evidence (step 6). Without one, `iac issue` and `gate start` wait roughly 10 to 20 seconds on connection retries and log connection errors. Use a new,
private scratch directory for each run. This check uses the production gate's
caller authentication and relay receipts, with an explicitly enabled canned
model reply. It is not the public demo or a live model integration test.

## 1. Build and start a local relay

```bash
cargo build --locked -p membrane-cli --bin membrane --example operator-request
export PATH="$PWD/target/debug:$PATH"
export PILOT_DIR="$(mktemp -d)"
export MEMBRANE_RELAY_URL='ws://127.0.0.1:7777'
export MEMBRANE_OPERATION_DIR="$PILOT_DIR/operations"

docker run --rm -d --name membrane-relay -p 127.0.0.1:7777:8080 \
  -v "$PWD/tools/relay-local.toml:/usr/src/app/config.toml:ro" \
  scsibug/nostr-rs-relay:0.10.0
```

Wait for the relay to listen. Keep it bound to localhost. A clean relay avoids
inheriting earlier severance or chain state. Do not use a public relay for writes.

## 2. Generate local keys and an exact grant

```bash
cargo run --locked -q -p membrane-cli --example operator-request -- setup "$PILOT_DIR"
export GATE_PUBKEY="$(jq -r .operator_pubkey "$PILOT_DIR/keys.json")"
export CALLER_PUBKEY="$(jq -r .caller_pubkey "$PILOT_DIR/keys.json")"
export NOSTR_NSEC="$(jq -r .operator_nsec "$PILOT_DIR/keys.json")"
```

The helper writes owner-only local key material and a registry with an exact
`pilot-scope`, `local-llm` and `sha256:demo-model` grant for the caller. No key is
printed. These ephemeral keys are for this local check only. Never commit the
scratch directory, send the operator secret to an agent, or reuse these keys in
production. The bundled example registry remains deny-all.

## 3. Issue and start as the operator

```bash
membrane iac issue --caller-pubkey "$CALLER_PUBKEY" \
  --scope-id pilot-scope --model sha256:demo-model --ttl-secs 900 \
  --out "$PILOT_DIR/iac.json"
MEMBRANE_DEV_MOCK_MODEL=1 membrane gate start \
  --registry "$PILOT_DIR/registry.yaml" --iac "$PILOT_DIR/iac.json" \
  --listen 127.0.0.1:8787 > "$PILOT_DIR/gate.log" 2>&1 &
export GATE_PID=$!
```

Wait until `curl -fsS http://127.0.0.1:8787/health` responds. If the gate exits,
inspect `gate.log`. `MEMBRANE_DEV_MOCK_MODEL=1` is local development only. Without
it an unreachable model backend fails, rather than returning a mock. For a live
backend set `model_api_url` in the scratch registry, omit the mock flag, and use
an exact model ID in both the registry grant and IAC.

## 4. Sign as the caller and send with curl

```bash
export NOSTR_NSEC="$(jq -r .caller_nsec "$PILOT_DIR/keys.json")"
cat > "$PILOT_DIR/chat.json" <<'JSON'
{"model":"sha256:demo-model","messages":[{"role":"user","content":"hi"}],"stream":false}
JSON
cargo run --locked -q -p membrane-cli --example operator-request -- sign \
  http://127.0.0.1:8787 "$GATE_PUBKEY" "$PILOT_DIR/iac.json" \
  /v1/chat/completions "$PILOT_DIR/chat.json" "$PILOT_DIR/request"
curl -fsS -D "$PILOT_DIR/response.headers" \
  http://127.0.0.1:8787/v1/chat/completions \
  --header @"$PILOT_DIR/request/headers.txt" \
  --data-binary @"$PILOT_DIR/request/body.json"
grep -i '^x-membrane-cp-hash:' "$PILOT_DIR/response.headers"
```

Expect HTTP 200, a canned model reply and a CP hash header. Send within 60 seconds
of signing. The helper verifies the IAC and gate audience, then signs the
serialized `ChatRequest` or `ToolInvokeRequest` using the shipped `CallerProof`.
It emits the exact typed body used in the proof. Do not edit the body after
signing. Each request needs a new proof and nonce.

## 5. Verify fail-closed behavior

Repeat the identical curl request without signing again. Expect HTTP 403 for
replayed proof. Send only the IAC header, without a proof: expect HTTP 403 and no
model dispatch. Do not use `curl -f` when inspecting those expected denials.

For a revocation check, set the exact caller grant's `revoked: true` in the
scratch registry using a temporary file and atomic rename. Sign again and send:
expect HTTP 403. Restore the grant only as an explicit operator action.

## 6. Evidence and cleanup

```bash
membrane evidence export --format jsonl --since-secs 3600 \
  --out "$PILOT_DIR/evidence.jsonl"
kill "$GATE_PID"
docker stop membrane-relay
unset NOSTR_NSEC
```

Inspect the evidence and local logs before deleting the scratch directory. A
CP receipt records authorized request intent, not proof of a completed upstream
write. Keep a persistent `MEMBRANE_OPERATION_DIR` for deployments; use the
[GitHub connector](github-connector.md) recipe for write IDs and reconciliation.
