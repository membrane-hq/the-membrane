# Quickstart: from clone to a refused call

Runs a real gate locally, sends one signed call that is allowed, then replays it and sends one without a caller proof. Both are refused.

Requires Rust (stable), a C toolchain, `git`, `jq` and `curl`. No Docker and no paid API. First build takes one to two minutes.

```bash
# 1. build
git clone https://github.com/membrane-hq/the-membrane.git && cd the-membrane
cargo build --locked -p membrane-cli --bin membrane --example operator-request
export PATH="$PWD/target/debug:$PATH" PILOT_DIR="$(mktemp -d)"

# 2. create operator and caller keys, plus an exact grant for the caller
cargo run --locked -q -p membrane-cli --example operator-request -- setup "$PILOT_DIR"
export GATE_PUBKEY="$(jq -r .operator_pubkey $PILOT_DIR/keys.json)"
export CALLER_PUBKEY="$(jq -r .caller_pubkey $PILOT_DIR/keys.json)"

# 3. issue a 15-minute signed scope and start the gate (mock model, local only)
export NOSTR_NSEC_FILE="$PILOT_DIR/operator.nsec"
membrane iac issue --caller-pubkey "$CALLER_PUBKEY" --scope-id pilot-scope \
  --model sha256:demo-model --ttl-secs 900 --out "$PILOT_DIR/iac.json"
MEMBRANE_DEV_MOCK_MODEL=1 membrane gate start --registry "$PILOT_DIR/registry.yaml" \
  --iac "$PILOT_DIR/iac.json" --listen 127.0.0.1:8787 > "$PILOT_DIR/gate.log" 2>&1 &
until curl -fsS http://127.0.0.1:8787/health >/dev/null; do sleep 1; done

# 4. sign as the caller and send
export NOSTR_NSEC_FILE="$PILOT_DIR/caller.nsec"
echo '{"model":"sha256:demo-model","messages":[{"role":"user","content":"hi"}],"stream":false}' > "$PILOT_DIR/chat.json"
cargo run --locked -q -p membrane-cli --example operator-request -- sign \
  http://127.0.0.1:8787 "$GATE_PUBKEY" "$PILOT_DIR/iac.json" /v1/chat/completions \
  "$PILOT_DIR/chat.json" "$PILOT_DIR/request"
send() { curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8787/v1/chat/completions \
  --header @"$PILOT_DIR/request/headers.txt" --data-binary @"$PILOT_DIR/request/body.json"; }
send   # 200: signed, in scope, receipt written
send   # 403: same proof replayed, refused
```

Expected: `200`, then `403` with `caller authentication failed: replay or replay capacity exceeded`. Sending the scope header with no `X-Membrane-Caller-Proof` is also refused (`missing caller proof`).

Send each signed request within 60 seconds of signing. Each request needs a new proof.

## Notes

- This quickstart runs without a relay. Without one, `iac issue` and `gate start` wait roughly 10 to 20 seconds and log connection errors, then continue. A relay adds receipt publishing, ending sessions and evidence export. To run one locally, use the [operator walkthrough](operator-walkthrough.md).
- `MEMBRANE_DEV_MOCK_MODEL=1` returns a canned model reply. It is for local checks only.
- Clean up with `kill %1` and `rm -r "$PILOT_DIR"`.
- Next: [caller identity](caller-identity.md) and the [GitHub connector](github-connector.md).
