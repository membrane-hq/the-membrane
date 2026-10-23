# GitHub connector

Operator vertical slice for The Membrane: allowlisted GitHub mutations go through
the production gate (`POST /v1/tools/invoke`) with live IAC, CP receipts, sever,
and SIEM export. This is **not** the public demo simulator.

The hosted sandbox at `demo.themembrane.org` stays simulation-only and must
not receive operator GitHub tokens.

## Tools

| Tool id | Effect | Typical IAC |
| --- | --- | --- |
| `github.comment` | POST issue/PR comment via GitHub API | allow |
| `github.issue.read` | GET issue/PR metadata (title digest only in receipts) | optional allow |
| `github.merge` | PUT merge PR | **omit** from allowlist to hard-block |

## Required env / config

| Name | Purpose |
| --- | --- |
| `MEMBRANE_GITHUB_TOKEN_FILE` | Path to a file holding the token (mode 0600). Preferred: the value never sits in the process environment or on a command line |
| `MEMBRANE_GITHUB_TOKEN` or `GITHUB_TOKEN` | Fallback. Fine-grained or classic token, never commit. Removed from the gate process environment after it is read |
| `github_repo_allowlist` in channel registry | Explicit `owner/name` list; empty denies all |

Suggested token scopes: classic `repo`, or fine-grained **Issues: Read and write**
(and **Pull requests: Read and write** if merging is ever allowlisted). Prefer a
disposable pilot repo.

## Credential handling

The gate is the only process that holds the connector credential. Callers and
models send a tool request; they never receive the token, and nothing in the
request chooses which credential is used.

- The token is held in a redacted, zeroed-on-drop type. Debug output shows
  `Secret(<redacted>)`, and the value is read only where the `Authorization`
  header is built.
- A configured token file must not be readable by group or others, and a set
  but unusable file stops startup. It never falls back to the environment.
- The token is attached only to an `https` API base, or to loopback for local
  tests. Any other destination is refused before a request is built.
- If GitHub echoes the token in an error body, the exact value is removed
  before the error reaches the caller, the receipt or the logs.

This follows the pattern in
[Bitwarden Agent Access](https://github.com/bitwarden/agent-access) and
[1Password's agentic autofill](https://support.1password.com/1password-claude-security/):
the agent asks for an action, the secret is applied at the point of use by
software that is not the model, and the request fields are treated as untrusted
claims. The Membrane does not adopt their approval model. Approval stays one
approval for one dispatch, bound to the exact request, and there is no
auto-approve window.

Receipts store `body_sha256` digests — not comment body plaintext or tokens.

## Operator recipe

First build and start the local relay from [the operator
walkthrough](operator-walkthrough.md). For this connector run, use a new scratch
directory and generate the exact repository grant at setup:

```bash
export PILOT_DIR="$(mktemp -d)"
export MEMBRANE_OPERATION_DIR="$PILOT_DIR/operations"
export OWNER='your-org'
export REPO='disposable-pilot-repo'
cargo run --locked -q -p membrane-cli --example operator-request -- \
  setup "$PILOT_DIR" "$OWNER/$REPO"
export GATE_PUBKEY="$(jq -r .operator_pubkey "$PILOT_DIR/keys.json")"
export CALLER_PUBKEY="$(jq -r .caller_pubkey "$PILOT_DIR/keys.json")"
export NOSTR_NSEC="$(jq -r .operator_nsec "$PILOT_DIR/keys.json")"
```

Use a disposable repository you control, with an existing issue #1. Load
`MEMBRANE_GITHUB_TOKEN` into the gate environment from your secret manager. Never
print or commit it. Unlike the local model check, the allowed comment below is a
live GitHub write. The setup helper grants only this repository, exact scope and
model to the caller; the global repository allowlist must match too.

```bash
# Issue as operator. Merge is deliberately omitted.
membrane iac issue --caller-pubkey "$CALLER_PUBKEY" \
  --scope-id pilot-scope --model sha256:demo-model --ttl-secs 900 \
  --tool github.comment --tool github.issue.read --out "$PILOT_DIR/iac.json"
membrane gate start --registry "$PILOT_DIR/registry.yaml" \
  --iac "$PILOT_DIR/iac.json" --listen 127.0.0.1:8787 \
  > "$PILOT_DIR/gate.log" 2>&1 &
export GATE_PID=$!
```

Wait for `/health` to respond and confirm `github_connector.token_configured`
is true. Keep the token only in the gate process, not the caller environment.

```bash
# Switch to caller. The CLI verifies the operator IAC and signs a fresh proof.
unset MEMBRANE_GITHUB_TOKEN GITHUB_TOKEN
export NOSTR_NSEC="$(jq -r .caller_nsec "$PILOT_DIR/keys.json")"
membrane tools invoke --gate-pubkey "$GATE_PUBKEY" --iac "$PILOT_DIR/iac.json" \
  --tool github.issue.read --model sha256:demo-model \
  --owner "$OWNER" --repo "$REPO" --issue-number 1

# Allowed write. Choose one ID for this intended write, then keep it on retry.
export COMMENT_OPERATION_ID="$(python3 -c 'import uuid; print(uuid.uuid4())')"
membrane tools invoke --gate-pubkey "$GATE_PUBKEY" --iac "$PILOT_DIR/iac.json" \
  --tool github.comment --operation-id "$COMMENT_OPERATION_ID" \
  --model sha256:demo-model --owner "$OWNER" --repo "$REPO" \
  --issue-number 1 --body 'Membrane pilot: allowed comment'

# Blocked by the IAC before any GitHub merge request.
membrane tools invoke --gate-pubkey "$GATE_PUBKEY" --iac "$PILOT_DIR/iac.json" \
  --tool github.merge --operation-id "blocked-merge-$COMMENT_OPERATION_ID" \
  --model sha256:demo-model --owner "$OWNER" --repo "$REPO" --pull-number 1
# Expected: HTTP 403 and nonzero CLI exit.

# Sever as operator; subsequent fresh-proof invokes on this scope fail closed.
NOSTR_NSEC="$(jq -r .operator_nsec "$PILOT_DIR/keys.json")" \
  membrane sever --scope-id pilot-scope
membrane evidence export --format jsonl --since-secs 3600 \
  --out "$PILOT_DIR/evidence.jsonl"
```

Severance is relay-backed; allow the gate's subscriber to observe it before
checking the subsequent denial. Do not auto-retry a write with a new operation
ID. Inspect GitHub and the journal first if a result is uncertain.

### Signed curl equivalent

This sends a live comment. Use it instead of the CLI comment above, not in
addition, unless a second comment is intended. Choose a stable operation ID and
keep the body unchanged after signing:

```bash
jq -n --arg owner "$OWNER" --arg repo "$REPO" \
  --arg operation_id "$COMMENT_OPERATION_ID" \
  '{tool:"github.comment",operation_id:$operation_id,model:"sha256:demo-model",owner:$owner,repo:$repo,issue_number:1,body:"Membrane pilot: allowed comment"}' \
  > "$PILOT_DIR/comment.json"
cargo run --locked -q -p membrane-cli --example operator-request -- sign \
  http://127.0.0.1:8787 "$GATE_PUBKEY" "$PILOT_DIR/iac.json" \
  /v1/tools/invoke "$PILOT_DIR/comment.json" "$PILOT_DIR/request"
curl -fsS http://127.0.0.1:8787/v1/tools/invoke \
  --header @"$PILOT_DIR/request/headers.txt" \
  --data-binary @"$PILOT_DIR/request/body.json"
```

The helper emits both the IAC and fresh caller-proof headers and the typed body
that was signed. Send within 60 seconds. Stop the gate and local relay after the
pilot; retain evidence and journal state until writes are reconciled.

## Connector execution and demo

The operator gate calls the GitHub API when a token and repository allowlist are configured. Authorization checks run before the request is sent. An unconfigured connector denies the request.

The demo approximates this workflow with simulated tool effects. It demonstrates authorization checks and receipt chaining without sending GitHub requests or holding connector credentials.

## Tests

```bash
cargo test -p membrane-gate github
cargo test -p membrane-gate tool_invoke_policy
# Optional live call (ignored by default):
# MEMBRANE_GITHUB_INTEGRATION=1 MEMBRANE_GITHUB_OWNER=… MEMBRANE_GITHUB_REPO=… \
#   cargo test -p membrane-gate live_github_integration -- --ignored
```

## Write retry safety

`github.comment` and `github.merge` require `--operation-id` in the CLI (or
`operation_id` in the signed JSON request). Keep the same ID when retrying the same
operation. Reserved IDs fail closed, including after restart. Inspect GitHub before
an operator clears any reservation. Store `MEMBRANE_OPERATION_DIR` on a persistent
volume; the reference compose file mounts `/state` for that purpose.

The router receipt covers the request intent and is published before GitHub is
contacted. It does not prove the write completed. The local append-only journal
records completion or uncertainty; it never automatically retries an uncertain
write. See [remaining enforcement limits](audit-fixes.md).
