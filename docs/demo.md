# Membrane demo dashboard

Browser dashboard for The Membrane fail-closed narrative, demonstrating Membrane gate IAC checks and CP receipt chaining.

Product overview and deployment: [product.md](product.md).

This is the **primary public demo path** - no secrets, relay setup, or external
tool access. For the operator full stack (relay + gate + your signed IAC), see
[README § Full stack (operators)](../README.md#full-stack-operators). Repo
overview: [README § Local demo dashboard](../README.md#local-demo-dashboard).

## Hosted page

Open **https://demo.themembrane.org**.

The hosted page is static. It shows the six-step flow below as a recorded
replay of one real `membrane demo` run, then a simulated operator view with
invented traffic. No gate runs behind it and nothing is sent anywhere. It is
the same flow as the local demo, not the same page: only the local demo runs
the gate code live.

A live hosted sandbox (per-session state, real signing) is a separate container
deployment, described in [deploy/demo/README.md](../deploy/demo/README.md). It
is not what the URL above serves today. Do not enter secrets, customer data, or
other sensitive information in any demo. GitHub mutations belong on the
production gate with a configured connector ([github-connector.md](github-connector.md)),
never on a sandbox.

## Run locally with one command

```bash
cargo run -p membrane-cli --features demo -- demo
```

Open **http://127.0.0.1:8790/**.

Optional listen address: `cargo run -p membrane-cli --features demo -- demo --listen 127.0.0.1:8790`

If the `membrane` binary was built with `--features demo`, the equivalent command is `membrane demo`.

## What it is

- Ephemeral local signing keys (no `NOSTR_NSEC`, no Doppler required)
- In-memory attestation bus (`memory://`) - no relay or paid APIs
- Demo-only HTTP routes under `/demo/api/*` (not mounted by `membrane gate start`)
- Tool calls (`jira.comment`, `slack.post`, `github.merge`) are **simulated** and labeled as such (production connectors are separate; see [github-connector.md](github-connector.md))

## Six-step demo flow

1. **Issue authorization** - 15-minute signed IAC for `support-agent-v1` with tools `jira.comment` and `slack.post`
2. **Allowed action** - run `jira.comment`; green chained receipt (CP hash linked to parent)
3. **Blocked tool** - attempt `github.merge`; hard block with reason
4. **Blocked model swap** - same tool with `unrestricted-agent-v9`; hard block
5. **Sever** - sever session, then retry `slack.post`; fails closed
6. **Evidence** - export JSON evidence or SIEM-ready OCSF-inspired/JSON Lines records, then verify the receipt chain (pass/fail). Verification recomputes each receipt hash, checks the issuer signature on every signed event, confirms the receipt fields match the signed event, and checks chain linkage. Each receipt also includes the exact signed Nostr bus envelope: verification checks its ID and signature, signer, kind, timestamp, and content against the signed Membrane event, and matches `bus_event_id` to its authenticated ID. Packs without a bus envelope fail verification; re-export evidence from an updated server. Blocked calls get signed `membrane.action.blocked` receipts anchored to the current chain head; they do not advance it. The hosted verifier pins the signing key of the server that issued the pack

Demo SIEM API:

```bash
curl -fsS 'http://127.0.0.1:8790/demo/api/siem?format=ocsf'
curl -fsS 'http://127.0.0.1:8790/demo/api/siem?format=jsonl'
```

Both remain simulation-only and omit action bodies and credentials. See
[siem-export.md](siem-export.md) for operator ingestion patterns and the
optional fail-open live webhook (`MEMBRANE_SIEM_WEBHOOK_URL`; leave unset on
the public sandbox).

## Technical IAC smoke test

The older relay-backed IAC smoke test remains available to operators as `membrane iac-smoke`. It requires a relay and your signing key and is not the public product demo.

## Tests

```bash
cargo test -p membrane-cli cli_tests
cargo test -p membrane-gate --features demo demo
cargo test -p membrane-gate github
cargo test -p membrane-gate tool_invoke_policy
cargo test -p membrane-core
```

GitHub connector (operators, not this demo): [github-connector.md](github-connector.md).
