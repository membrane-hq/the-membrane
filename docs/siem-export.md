# SIEM / SOC export

The Membrane emits authorization telemetry for security systems to consume
(**telemetry out** — prove-and-stop stays at the gate). It does not replace a
SIEM, SOC, or SOAR, and these exports do not imply an integration or partnership
with any particular vendor.

## Formats

- `jsonl` — newline-delimited `membrane.action_receipt` records for syslog
  collectors, file tailers, object storage, and HTTP bulk ingestion.
- `ocsf` — an OCSF-inspired JSON projection with familiar `actor`, `session`,
  `api`, `policy`, `status`, and `metadata.product` fields. It intentionally
  omits OCSF class/activity numeric IDs until the mapping is certified against
  a pinned OCSF release.

Both formats include timestamps, public agent/subject identifiers,
session/scope identifiers when known, allowlisted model/tool names, policy and
receipt digests, parent receipt digests, outcomes, and block/degradation
reasons. They omit prompts, action bodies, private keys, credentials, and
signatures.

## CLI export

Export the last day of signed attestation-bus receipts and alerts:

```bash
membrane evidence export \
  --relay "$MEMBRANE_RELAY_URL" \
  --since-secs 86400 \
  --format jsonl \
  --out membrane-siem.jsonl
```

Use `--format ocsf --out membrane-siem.ocsf.json` for the OCSF-inspired pack.
Use `--subject-pubkey <hex>` to restrict a shared bus export to one public
subject identifier. Reading the bus requires no signing key.

The bus export covers published authorization, allowed-action CP,
blocked-action, sever, and stale/degraded events. Coverage remains limited to
traffic routed through the Membrane gate.

## Live webhook shipper

> For production use the [hardened export](siem-export-hardened.md): bounded durable
> spool, TLS pinning, retry with backoff and an explicit failure mode. The shipper
> below is fail-open by default and is meant for local demos.

When `MEMBRANE_SIEM_WEBHOOK_URL` is set, the gate (and `membrane iac issue`)
POST mapped SIEM events as they are published:

| Event | Trigger |
| --- | --- |
| `authorization_issued` | `membrane iac issue` (and optional local demo issue) |
| `allowed_action` | Successful gate router turn |
| `blocked_action` | Gate fail-closed deny |
| `sever` / `degraded` | Subject sever or Δt stale alert |

Delivery is **fail-open by default**: webhook outages never block authorization
or chat/completions. Set `MEMBRANE_SIEM_WEBHOOK_FAIL_OPEN=false` only when a
synchronous caller (for example `iac issue`) should surface delivery failure.

### Environment

| Variable | Purpose | Default |
| --- | --- | --- |
| `MEMBRANE_SIEM_WEBHOOK_URL` | One URL, or comma-separated URLs | unset (disabled) |
| `MEMBRANE_SIEM_WEBHOOK_FORMAT` | `jsonl` or `ocsf` | `jsonl` |
| `MEMBRANE_SIEM_WEBHOOK_SECRET` | Optional shared-secret header value | unset |
| `MEMBRANE_SIEM_WEBHOOK_SECRET_HEADER` | Header name for the secret | `X-Membrane-Webhook-Secret` |
| `MEMBRANE_SIEM_WEBHOOK_FAIL_OPEN` | Swallow delivery errors after retries | `true` |
| `MEMBRANE_SIEM_WEBHOOK_DEAD_LETTER` | Append-only JSONL dead-letter path | unset |
| `MEMBRANE_SIEM_WEBHOOK_MAX_ATTEMPTS` | Attempts per URL (including first) | `4` |
| `MEMBRANE_SIEM_WEBHOOK_BACKOFF_MS` | Initial exponential backoff | `100` |

Keep the webhook URL and shared secret in the operator secret manager (Doppler,
Vault, etc.). Never commit them.

### Example

```bash
export MEMBRANE_SIEM_WEBHOOK_URL='https://siem.example.invalid/ingest'
export MEMBRANE_SIEM_WEBHOOK_FORMAT=jsonl
export MEMBRANE_SIEM_WEBHOOK_SECRET='…'   # from secret manager
export MEMBRANE_SIEM_WEBHOOK_DEAD_LETTER=/var/log/membrane/siem-dead-letter.jsonl

membrane gate start --listen 127.0.0.1:8787
```

Each POST body is a single JSON Lines record (`Content-Type: application/x-ndjson`)
or a single OCSF-inspired object (`Content-Type: application/json`). Retries use
exponential backoff. Exhausted deliveries append a dead-letter line with the
error, attempt count, URL, and the original digest-only event.

The local demo may honor the same env vars for operator testing. Leave them
unset on the public sandbox so simulation traffic is never shipped to a SOC.

## Demo API

The simulation-only dashboard exposes the same normalized records:

```bash
curl -fsS 'http://127.0.0.1:8790/demo/api/siem?format=ocsf'
curl -fsS 'http://127.0.0.1:8790/demo/api/siem?format=jsonl'
```

The hosted sandbox uses the same routes at
`https://demo.themembrane.org`. Every demo record has
`"simulation": true`.

## Ingestion patterns

For file-based ingestion, run the CLI on a schedule, write to a temporary file,
then atomically rename it into the directory watched by the SIEM forwarder. A
collector can also tail JSON Lines and forward each line over syslog or HTTPS.

For HTTP ingestion without the live shipper, POST a generated file with the
authentication and retry mechanism supplied by the operator's collector:

```bash
curl --fail-with-body \
  -H 'Content-Type: application/x-ndjson' \
  --data-binary @membrane-siem.jsonl \
  "$SIEM_INGEST_URL"
```

## Deferred

- Certified OCSF class, category, activity, and severity identifiers
- CEF formatting and RFC 5424 framing
- Vendor-specific field packs and authentication adapters

Production tool invoke (`POST /v1/tools/invoke`) now publishes blocked-action
receipts with `tool_id` / `tool_allowlist` fields for the GitHub connector.
See [github-connector.md](github-connector.md).
