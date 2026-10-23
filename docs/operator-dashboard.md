# Local operator audit dashboard

This is an observational surface with exactly one operation: deciding held
approval calls. The `membrane-dashboard` binary is a separate Rust/Axum process with
no signing keys, connector credentials or policy editor. It stores no operator token:
the approvals view relays the token the operator pastes into the page to the gate
with each request, and the gate authenticates and receipts every decision. Static
assets are bundled; no CDN, framework build, external fonts or analytics are used.

## Run

Start the gate with your existing operator registry, signed IAC and relay setup:

```sh
cargo run -p membrane-cli -- gate start --registry tools/channel-registry.example.yaml --iac path/to/operator-iac.json
```

The gate starts a dedicated GET-only audit listener on `127.0.0.1:8788`, separate
from the production gate HTTP router. Set `MEMBRANE_AUDIT_LISTEN` to a literal
loopback socket to change it. A non-loopback address or bind failure stops startup.
Do not expose this listener with a reverse proxy.

In another terminal:

```sh
cargo run -p membrane-dashboard
# Open http://127.0.0.1:8790
# Optional, still loopback only:
cargo run -p membrane-dashboard -- --listen 127.0.0.1:8791 --audit-url http://127.0.0.1:8788
```

The approvals view talks to the production gate router, default
`http://127.0.0.1:8787`; change it with `--gate-url`. Like the audit upstream, the
gate URL must be a plain loopback HTTP base URL.

## What the page means

- **Approvals**: held calls waiting for a human decision, newest first, with the
  caller identity, scope, expiry and the exact held request payload. A pending hold
  takes an optional receipt note and a two-step approve or reject. Decided, consumed
  and expired holds stay visible with the decider's OIDC subject. When approval gates
  are not configured on the gate, the panel says so instead of showing an empty list.
  The caller still retries after approval; the dashboard does not execute anything.
- **Decision log**: newest 500 authorization decisions in the running gate process,
  allow/deny, stable matched rule code, UTC Unix timestamp displayed in browser local
  time, action class, signing gate identity and verified scope when available.
  The current IAC format does not authenticate a caller-specific agent ID; the page
  does not pretend an untrusted header is one. A denied scope is shown as unverified.
- **Liveness**: idle (no active scope), live, degraded (severed/stale checkpoint),
  or unknown when telemetry cannot be verified. It is not a claim that every scope
  is authorized. Polling every 10 seconds while visible; offline/stale responses clear
  cached status and metrics. Checkpoints can become stale between polls.
  The card shows two separate things: the gate's own uptime and heartbeat, and the
  router checkpoint age. The heartbeat is stamped every 5 seconds inside the gate
  process; after three missed intervals (15 seconds) status turns degraded. It is
  not published to the bus, because a liveness event on the checkpoint chain would
  move the chain head that IACs anchor to, and it never masks a stale router. It
  proves the gate runtime is scheduling work, not that any request would be allowed.
- **Loaded policy**: the running registry's channels, model/repository allowlists,
  forbidden exports and checkpoint freshness threshold, without the model API URL.
  Per-request signed IAC constraints still apply and are not editable here.
- **Deny rate**: denied / (allowed + denied) over the retained 500 rows, not an all-time
  or time-window metric. No observations means N/A. Total observed resets on restart.

An allow is recorded immediately before the upstream model/tool call, after the
relevant preflight authorization checks, not inferred from a successful receipt.
An upstream execution or post-action receipt failure does not retroactively turn
that allow into a policy denial. Those failures remain on the existing receipt/SIEM
paths. Invalid JSON handler requests are recorded as request/registry failures.
Other routing, HTTP transport and body-limit rejections are not authorization decisions.

## Security and limits

Both listeners only accept loopback IP bind addresses, reject foreign Host/Origin
headers and send no CORS permission. The dashboard uses only GET requests to the
audit source, refuses redirects, bypasses proxies and bounds response size/time.
Assets have a same-origin CSP, no-store and nosniff headers. DOM content uses
`textContent`, never interpreted HTML.

The approval decision route is the single write path. It accepts a POST only from
this page on this machine: the Host must be a literal loopback address, the Origin
must match it exactly and fetch metadata must not mark the request cross-site. The
dashboard validates the approval id and decision shape, then forwards the operator's
bearer token to the gate's `/v1/approvals` routes. The gate re-authenticates the
operator on every call, publishes the signed decision receipt before the decision
takes effect, and the approval store applies it exactly once. The token lives in the
page's memory; reloading or "Forget token" discards it, and it is never written to
disk, localStorage or the audit log.

Local users/processes are inside this trust boundary; loopback is not authentication
for reads. For decisions, the gate's OIDC operator token is the authentication. Use
OS account isolation for multi-user hosts. Do not forward either port publicly.

This bounded memory log is not durable, cryptographically signed, complete historical
SIEM export, or a substitute for the chained bus receipts. It resets on gate restart.
Telemetry lock failures show unknown and never grant an action. Existing gate policy,
receipt enforcement and SIEM behavior are otherwise unchanged.

## Verify

```sh
cargo test --workspace
cargo clippy -p membrane-dashboard --all-targets
```

For a local visual fixture only, without relay setup or tool execution:

```sh
cargo run -p membrane-gate --example audit-preview
# In another terminal, run membrane-dashboard as above.
```

The example emits three synthetic decisions and an idle policy view. It must not be
used to represent a production gate. Stop the example before starting the operator gate.

## Alarm delivery

The gate raises an alarm for four conditions that have a clock on them, and only these:

| Alarm | Raised when |
| --- | --- |
| `stuck_agent` | An identity that was previously allowed has been denied continuously for `MEMBRANE_ALARM_STUCK_SECS` (default 900) and is still retrying. |
| `deny_spike` | At least `MEMBRANE_ALARM_SPIKE_MIN_DENIES` (default 10) denials make up at least `MEMBRANE_ALARM_SPIKE_MIN_RATE` (default 0.5) of decisions inside `MEMBRANE_ALARM_SPIKE_WINDOW_SECS` (default 300). Re-arms once the window clears. |
| `grant_expiring` | A grant with a window is within `MEMBRANE_ALARM_GRANT_LEAD_SECS` (default 86400, one day) of its end and has not expired yet. Raised once per grant and expiry time; renewing the grant to a new expiry arms it again. Already expired grants raise no alarm, since their denials appear in the decision log as `grant_window`. |
| `first_seen_identity` | A key-verified caller identity makes its first request since the gate started. List identities in `MEMBRANE_ALARM_KNOWN_IDENTITIES` (comma-separated public keys) to exempt them. |

Set `MEMBRANE_ALARM_WEBHOOK_URL` to deliver each alarm as a JSON POST (`kind`, `identity`,
`summary`, `raised_at`, plus a chat-compatible `text` field). The URL must be `https`, or a literal
loopback address for a local relay. `MEMBRANE_ALARM_WEBHOOK_SECRET` is sent in
`MEMBRANE_ALARM_WEBHOOK_SECRET_HEADER` (default `X-Membrane-Alarm-Secret`). Delivery makes three
attempts.

Alarms are derived from the bounded audit log and are observational: they never feed an
authorization decision. Invalid alarm settings stop the gate at startup. A delivery that is
rejected or unreachable is recorded as `failed`, never `delivered`, and with no webhook set the
status is `not_configured`. Alarms and their delivery status appear in the loopback `/audit`
snapshot under `alarms`. The audit log holds the last 500 decisions, so a streak older than that is
measured from its oldest retained decision.

## Readings

The `/audit` snapshot includes `readings`, computed by the gate from its retained decisions, and the
dashboard shows them under the decision log. Readings are for spotting drift in the allow log, not
only the denials:

- Denials by rule clause.
- Callers: allows and denials per key-verified identity, and each identity's allow volume in the
  last hour compared with its hourly rate over the retained time before that (`volume_ratio`, shown
  only once the retained baseline covers at least one hour).
- Action types with allow and deny counts, and action types seen in the last hour that are absent
  from the earlier retained decisions.
- Decisions with no verified caller identity, counted separately.

Readings describe the retained decisions only: the last 500 in this process. The snapshot reports
how many older decisions are no longer retained (`coverage.dropped`) and the time span covered, and
the dashboard shows both. They are observational and never feed an authorization decision. Grant
and policy changes are not part of the decision log, so they are not in these readings.
