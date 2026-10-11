# Recommendation advisor

`membrane-advisor` turns gate denials into a reviewable policy patch. It is
deterministic (no model, no network, no randomness), read-only (it prints text, it
never opens the registry for writing), and advisory (a human applies and merges the
patch through normal code review).

## Use

```sh
curl -s http://127.0.0.1:8788/audit | \
  cargo run -q -p membrane-advisor -- --registry tools/channel-registry.example.yaml
# Only the diff, for `git apply`:
... --format patch
# Ignore one-off denials:
... --min-denials 3
```

Run from the repo root with a repo-relative registry path so the diff headers apply
with `git apply`. `--snapshot FILE` reads a saved snapshot instead of stdin.

## What it recommends

| Rule | Output |
| --- | --- |
| `repository_allowlist` | Patch adding the one exact `owner/name` to `github_repo_allowlist` |
| `model_allowlist` (not in registry) | Patch adding the one exact model id to `model_allowlist`; the signed IAC must also list it |
| `model_allowlist` (already in registry) | Advice: the IAC is what denies; re-issue it |
| `tool_allowlist`, `iac_validity`, `channel_allowlist`, `export_restriction`, `context_bound` | Advice: these live in the signed IAC, which a text patch cannot change |
| `iac_signature` | Investigate. Never a policy change |
| `session_stale`, `session_degraded`, connector faults | Operate. Never raise `delta_t_secs` to hide it |

Every recommendation is conditional: if the denied call was not intended, change
nothing, the denial is the gate working.

## Safety rules

- **Narrowest change.** One exact entry per patch. No wildcards, ever.
- **Hostile input.** The denied model, tool and repository names are caller-chosen
  strings. A name enters a patch only if it is a plain identifier or `owner/name`;
  anything else (wildcards, newlines, spaces, `..`) gets advice and no patch. The
  edited registry is re-parsed and compared: only the intended list may change.
- **Unsupported shapes are refused.** Inline lists (`[a, b]`) are not rewritten.
- **Review-by comment.** Added global allowlist entries carry a `review by
  <date>` comment (snapshot time plus 7 days). The comment is a reminder, not
  enforcement. Identity grants support enforced `not_before`, `expires_at` or
  `valid_for` windows; IACs also have `valid_until`. See [caller
  identity](caller-identity.md). A global allowlist comment does not set a window.
- **Per-identity review.** Caller-bound IACs and proof-of-possession authenticate
  exact caller keys. The advisor groups denials by `authenticated_identity` and
  can recommend exact-key revocation for review. It does not auto-grant,
  un-revoke or widen global policy for identity-attributed denials. `grant_window`
  denials get window/renewal advice; renewal stays an operator decision.

## Gate change

`Decision` in the audit snapshot gains an optional `subject`: the model, tool or
repository a denial named, control characters dropped and capped at 128 characters.
It is observational only and never an authorization input. Older snapshots without
it still parse; the advisor then says the log has no subject.

## Optional model triage (advisory)

The deterministic pass above is the advisor. A decision model can be added on top to
triage each denial group, and it is off unless you pass `--model-config <file>`.

What the model can do: answer one fixed yes/no question per rule ("is this pattern most
likely a legitimate caller missing an allowlist entry, rather than probing?") and have
that attached to the report as a note: `likely_misconfiguration`, `likely_probe` or
`unclear`, with the probability. That is all. A note never creates, changes or removes a
recommendation or a patch, and no label means allow. Renewal, IAC re-issue and registry
changes stay operator acts. The gate never reads any of this.

What the model sees: a small summary per rule (rule name, denial count, number of distinct
subjects and identified callers). No raw log lines, no caller-chosen names, no credentials.

What comes back is validated against a fixed schema. Wrong type, out-of-range number,
missing or extra question ids, bad JSON, a timeout or an HTTP error: the note is dropped
and the report is unchanged. Each note records the backend and the model version the
backend echoed, so a run can be replayed against the same model.

### Backends

Clef and Jev both take the same request, a `state` plus typed `questions`
(`choice`, `score`, `noul`), and return `answers` under the same ids. Only the URL, the
token and the model string differ, so the backend is one config file:

```json
{ "backend": "clef_local", "url": "http://127.0.0.1:8000/v1/systemone", "model": "clef-flash" }
```

```json
{ "backend": "clef_workers_ai", "account_id": "<id>", "token_env": "CF_API_TOKEN", "model": "clef" }
```

```json
{ "backend": "jev_api", "token_env": "TYPESAFE_API_KEY" }
```

- `clef_local` is the default choice: open weights, runs on your hardware, no secret. The
  URL is whatever your local server exposes. Membrane does not ship or pin a server; check
  that your server speaks the shape above. The GPU requirement belongs to that server,
  not to the gate or the advisor.
- `clef_workers_ai` and `jev_api` are hosted. Tokens are read from the named environment
  variable, never from the file, and a missing variable is an error.
- Plain `http://` is accepted only for loopback. Anything else must be `https://`.

```sh
curl -s http://127.0.0.1:8788/audit | cargo run -q -p membrane-advisor -- \
  --registry tools/channel-registry.example.yaml --model-config advisor-model.json
```

Adding another backend means implementing the `Backend` trait in
`membrane-advisor/src/seam.rs`; nothing else changes.
