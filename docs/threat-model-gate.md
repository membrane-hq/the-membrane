# Gate threat model
Scope: the authorization gate in this repository (membrane gate start, the CLI, the GitHub connector, the operator dashboard and the journal). It does not replace the research threat model in whitepaper.md, which covers the cognitive-boundary specification and is not implemented here.
Status: early-stage software, not production-proven, no external audit. Describes main at commit 1a91c24.
## What the gate protects
- Tool and model calls an agent can make through the gate, and the authority behind them (operator-signed IAC, registry grants).
- The operator signing key, caller keys and the connector token.
- The receipt chain, the intent journal and the audit log.
## Actors and trust boundaries
| Actor | Trust |
| --- | --- |
| Operator | Trusted. Holds the signing key, edits the registry, approves held calls through OIDC. |
| Caller (agent runtime) | Untrusted. Holds only its own caller key and an operator-issued IAC. |
| Model backend | Untrusted. Unreachable backend denies. |
| Upstream (GitHub) | Where effects happen. Reconciliation only reads. |
| Relay | Carries receipts, severance and alerts. |
| Network attacker | Untrusted. |
Boundaries: caller to gate (signed proof on every production request); gate to upstream (allowlisted tools and repositories, token held only by the gate); gate to relay; operator to gate (OIDC); gate to the loopback-only audit listener and dashboard.
## Threats, controls and remaining limits
| Threat | Control | Remaining limit |
| --- | --- | --- |
| Stolen or copied IAC | IAC carries a caller key; every request needs a proof of possession. | A compromised caller private key is not protected. |
| Replay of a captured request | Proof must be at most 60 s old and not future-dated; nonce consumed per caller; a full or poisoned cache denies; the audience includes a random per-process value, so a restart rotates it. | In-memory cache, one gate process per audience, no shared replay store, a single 10,000-entry cap. |
| Caller exceeds authority | Permission is the intersection of IAC, policy and registry grant; an unreadable registry, an unknown identity and a revoked identity all deny; grants can be time-boxed. | Revocation is not retroactive; a dispatched connector call cannot be recalled. |
| Misconfigured registry | Default registry denies all; no wildcards; validate and diff before apply. | A valid but wrong policy is not detected. |
| Unknown or duplicate write after a crash | Operation IDs are reserved and journaled before dispatch; frames are sequence-numbered, hash-linked and flushed; an OS lock on instance.lock excludes a second process; corrupt or torn records block the gate; reconciliation only reads upstream. | One instance per journal. Checksums are not keyed, so a privileged local attacker can rewrite history. Losing or rolling back the volume loses the guarantees. Reconciliation cannot prove who caused an effect. |
| Dispatch after severance or stale session | Every live tool dispatch re-reads operator relay events (up to the latest 5,000) and denies if the relay cannot be read; a stale session is denied and a degraded alert is published. | Relay checks are skipped for memory:// and local:// relay URLs (test and demo). A sever that arrives after the check does not stop an in-flight call. An event beyond the 5,000 window, or silently omitted by the relay, may be missed. |
| Fake operator | Issuer and JWKS URL are set by the operator (HTTPS, no credentials, no redirects, 5 s timeout); RS256 only; zero clock leeway; issuer, audience, expiry and subject required; the identity claim must map to a configured operator; requested IAC lifetime is 1 to 300 s, with actual expiry bounded by token expiry and the caller grant's window, and cannot exceed the caller's registry grant (scopes, models, channels, tools). | A mapped operator can issue IACs up to what the caller grant allows. Serve the production listener behind TLS. Not exercised against a live Okta or Entra tenant. |
| Operator key or connector token exposure | Signing key is read from a private file with permission checks; the file source wins over raw values and a bad file never falls back. The connector token is held in redacted types, with no redirects and an exact host check. | Legacy raw --nsec and NOSTR_NSEC are still accepted and can leak through process listings, shell history or /proc. Not remote signing or vault delivery. |
| Out-of-scope call | Blocked, or held for a one-shot operator approval bound to the exact call. | Single approver, no multi-approver rule; tool calls only. |
| Exfiltration through allowed calls | Forbidden-export declarations and lexical context bounds. | Not semantic exfiltration prevention; content and provider retention are not inspected. |
| Direct upstream access | None. | The gate only constrains requests routed through it. |
| Dashboard or audit listener abuse | Loopback only, GET-only audit, Host and Origin checks, no stored operator token. | Do not expose through a reverse proxy. |
| Telemetry tampering or leakage | Hash-chained spool, TLS with explicit CA bundle, optional leaf pin, digest-only events. | Telemetry only; it never changes a decision. |
| Vulnerable dependencies | Blocking cargo audit and secret scanning, clippy, dependabot. | No fuzzing. |
## Assumptions
- The operator protects the signing key, registry file, journal volume and host.
- One gate process serves one audience and one journal.
- TLS is provided outside localhost.
- Only registered channels are seen.
## Out of scope for this model
A compromised host; a caller key stolen before revocation; settlement adapters (mock-tested only, no keys here); the simulated demo; research components in the whitepaper.
## Not yet tested
Live relay end to end, live Okta or Entra, power-loss and filesystem fault injection, fuzzing, multi-process stress, and a clean installation with a real registry image and model.
