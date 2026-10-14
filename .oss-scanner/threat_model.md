# The Membrane security-analysis scope

The Membrane is a self-hosted, fail-closed authorization gate for AI-agent requests.
Its Rust workspace contains membrane-core, membrane-gate, membrane-cli,
membrane-dashboard and membrane-advisor. Analyze the current implementation, not
unimplemented components described in the research specification.

## Trust boundaries and priorities

Treat caller requests, proof headers, tool bodies, upstream responses, relay
events, imported receipts and malformed configuration as potentially hostile.
Prioritize authorization bypass, cross-caller or cross-scope access, forged or
replayed proofs and receipts, revocation/liveness bypass, duplicate dispatched
effects, approval-gate bypass, credential exposure and fail-open recovery.
Inspect parsers, signature/canonicalization boundaries, persisted journals,
concurrent operations, HTTP routing, operator OIDC and outbound connectors.

Operator signing keys and policy administration are trusted authority. Distinguish
an attacker crossing an enforced boundary from an operator intentionally granting
permission or an already-compromised signing key. A compromised key may still
expose a separate boundary defect; explain which capability is needed.

## Existing assumptions and limits

Read SECURITY.md and docs/caller-identity.md, docs/durable-journal.md,
docs/approval-gates.md, docs/audit-fixes.md and docs/siem-export-hardened.md.
Scope checks cover requests routed through the gate, not direct upstream access.
Do not treat simulated demo effects as proof of production security. BCI, zk-STARK
and TEE proposals are not implemented. Explain any finding against the current
code and its documented trust assumptions rather than inferring broader claims.

## Offline reproduction

The image keeps the full checkout in /src, toolchain and Cargo dependency cache.
Run cargo test --workspace --frozen and cargo test --workspace --all-features
--frozen. Test fixtures and examples remain in the checkout. Ordinary tests use
local fixtures or loopback mock servers where external services are involved.
Do not enable ignored live-GitHub integration tests or use production credentials,
real relays, real API accounts or payment services. Reproduce connector defects
against loopback mocks with synthetic credentials.

## Reports

Provide affected commit, component, required attacker capabilities, expected and
observed behavior, a minimal offline reproducer and a regression test or candidate
patch where possible. Distinguish demonstrated impact from theoretical impact.
Group reports sharing one root cause and identify duplicates of documented limits.
Use exploit preconditions and demonstrated impact to explain severity; do not
assume a deployment scale or user base not documented by the project.
