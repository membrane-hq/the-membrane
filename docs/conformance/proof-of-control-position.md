# Proof-of-Control position statement - the Membrane

This statement describes how the Membrane maps to the Proof-of-Control draft standard. It is not a conformance claim and not a certification. "Proof-of-Control Certified" is a protected certification mark and nothing here uses it. Until the accredited-assessor body exists, a system is described as placed at a conformance stage, not certified; this statement is a Self-Declared placement. Public wording stays "maps to / building toward".

## Required fields

- **System:** the Membrane (github.com/membrane-hq/the-membrane), a self-hosted, fail-closed authorization gateway for AI agents.
- **Version:** v0.1.0 and later; this statement was graded against main @ 9e357a3 (2026-11-09).
- **Environment:** operator self-hosted deployments per docs/reference-stack.md and docs/edge-deployment.md.
- **Standard:** Proof-of-Control Working Draft v0.1, LFDT-ProofOfControl/ov-poc-standard @ 54a7bc6. Requirements are cited version-qualified (for example v0.1-C4.1.1).
- **Claim date:** 2026-11-11.
- **Conformance stage:** Self-Declared. The operator attests; no third party has assessed the system.
- **System surface framework:** MAESTRO, the Cloud Security Alliance seven-layer agent-stack model, as reproduced in ov-poc-standard C9. MAESTRO carries no numbered version; the C9 layer definitions are the reference used.
- **Claim register:** docs/conformance/claim-register.json, machine-readable, with its schema at docs/conformance/claim-register.schema.json. Every verifiable fact asserted in this statement resolves to at least one register entry.
- **Grading basis:** "met" means implemented as the requirement reads and verifiable in the public repo today. It does not mean independently audited.

## Domains claimed

- **C4 Authorization** - claimed, Tier 2. The strongest domain: grant-before-action, per-action evaluation, block-not-flag, per-task short-lived credentials, recorded approvals, and delegation-scope intersection all hold in code and docs.
- **C7 Evidence Generation and Properties** - not a claimable domain; it is the evidence axis. The register lists, per claim, the C7 properties the claim's evidence meets.
- **Not claimed:** C1 Provenance, C2 Privacy, C3 Portability, C5 Identity, C6 Security. These sit outside what an authorization gateway does, and nothing in the project's repo, site, or public comments claims them.

## Tier reached, and why

All claims are registered at **Tier 2**. Evidence is signed under operator-held keys, and a single trusted party caps a claim at Tier 2 (v0.1-C8.1.3). The receipt chain is verifiable after the fact, which would permit Tier 3 at most (v0.1-C8.1.6); the project claims Tier 2, the conservative placement. The Tier 3 blockers are disclosed below, unchanged from public comment LFDT-ProofOfControl/ov-poc-standard#139.

## System boundary and scope (v0.1-C10.1.6)

**In scope:** membrane-gate (interception, policy evaluation, dispatch), membrane-core (IACs, bus events, receipts, canonicalization), the durable journal, the hardened SIEM export, the approval gates, the read-only advisor, and the reference edge deployment. **In-scope action classes:** agent tool and effect calls routed through the gate under operator-issued, caller-bound IACs.

**Excluded action classes, with rationale:**

- **Model artifact and serving verification** - the model server is outside the gate's trust boundary (docs/reference-stack.md); the gate authorizes calls by exact model identifier but does not verify weights or manifests. C1 is not claimed.
- **Agent traffic not routed through the gate** - coverage is limited to gate-routed traffic (docs/siem-export.md); unrouted agents produce no receipts and are out of scope.
- **Execution outcomes** - receipts attest request intent at decision time, not runtime execution success (docs/audit-fixes.md). Signing-time claims are kept separate from runtime claims (v0.1-C8.2.2).
- **Private downstream deployments** - separate, private work; outside this public statement.

## Effect-channel mediation (v0.1-C7.1.4)

Closest to option (c): the gate itself dispatches every admitted call, holds all upstream credentials (GitHub token, Routstr key - never agent-visible), and the reference deployment confines egress to the gate (docs/edge-deployment.md). There is no attested enforcement point and no single-use capability bound to an evaluated snapshot digest.

## Mechanisms used

| Mechanism | What it proves here | What it does not prove |
| --- | --- | --- |
| Operator-signed IACs (Schnorr/secp256k1 over SHA-256) | Origin and scope of a grant at issuance time | Runtime behavior under the grant |
| Per-request caller proofs (timestamp, nonce, audience, route and body binding) | The caller holds the key and made this exact request | Anything about requests never sent |
| Hash-chained receipts and journal | Tamper-evident ordering of the operator's record | Independence from the operator; inclusion or consistency to an outside verifier (see #62) |
| Monotonic sequence numbers on export | Gap detection between gate and SIEM | Completeness against actions never routed through the gate |
| Fail-closed evidence pipeline | Actions stop when evidence cannot be written | Anything when the pipeline is healthy but the policy is wrong |
| Machine-readable JSON Schemas (schemas/) | The exact shape of every evidence record | Canonicalization completeness (see v0.1-C7.7.2/7.7.3 notes in the register) |

## Trust-assumption disclosure (v0.1-C10.2)

Per claim, matched one-to-one against the mechanisms above. Categories are drawn from the draft set: Hardware, Mathematical, Ceremony, Vendor, Implementation, Distributed.

| ID | Subject | Category | Assumption |
| --- | --- | --- | --- |
| TA-1 | Operator-held signing keys | Implementation | The operator controls the keys that sign IACs and receipts. A compromised operator key can forge evidence. This caps every claim at Tier 2. |
| TA-2 | SHA-256 and Schnorr/secp256k1 | Mathematical | Collision resistance and signature unforgeability hold. Algorithm identity is pinned by schema version, not per-field tags. |
| TA-3 | Operator-run relay | Implementation | Chain-head publication depends on a relay the operator runs. It is not an independent witness and provides no equivocation resistance. |
| TA-4 | Operator's OIDC identity provider | Vendor | Approval records are only as strong as the IdP's authentication of the approver. |
| TA-5 | Host OS and filesystem | Implementation | Evidence stores are local files under OS permissions; there is no role-based access and no read auditing of evidence. |
| TA-6 | Reference deployment confinement | Implementation | No-bypass (v0.1-C7.1.1) holds where the reference deployment confines backend access, CI-verified in deploy/edge/verify.sh; other deployments must reproduce it. |

Hardware assumptions: none (no TEE, TPM, or HSM). Ceremony assumptions: none. Distributed assumptions: none.

## Retention (v0.1-C7.6.5)

The journal retains full history without compaction (docs/durable-journal.md). No fixed retention period is configured, and none is claimed.

## Known gaps (disclosed, not claimed)

- **Operator-held signing keys (v0.1-C7.3.2)** - the Tier 2 ceiling, as disclosed in #139.
- **No scheduled external anchoring (v0.1-C7.2.2, C7.6.6)** - the OpenTimestamps rollup exists (membrane-core/src/ots.rs) but is optional, excluded from air-gap builds, and runs on no declared interval with no missed-deadline alert.
- **No inclusion or consistency proofs (v0.1-C7.3.4, C7.3.5)** - the Merkle defects tracked in membrane-hq/the-membrane#62: odd-leaf duplication, sorted leaves, no domain separation, no commitment to count or order, and no published inclusion-proof API.
- **No equivocation resistance (v0.1-C7.3.3)** - chain heads publish to an operator-run relay; no gossip, witness quorum, or ledger.
- **No hardware binding or attestation (v0.1-C7.2.4 and the C6 hardware items)**.
- **Authorization gaps:** no generic tool-schema validation (v0.1-C4.1.4 - only the shipped GitHub tools and spend), no path-aware composition (v0.1-C4.1.7), single-hop delegation only (v0.1-C4.2.2), no confidential delegation (v0.1-C4.2.4).
- **One signed record per decision point (v0.1-C7.1.2)** - not three independently signed before/during/after records; raised with the working group as a cost question.
- **Evidence parsing:** duplicate JSON object keys resolve last-wins (v0.1-C7.7.5).

## Claims review

Public materials describe receipts as execution facts only and use "maps to / building toward" language; no Proof-of-Control conformance or certification claim appears anywhere (v0.1-C8.1.4, v0.1-C7.5.2). Changes to public claims are reviewed against this statement before publishing.

## What this statement is not

Not a conformance claim, not a certification, not third-party assessed. Every evidence citation points at the public repo; readers can verify each claim there today.
