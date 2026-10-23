# Caller-bound IACs and identity grants

The operator still signs the IAC using the existing Schnorr/canonical-JSON mechanism.
`caller_pubkey` is now part of that signed view. The caller holds a separate key and
proves possession on every production chat or tool request. An IAC is not a bearer
credential: copying it is insufficient to act.

## Operator setup

1. Put the caller's lowercase, 64-hex public key in `identities` in the channel registry.
   Give exact scopes, channels, models, tools and repositories. No wildcard matching.
   Missing lists grant nothing; an absent identity or `revoked: true` denies.
2. Issue with the operator key: `membrane iac issue --caller-pubkey <caller-key>
   --scope-id pilot-scope --model <model> --tool github.comment --out iac.json`.
   Relay and signing-key options remain as before. Do not give the operator secret to an agent.
3. Start the gate with the registry and signed IAC as before. The CLI start path
   rereads identity grants on each production authorization and again immediately
   before dispatch. Edit the file atomically (temporary file then rename).
4. Invoke using the caller key: `membrane tools invoke --gate-pubkey <operator-key>
   --iac iac.json --tool github.comment --model <model> --owner <owner> --repo <repo>
   --issue-number 1 --operation-id <stable-write-id> --body <comment>`. Supply the caller secret through the existing
   `NOSTR_NSEC_FILE` or `--nsec-file` pointing to a private, untracked file.
   See [signing-key handling](signing-key.md) for precedence and legacy sources.

The local chat command is the self-caller case (operator and caller keys equal).
It binds new session IACs and sends proofs automatically. Its generated scope still
needs an explicit registry grant. Distinct agents use operator-issued IACs, not
self-issued authority; the tool CLI supports separate operator/caller keys.

## Request proof

Fetch `/health` for `caller_audience` (operator key plus a fresh process challenge).
The `X-Membrane-Caller-Proof` JSON has `timestamp`, `nonce`, `signature`. Sign the
SHA-256 digest of the canonical JSON produced by `membrane_core::caller::CallerProof`:
domain `membrane/caller-proof/v1`, audience, POST, exact route, typed request body,
IAC signable hash, timestamp and random 64-hex nonce. The Rust helper is the reference.
The gate uses the deserialized request shape, including serde defaults/null fields.
Use the typed `ChatRequest` or `ToolInvokeRequest` when signing.

Proofs cannot be future-dated and expire after 60 seconds. Nonces are consumed after
signature verification, even if policy later denies. A mutex-protected cache denies
replay and fails closed at 10,000 retained entries. A restart rotates the audience,
so a captured old proof does not revive. Use one gate process per audience; this is
not a shared multi-replica replay store. Use TLS outside localhost. Proofs do not
hide request content and do not protect a compromised caller private key.

## Authorization and revocation

Permission is the intersection of the operator-signed IAC, loaded global policy,
current registry identity grant and existing liveness/export/context checks. No
identity grant expands the IAC or bypasses an existing clause. Registry reread
errors deny; an unavailable replay cache denies. Production has no identity-free
fallback, including when a default IAC is configured. Old unbound IACs remain
parseable for historical/demo data but production requests deny until reissued.
The demonstration remains simulation-only and does not exercise caller auth.

### Time-boxed grants

An identity grant can carry an optional window, in Unix seconds:

```yaml
identities:
  <64-hex caller key>:
    scopes: [pilot-scope]
    not_before: 1791100000   # usable from this time
    expires_at: 1791186400   # stops working at this time (exclusive)
```

Both fields are optional; a grant with neither is a standing grant, as before. Instead of
`expires_at`, a grant can give a length counted from `not_before`:

```yaml
    not_before: 1791100000
    valid_for: 24h           # s, m, h or d; whole numbers only
```

`valid_for` needs `not_before` and cannot be combined with `expires_at`. The window is still
absolute once written, so the registry file means the same thing whenever it is read (a length
counted from "now" would renew itself on every hot reload). Zero, unknown units, decimals, a
missing `not_before`, both forms together and overflow all deny. The gate raises a
`grant_expiring` alarm before a window ends; see the operator dashboard doc. Outside the window
the request is denied with rule `grant_window`, which the audit log, readings and advisor report
separately from `identity_grant`. A contradictory window (`expires_at` not after `not_before`)
denies at every time, and so does an unreadable system clock. The window is read on every
authorization, so it applies with registry hot reload and needs no restart. A window only narrows:
it never adds a scope, channel, model, tool or repository, and the intersection with the signed IAC
and global policy still applies. An expired grant is not renewed automatically; renewal is an
operator edit of the registry.

Set `identities.<key>.revoked: true` or remove the key. The next authorization sees
that change without restarting. Revocation is not retroactive: an already-dispatched
connector call cannot be recalled, and a file edit racing the final check can win
just after it. There is no dashboard write endpoint. Library embedders must use
`with_identity_registry_path` for hot reload; without it grants are immutable for
that Gate instance. Global connector/config changes still require restart.

## Audit and advisor

`Decision.agent` remains the gate signer for compatibility. New optional
`authenticated_identity` is the verified caller key on allows and on denials after
proof verification (including unknown/revoked identity). Authentication failures
leave it absent, never record an attacker-claimed key as authenticated.
`/audit` exports the same field. Old snapshots still parse. The advisor groups by
caller and can recommend exact-key revocation for review; it never auto-grants or
un-revokes from a denial and does not generate global-widening patches for
identity-attributed denials. This bounded observational log is not a receipt store.

## Tests

`cargo test --workspace`: caller/operator separation, wrong caller signature,
tampered caller binding, wrong body/route/audience, stale/future/unbound proof,
replay, unknown/revoked identity, permission intersection, live registry edits and
broken/missing registry, plus HTTP handler audit attribution and advisor grouping.
The live GitHub connector test stays ignored unless explicitly enabled.

## Re-issuing an IAC

An IAC is operator-signed and short-lived, so it expires or stops matching the
registry. Re-issue is an operator command, never an automatic one:

```
membrane iac reissue --previous old-iac.json --ttl-secs 3600 --out new-iac.json
```

- The previous IAC must verify against the operator key (`NOSTR_NSEC`). An unsigned,
  tampered or foreign credential is refused, even if it has already expired.
- Scope, caller binding, models, tools, channels, export restrictions and context
  bound are copied unchanged. Only `valid_until` and `parent_cp_hash` (the current
  chain head) change.
- Widening is explicit and narrow: `--add-model`, `--add-tool`, `--add-channel`, one
  exact identifier each. Wildcards, spaces and path tricks are refused. Forbidden
  exports cannot be removed.
- The lifetime is capped at 7 days. `--out` must differ from `--previous`.
- The command prints every difference, publishes an authorization event that
  records `supersedes_iac_hash`, and writes the new file. The gate reads its IAC at
  start, so restart it with the new file.
- Limit: the old credential is not revoked. It stays valid until its own
  `valid_until`. To cut access off sooner, revoke the identity grant in the
  registry.
