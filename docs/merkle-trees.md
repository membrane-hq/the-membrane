# Merkle trees: set commitments and the ordered receipt log

Status: implemented. The set commitment tree (§2) is implemented in
`membrane-core/src/merkle.rs`. The ordered log tree (§3) is implemented in
`membrane-core/src/log_tree.rs` (construction, signed tree head, inclusion and
consistency proofs) with CLI access via `membrane log`; `RollupBundle` carries
`log_root`/`log_size` per §3.6 and the §3.7 vectors live in
`membrane-core/tests/data/log_tree_vectors.json`.

This document resolves the design discussion in
[issue #62](https://github.com/membrane-hq/the-membrane/issues/62): the sorted,
odd-leaf-duplicating construction is kept and documented as a *set* commitment,
and a separate ordered tree carries every claim that involves leaf count,
sequence, or third-party verification. No existing root changes meaning.

## 1. Two constructions, two guarantees

| | Set commitment tree | Ordered log tree |
|---|---|---|
| Purpose | Commit to a set without disclosure | Commit to an append-only sequence |
| Leaf order | Sorted by digest | Append order |
| Odd leaf | Duplicated | Never duplicated |
| Leaf/node separation | None | `0x00` leaf / `0x01` node + versioned tag |
| Commits to count | No | Yes |
| Commits to order | No | Yes |
| Inclusion/consistency proofs | Not defined | RFC 6962-style (§3.4, §3.5) |
| Used for | Channel/context, witness, bus and CP-rollup roots | Receipt log, anchored period roots |

Rule of thumb: a set root says "these inputs, no others". It never says "exactly
this many" or "in this order". Only an ordered-log root may be presented as
evidence of an exact count or sequence.

## 2. Set commitment tree (implemented)

Byte-level construction, matching `membrane-core/src/merkle.rs`:

- Leaf: `SHA-256(domain_byte || data)` with `domain_byte` in
  `0x00` feature chunk, `0x01` bus event, `0x02` CP hash, `0x03` witness key.
  (`from_domain_leaves` keeps caller order; `from_prefixed_leaves` sorts the
  digests lexicographically.)
- Parent: `SHA-256(min(l, r) || max(l, r))` — children are ordered
  lexicographically before hashing.
- Odd node out: the last node at a level is paired with itself.

**Guarantee.** Given the same inputs, an honest recomputation yields the same
root if and only if the input *sets* match. This is exactly what the current
verifiers need: bus and CP-rollup roots are recomputed from the full event log,
and channel/witness roots are proven inside a STARK over witness chunks. The
verifier already holds every leaf.

**Non-guarantees.**

- Count: `[a, b, c]` and `[a, b, c, c]` share a root (the duplicated leaf is
  the post-sort maximum digest).
- Order: sorted leaves and pair-sorted parents commit to no sequence.
- Type: a leaf digest is not domain-separated from an internal node digest, so
  the construction does not support proving one leaf's membership to a party
  that does not hold all leaves.

These are properties of the construction, not defects to patch in place:
changing any of them would alter every existing root. Where they matter, use
the ordered log tree.

## 3. Ordered log tree v1 (specified)

### 3.1 Domain tags

```text
LOG_DOMAIN   = "membrane-log/v1"          (ASCII, 15 bytes, no length prefix)
leaf_hash(e) = SHA-256(0x00 || LOG_DOMAIN || e)
node_hash(l, r) = SHA-256(0x01 || LOG_DOMAIN || l || r)
sth_msg(size, root, ts) = SHA-256(0x02 || LOG_DOMAIN || u64be(size) || root || u64be(ts))
```

The version tag is part of every hash. Any change to tags or construction is a
new tag (`membrane-log/v2`, ...); v1 roots remain valid and verifiable forever.
Existing set-tree roots are untouched.

### 3.2 Tree construction

Leaves are the period's receipts in append order. The entry `e` is the
canonical receipt bytes — the same canonicalization the receipt's signature
covers.

```text
MTH({})        = SHA-256("")                       (empty tree)
MTH({e})       = leaf_hash(e)
MTH(D[0:n])    = node_hash(MTH(D[0:k]), MTH(D[k:n]))
                 where k = largest power of two strictly less than n
```

This is the RFC 6962 §2.1 Merkle Tree Hash with our domain separation. Because
no leaf is ever duplicated, the root commits to the exact leaf count, and
because leaves sit in append order, it commits to the sequence.

### 3.3 Signed tree head (STH)

```text
STH = {
  tree_size:  u64,
  root:       32 bytes,           // MTH of the first tree_size entries
  timestamp:  u64,                // unix seconds
  signature:  Sign(node_key, sth_msg(tree_size, root, timestamp))
}
```

The operator signs the STH with the same node key that signs bus events. STHs
are published to the attestation bus so witnesses and replicas can hold the
operator to a single history: two conflicting STHs at overlapping sizes with no
valid consistency proof between them are proof of equivocation.

### 3.4 Inclusion proof

For leaf index `m` (0-based) in a tree of size `n > m`, the audit path is the
RFC 6962 §2.1.1 `PATH(m, D[n])`:

```text
PATH(m, {e})     = {}                                (empty path)
PATH(m, D[0:n])  = PATH(m, D[0:k])     ++ {MTH(D[k:n])}   if m < k
                 = PATH(m - k, D[k:n]) ++ {MTH(D[0:k])}   if m >= k
                 where k = largest power of two strictly less than n
```

A proof carries `(leaf_index, tree_size, path[])`. The verifier recomputes the
root from `leaf_hash(entry)` and the path using the index bits to order each
concatenation, then accepts if the result equals the STH root and the STH
signature verifies. Verification needs the one receipt, the proof, and the STH —
not the log.

### 3.5 Consistency proof

For sizes `m < n`, the proof that the size-`m` tree is a prefix of the size-`n`
tree is the RFC 6962 §2.1.2 `SUBPROOF(m, D[n], true)`:

```text
SUBPROOF(m, D[n], b):
  if m == n:   return {} if b, else {MTH(D[m])}
  k = largest power of two strictly less than n
  if m <= k:   return SUBPROOF(m, D[0:k], b) ++ {MTH(D[k:n])}
  else:        return SUBPROOF(m - k, D[k:n], false) ++ {MTH(D[0:k])}
```

A verifier holding an old STH checks the new STH's signature, then recomputes
both roots from the consistency proof. Append-only growth is thereby auditable
between any two anchored points.

### 3.6 Anchoring

`RollupBundle` gains two fields during transition:

```text
log_root   // MTH over the period's receipt entries (§3.2)
log_size   // u64 leaf count
```

`cp_chain_root` and `last_bus_root` remain set-tree roots (§2) until the log
tree is deployed; `ots_digest` covers the full canonical bundle including the
new fields, so the daily OpenTimestamps stamp binds the ordered root into
Bitcoin. End-to-end third-party verification of one receipt: inclusion proof →
`log_root` → signed bundle → OTS proof → Bitcoin.

### 3.7 Test vectors

The implementation change ships JSON test vectors covering: empty tree, single
leaf, two leaves, odd and even counts around power-of-two boundaries (1..9
leaves), a domain-separation negative (leaf bytes reinterpreted as a node must
not verify), an inclusion proof at each position of a 9-leaf tree, and a
consistency proof between sizes 6 and 9.

## 4. Out of scope here

- Operator-held signing keys and key ceremony (tracked separately).
- Declared anchor cadence and missed-anchor alerting (tracked separately).
- The STARK circuits of the research specification; the ordered log tree does
  not depend on them.

## 5. References

- RFC 6962, *Certificate Transparency*, §2.1 (tree hash, audit paths,
  consistency proofs).
- CVE-2012-2459 (Bitcoin odd-leaf duplication) — the ambiguity class the set
  tree documents and the log tree excludes by construction.
- [Issue #62](https://github.com/membrane-hq/the-membrane/issues/62).
