# Memory as policy

Status: design direction. This note proposes a memory-policy boundary alongside actions and spend. It does not add memory support, select a storage provider, or commit an implementation schedule.

## Boundary

Govern memory, don't buy storage. Permission to call a model or tool is not permission to read or persist context without a limit. Memory reads and writes should pass through the same caller-bound, signed, time-bounded authorization boundary as other agent operations.

A proposed memory grant in the identity registry would follow the spend-policy pattern: bind an identified caller and scope to allowed namespaces, read/write permissions, a validity window, per-object size ceiling, and cumulative namespace capacity. Grant expiry limits future access; retention and deletion are separate policies. A storage adapter would execute an approved operation, not grant authority or change policy.

Storage integrity and operation authorization prove different things. A blob hash can detect changed bytes; it cannot establish that the caller was allowed to write those bytes. Memory providers may already enforce access controls. Walrus Memory, for example, documents signed requests, ownership and delegate permissions for reads and writes. The proposed Membrane boundary adds operator-owned execution policy and receipts tied to the caller, scope, and live grant, independent of the selected backend.

## Operator storage, optional adapters

The default backend would store immutable, content-addressed blobs on operator-controlled disk. A namespace index would resolve logical memory identifiers to authorized blob versions. Receipts would commit to blob hashes and operation metadata rather than copying memory contents into the journal.

This local path requires no token or external storage-network fee. Disk, backups, encryption, and operations still have costs. An adapter interface would permit decentralized or object-storage backends, including Walrus, IPFS, or S3, without making any provider or token a Membrane dependency. Each backend retains its own availability, privacy, durability, pricing, and deletion limits; no automatic migration or fallback is implied.

## Proposed execution and evidence

1. Authenticate the caller and validate the live grant, namespace, operation, and size limits. Deny on expiry, revocation, malformed policy, unavailable state, or an unprovable limit. Bind writes to the requested content hash and expected namespace version; reserve capacity atomically before accepting concurrent writes.
2. For a write, durably store and verify the blob before publishing its namespace version. For a read, resolve only authorized versions and verify their hashes before returning bytes. Keep storage credentials outside model-visible context and prevent direct backend access from bypassing the gate.
3. Journal the operation and namespace transition in the existing hash-chained journal, with writer identity and grant provenance. Issue a receipt only for the recorded outcome. Define crash recovery and idempotency so interrupted writes cannot become visible without their authorization record, and read evidence is durable before bytes leave the boundary.
4. Preserve immutable history. An operator-authorized rollback would append a new namespace transition to a known prior version, not rewrite the journal. Recheck access policy when restored memory is read.

Proposed receipt fields include caller, scope and grant identifiers, namespace, operation, logical memory identifier, version, blob hash, byte count, timestamp, and outcome. Do not include memory plaintext, signing keys, or bearer credentials. A Membrane receipt and a backend integrity proof should be linked without treating either as a substitute for the other.

## Limits and open checks

Writer and grant provenance make suspect state attributable and support namespace rollback. They do not prove that authorized content is true, safe, or free of prompt injection, and rollback cannot undo prior disclosures or downstream actions. Retrieved memory remains data, not new authority.

Before implementation, validate namespace isolation, concurrent quota accounting, journal/index recovery, encryption and key custody, receipt metadata leakage, retention and garbage collection, and backend bypass resistance. Hash-chained receipts are tamper-evident records, not a confidentiality mechanism or a guarantee of deletion from replicas. Semantic retrieval and embeddings are separate from this authorization boundary.

## References

- [Caller identity](caller-identity.md), [durable journal](durable-journal.md), and [spend-policy direction](settlement-adapters.md).
- [Walrus Memory: permissions, storage, and integrity](https://walrus.xyz/products/walrus-memory/).
