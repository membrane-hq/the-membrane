//! Ordered RFC 6962-style receipt log tree (whitepaper §5.1.2, docs/merkle-trees.md §3).
//!
//! Unlike the set commitment tree in [`crate::merkle`], this construction
//! commits to the exact leaf count and the append order: leaves are never
//! duplicated, leaf and node hashes are domain-separated, and every hash
//! carries the versioned tag [`LOG_DOMAIN`]. Inclusion and consistency proofs
//! follow RFC 6962 §2.1; verification pseudocode follows RFC 9162
//! §2.1.3.2/§2.1.4.2 with the membrane domain separation.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Versioned domain tag carried by every hash in the ordered log tree.
/// Any change to tags or construction is a new tag (`membrane-log/v2`, ...).
pub const LOG_DOMAIN: &[u8] = b"membrane-log/v1";

#[derive(Debug, thiserror::Error)]
pub enum LogTreeError {
    #[error("root is not 64 hex chars: {0}")]
    InvalidRootHex(String),
    #[error("signature is not valid hex: {0}")]
    InvalidSignatureHex(String),
    #[error("invalid signer pubkey: {0}")]
    InvalidSignerPubkey(String),
    #[error("signature does not verify")]
    InvalidSignature,
    #[error("proof path is not valid hex: {0}")]
    InvalidProofHex(String),
    #[error("consistency proof sizes out of order: first {first}, second {second}")]
    BadProofSizes { first: u64, second: u64 },
}

/// `SHA-256(0x00 || LOG_DOMAIN || entry)`.
pub fn leaf_hash(entry: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(LOG_DOMAIN);
    hasher.update(entry);
    hasher.finalize().into()
}

/// `SHA-256(0x01 || LOG_DOMAIN || left || right)`.
pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(LOG_DOMAIN);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// `SHA-256(0x02 || LOG_DOMAIN || u64be(size) || root || u64be(ts))` — the
/// message the log operator signs to produce a signed tree head.
pub fn sth_message(tree_size: u64, root: &[u8; 32], timestamp: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x02]);
    hasher.update(LOG_DOMAIN);
    hasher.update(tree_size.to_be_bytes());
    hasher.update(root);
    hasher.update(timestamp.to_be_bytes());
    hasher.finalize().into()
}

/// Largest power of two strictly less than `n` (`n >= 2`).
fn split_point(n: usize) -> usize {
    debug_assert!(n >= 2);
    let mut k = 1usize;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// Merkle Tree Hash over ordered entries: `MTH({}) = SHA-256("")`,
/// `MTH({e}) = leaf_hash(e)`, otherwise split at the largest power of two
/// strictly below n and hash the two sub-roots. No leaf is ever duplicated.
pub fn mth(entries: &[Vec<u8>]) -> [u8; 32] {
    match entries.len() {
        0 => Sha256::digest([]).into(),
        1 => leaf_hash(&entries[0]),
        n => {
            let k = split_point(n);
            node_hash(&mth(&entries[..k]), &mth(&entries[k..]))
        }
    }
}

/// RFC 6962 §2.1.1 `PATH(m, D[n])` over raw entries.
fn audit_path(m: usize, entries: &[Vec<u8>]) -> Vec<[u8; 32]> {
    let n = entries.len();
    if n == 1 {
        return Vec::new();
    }
    let k = split_point(n);
    if m < k {
        let mut path = audit_path(m, &entries[..k]);
        path.push(mth(&entries[k..]));
        path
    } else {
        let mut path = audit_path(m - k, &entries[k..]);
        path.push(mth(&entries[..k]));
        path
    }
}

/// RFC 6962 §2.1.2 `SUBPROOF(m, D[n], complete)` over raw entries.
fn subproof(m: usize, entries: &[Vec<u8>], complete: bool) -> Vec<[u8; 32]> {
    let n = entries.len();
    if m == n {
        return if complete {
            Vec::new()
        } else {
            vec![mth(entries)]
        };
    }
    let k = split_point(n);
    if m <= k {
        let mut proof = subproof(m, &entries[..k], complete);
        proof.push(mth(&entries[k..]));
        proof
    } else {
        let mut proof = subproof(m - k, &entries[k..], false);
        proof.push(mth(&entries[..k]));
        proof
    }
}

/// Append-only ordered log: the period's receipts in append order. An entry is
/// the canonical receipt bytes — the same canonicalization the receipt's
/// signature covers.
#[derive(Debug, Clone, Default)]
pub struct OrderedLogTree {
    entries: Vec<Vec<u8>>,
}

impl OrderedLogTree {
    pub fn new(entries: Vec<Vec<u8>>) -> Self {
        Self { entries }
    }

    pub fn append(&mut self, entry: Vec<u8>) {
        self.entries.push(entry);
    }

    pub fn entries(&self) -> &[Vec<u8>] {
        &self.entries
    }

    pub fn tree_size(&self) -> u64 {
        self.entries.len() as u64
    }

    /// MTH of all entries; the empty tree hashes to `SHA-256("")`.
    pub fn root(&self) -> [u8; 32] {
        mth(&self.entries)
    }

    pub fn root_hex(&self) -> String {
        hex::encode(self.root())
    }

    /// Audit path for the entry at `leaf_index` (0-based), or `None` when the
    /// index is outside the tree.
    pub fn inclusion_proof(&self, leaf_index: u64) -> Option<InclusionProof> {
        if leaf_index >= self.tree_size() {
            return None;
        }
        Some(InclusionProof {
            leaf_index,
            tree_size: self.tree_size(),
            path: audit_path(leaf_index as usize, &self.entries),
        })
    }

    /// RFC 6962 §2.1.2 `PROOF(first_size, D[n])`: proof that the tree of
    /// `first_size` entries is a prefix of this tree. Requires
    /// `0 < first_size < tree_size`.
    pub fn consistency_proof(&self, first_size: u64) -> Option<ConsistencyProof> {
        let second_size = self.tree_size();
        if first_size == 0 || first_size >= second_size {
            return None;
        }
        Some(ConsistencyProof {
            first_size,
            second_size,
            path: subproof(first_size as usize, &self.entries, true),
        })
    }
}

/// Inclusion proof for one entry (RFC 6962 §2.1.1 audit path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    pub leaf_index: u64,
    pub tree_size: u64,
    pub path: Vec<[u8; 32]>,
}

impl InclusionProof {
    /// Recompute the root from `entry` and the path; accept when it equals
    /// `expected_root`. Verification needs the one entry, the proof and the
    /// signed tree head — not the log.
    pub fn verify(&self, entry: &[u8], expected_root: &[u8; 32]) -> bool {
        if self.tree_size == 0 || self.leaf_index >= self.tree_size {
            return false;
        }
        let mut fn_ = self.leaf_index;
        let mut sn = self.tree_size - 1;
        let mut r = leaf_hash(entry);
        for p in &self.path {
            if sn == 0 {
                return false;
            }
            if fn_ & 1 == 1 || fn_ == sn {
                r = node_hash(p, &r);
                while fn_ & 1 == 0 && fn_ != 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            } else {
                r = node_hash(&r, p);
            }
            fn_ >>= 1;
            sn >>= 1;
        }
        sn == 0 && &r == expected_root
    }

    pub fn to_json(&self) -> InclusionProofJson {
        InclusionProofJson {
            leaf_index: self.leaf_index,
            tree_size: self.tree_size,
            path: self.path.iter().map(hex::encode).collect(),
        }
    }

    pub fn from_json(json: &InclusionProofJson) -> Result<Self, LogTreeError> {
        let path = decode_path(&json.path)?;
        Ok(Self {
            leaf_index: json.leaf_index,
            tree_size: json.tree_size,
            path,
        })
    }
}

/// Hex-encoded serde form of [`InclusionProof`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProofJson {
    pub leaf_index: u64,
    pub tree_size: u64,
    pub path: Vec<String>,
}

/// Consistency proof between a smaller and a larger tree (RFC 6962 §2.1.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsistencyProof {
    pub first_size: u64,
    pub second_size: u64,
    pub path: Vec<[u8; 32]>,
}

impl ConsistencyProof {
    /// Verify that the tree head `first_hash` at `first_size` is a prefix of
    /// `second_hash` at `second_size` (RFC 9162 §2.1.4.2).
    pub fn verify(&self, first_hash: &[u8; 32], second_hash: &[u8; 32]) -> bool {
        if self.first_size == 0 || self.first_size >= self.second_size || self.path.is_empty() {
            return false;
        }
        let mut path = self.path.clone();
        if self.first_size.is_power_of_two() {
            path.insert(0, *first_hash);
        }
        let mut fn_ = self.first_size - 1;
        let mut sn = self.second_size - 1;
        while fn_ & 1 == 1 {
            fn_ >>= 1;
            sn >>= 1;
        }
        let mut fr = path[0];
        let mut sr = path[0];
        for c in &path[1..] {
            if sn == 0 {
                return false;
            }
            if fn_ & 1 == 1 || fn_ == sn {
                fr = node_hash(c, &fr);
                sr = node_hash(c, &sr);
                while fn_ & 1 == 0 && fn_ != 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            } else {
                sr = node_hash(&sr, c);
            }
            fn_ >>= 1;
            sn >>= 1;
        }
        sn == 0 && &fr == first_hash && &sr == second_hash
    }

    pub fn to_json(&self) -> ConsistencyProofJson {
        ConsistencyProofJson {
            first_size: self.first_size,
            second_size: self.second_size,
            path: self.path.iter().map(hex::encode).collect(),
        }
    }

    pub fn from_json(json: &ConsistencyProofJson) -> Result<Self, LogTreeError> {
        if json.first_size == 0 || json.first_size >= json.second_size {
            return Err(LogTreeError::BadProofSizes {
                first: json.first_size,
                second: json.second_size,
            });
        }
        let path = decode_path(&json.path)?;
        Ok(Self {
            first_size: json.first_size,
            second_size: json.second_size,
            path,
        })
    }
}

/// Hex-encoded serde form of [`ConsistencyProof`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsistencyProofJson {
    pub first_size: u64,
    pub second_size: u64,
    pub path: Vec<String>,
}

fn decode_path(path: &[String]) -> Result<Vec<[u8; 32]>, LogTreeError> {
    path.iter()
        .map(|h| {
            let bytes = hex::decode(h).map_err(|_| LogTreeError::InvalidProofHex(h.clone()))?;
            <[u8; 32]>::try_from(bytes.as_slice())
                .map_err(|_| LogTreeError::InvalidProofHex(h.clone()))
        })
        .collect()
}

/// Signed tree head: the log operator's signed statement of
/// `(tree_size, root, timestamp)`, signed with the same node key that signs
/// bus events (whitepaper §5.1.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTreeHead {
    pub tree_size: u64,
    /// Hex-encoded MTH of the first `tree_size` entries.
    pub root: String,
    /// Unix seconds; for period roots this is `period_end`.
    pub timestamp: u64,
    /// Hex-encoded 64-byte Schnorr signature over [`sth_message`].
    pub signature: String,
}

impl SignedTreeHead {
    pub fn sign(tree_size: u64, root: [u8; 32], timestamp: u64, keys: &nostr::Keys) -> Self {
        let message =
            nostr::secp256k1::Message::from_digest(sth_message(tree_size, &root, timestamp));
        let sig = keys.sign_schnorr(&message);
        Self {
            tree_size,
            root: hex::encode(root),
            timestamp,
            signature: hex::encode(sig.serialize()),
        }
    }

    pub fn root_bytes(&self) -> Result<[u8; 32], LogTreeError> {
        let bytes =
            hex::decode(&self.root).map_err(|_| LogTreeError::InvalidRootHex(self.root.clone()))?;
        <[u8; 32]>::try_from(bytes.as_slice())
            .map_err(|_| LogTreeError::InvalidRootHex(self.root.clone()))
    }

    pub fn message(&self) -> Result<[u8; 32], LogTreeError> {
        Ok(sth_message(
            self.tree_size,
            &self.root_bytes()?,
            self.timestamp,
        ))
    }

    /// Verify the Schnorr signature against the operator's pubkey.
    pub fn verify(&self, signer_pubkey_hex: &str) -> Result<(), LogTreeError> {
        let sig_bytes = hex::decode(&self.signature)
            .map_err(|e| LogTreeError::InvalidSignatureHex(e.to_string()))?;
        let sig = nostr::secp256k1::schnorr::Signature::from_slice(&sig_bytes)
            .map_err(|e| LogTreeError::InvalidSignatureHex(e.to_string()))?;
        let pubkey = nostr::PublicKey::from_hex(signer_pubkey_hex)
            .map_err(|e| LogTreeError::InvalidSignerPubkey(e.to_string()))?;
        let message = nostr::secp256k1::Message::from_digest(self.message()?);
        let secp = nostr::secp256k1::Secp256k1::verification_only();
        let xonly = pubkey
            .xonly()
            .map_err(|e| LogTreeError::InvalidSignerPubkey(e.to_string()))?;
        secp.verify_schnorr(&sig, &message, &xonly)
            .map_err(|_| LogTreeError::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(n: usize) -> Vec<Vec<u8>> {
        (0..n).map(|i| format!("entry-{i}").into_bytes()).collect()
    }

    #[test]
    fn empty_tree_root_is_sha256_of_empty_string() {
        let tree = OrderedLogTree::new(vec![]);
        assert_eq!(hex::encode(tree.root()), hex::encode(Sha256::digest([])));
    }

    #[test]
    fn single_leaf_root_is_leaf_hash() {
        let tree = OrderedLogTree::new(entries(1));
        assert_eq!(tree.root(), leaf_hash(b"entry-0"));
    }

    #[test]
    fn two_leaf_root_is_node_hash() {
        let tree = OrderedLogTree::new(entries(2));
        assert_eq!(
            tree.root(),
            node_hash(&leaf_hash(b"entry-0"), &leaf_hash(b"entry-1"))
        );
    }

    /// Pinned reference values for the RFC 6962 §2.1 recursion, computed from
    /// the RFC definition with an independent (non-Rust) implementation: the
    /// `LOG_DOMAIN` tag is the only difference between this construction and
    /// plain RFC 6962.
    #[test]
    fn plain_recursion_matches_rfc6962_reference_values() {
        fn plain_leaf(e: &[u8]) -> [u8; 32] {
            let mut h = Sha256::new();
            h.update([0x00]);
            h.update(e);
            h.finalize().into()
        }
        fn plain_node(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
            let mut h = Sha256::new();
            h.update([0x01]);
            h.update(l);
            h.update(r);
            h.finalize().into()
        }
        // MTH({}) = SHA-256("")
        assert_eq!(
            hex::encode(mth(&[])),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // MTH({"123"}) = SHA-256(0x00 || "123")
        assert_eq!(
            hex::encode(plain_leaf(b"123")),
            "03b85d7ad09d3f1baf46f5bf1b7b60000eb5c68d629f6dd574e23e8cbf9e040a"
        );
        // MTH({"123", "456"}) = SHA-256(0x01 || MTH({"123"}) || MTH({"456"}))
        let l = plain_leaf(b"123");
        let r = plain_leaf(b"456");
        assert_eq!(
            hex::encode(plain_node(&l, &r)),
            "aef7cbb5e4271571855c302fd518627a5edee86ea2e83f5a4a8d4fbdcf120fcd"
        );
        // Our tagged construction must differ from the untagged reference.
        assert_ne!(leaf_hash(b"123"), plain_leaf(b"123"));
    }

    /// Domain separation negative: leaf bytes reinterpreted as a node (or the
    /// reverse) must never verify — the 0x00/0x01 tags make the two hash
    /// worlds disjoint even over identical payloads.
    #[test]
    fn domain_separation_negative() {
        let l = leaf_hash(b"a");
        let r = leaf_hash(b"b");
        let root = node_hash(&l, &r);
        // Reinterpreting the node preimage as one giant leaf entry cannot
        // reproduce the root.
        let mut fake_entry = vec![0x01u8];
        fake_entry.extend_from_slice(LOG_DOMAIN);
        fake_entry.extend_from_slice(&l);
        fake_entry.extend_from_slice(&r);
        assert_ne!(leaf_hash(&fake_entry), root);
        // And a proof for the two-leaf tree cannot verify against the
        // single-leaf reinterpretation.
        let tree = OrderedLogTree::new(vec![b"a".to_vec(), b"b".to_vec()]);
        let proof = tree.inclusion_proof(0).unwrap();
        assert!(!proof.verify(&fake_entry, &tree.root()));
        // Same payload, different tag world:
        assert_ne!(leaf_hash(&fake_entry), node_hash(&l, &r));
    }

    /// RFC 6962 §2.1.3 / RFC 9162 §2.1.5 structural example: the 7-leaf tree,
    /// its audit paths and its consistency proofs, with membrane tags.
    #[test]
    fn rfc6962_example_tree_structure() {
        let data: Vec<Vec<u8>> = (0..7).map(|i| vec![b'd', b'0' + i as u8]).collect();
        let d: Vec<[u8; 32]> = data.iter().map(|e| leaf_hash(e)).collect();
        let a = d[0];
        let b = d[1];
        let c = d[2];
        let dd = d[3];
        let e = d[4];
        let f = d[5];
        let g = node_hash(&a, &b);
        let h = node_hash(&c, &dd);
        let i = node_hash(&e, &f);
        let j = d[6];
        let k = node_hash(&g, &h);
        let l = node_hash(&i, &j);

        let tree = OrderedLogTree::new(data.clone());
        assert_eq!(tree.root(), node_hash(&k, &l));
        assert_eq!(tree.inclusion_proof(0).unwrap().path, vec![b, h, l]);
        assert_eq!(tree.inclusion_proof(3).unwrap().path, vec![c, g, l]);
        assert_eq!(tree.inclusion_proof(4).unwrap().path, vec![f, j, k]);
        assert_eq!(tree.inclusion_proof(6).unwrap().path, vec![i, k]);

        for (m, expected) in [
            (3usize, vec![c, dd, g, l]),
            (4, vec![l]),
            (6, vec![i, j, k]),
        ] {
            let proof = tree.consistency_proof(m as u64).unwrap();
            assert_eq!(proof.path, expected, "PROOF({m}, D[7])");
            let first_root = mth(&data[..m]);
            assert!(proof.verify(&first_root, &tree.root()));
        }
    }

    /// The root commits to the exact leaf count: [a, b, c] and [a, b, c, c]
    /// differ, unlike the set commitment tree.
    #[test]
    fn root_commits_to_count() {
        let three = OrderedLogTree::new(entries(3));
        let mut four_entries = entries(3);
        four_entries.push(four_entries[2].clone());
        let four = OrderedLogTree::new(four_entries);
        assert_ne!(three.root(), four.root());
        assert_eq!(three.tree_size(), 3);
        assert_eq!(four.tree_size(), 4);
    }

    /// The root commits to append order.
    #[test]
    fn root_commits_to_order() {
        let forward = OrderedLogTree::new(entries(3));
        let mut swapped = entries(3);
        swapped.swap(0, 2);
        let backward = OrderedLogTree::new(swapped);
        assert_ne!(forward.root(), backward.root());
    }

    #[test]
    fn inclusion_proof_out_of_range() {
        let tree = OrderedLogTree::new(entries(2));
        assert!(tree.inclusion_proof(2).is_none());
        let proof = tree.inclusion_proof(0).unwrap();
        assert!(!proof.verify(b"entry-1", &tree.root()));
        let mut wrong = proof.clone();
        wrong.leaf_index = 1;
        assert!(!wrong.verify(b"entry-0", &tree.root()));
    }

    #[test]
    fn consistency_proof_bounds() {
        let tree = OrderedLogTree::new(entries(4));
        assert!(tree.consistency_proof(0).is_none());
        assert!(tree.consistency_proof(4).is_none());
        assert!(tree.consistency_proof(5).is_none());
        let proof = tree.consistency_proof(2).unwrap();
        let wrong = [0x11; 32];
        assert!(!proof.verify(&wrong, &tree.root()));
        assert!(!proof.verify(&mth(&entries(2)), &wrong));
    }

    #[test]
    fn sth_sign_and_verify_roundtrip() {
        let keys = nostr::Keys::generate();
        let tree = OrderedLogTree::new(entries(5));
        let sth = SignedTreeHead::sign(tree.tree_size(), tree.root(), 1_700_000_000, &keys);
        sth.verify(&keys.public_key().to_hex()).unwrap();
        assert_eq!(sth.root_bytes().unwrap(), tree.root());

        let wrong_keys = nostr::Keys::generate();
        assert!(sth.verify(&wrong_keys.public_key().to_hex()).is_err());

        let mut tampered = sth.clone();
        tampered.tree_size += 1;
        assert!(tampered.verify(&keys.public_key().to_hex()).is_err());
    }

    #[test]
    fn proof_json_roundtrip() {
        let tree = OrderedLogTree::new(entries(9));
        let proof = tree.inclusion_proof(5).unwrap();
        let json = proof.to_json();
        let restored = InclusionProof::from_json(&json).unwrap();
        assert_eq!(proof, restored);
        let text = serde_json::to_string(&json).unwrap();
        let parsed: InclusionProofJson = serde_json::from_str(&text).unwrap();
        assert_eq!(InclusionProof::from_json(&parsed).unwrap(), proof);

        let consistency = tree.consistency_proof(6).unwrap();
        let json = consistency.to_json();
        assert_eq!(ConsistencyProof::from_json(&json).unwrap(), consistency);
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    fn entry_vec(max_len: usize) -> impl Strategy<Value = Vec<Vec<u8>>> {
        proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..64), 0..max_len)
    }

    proptest! {
        /// Every entry of every tree proves inclusion against the tree root.
        #[test]
        fn inclusion_proof_roundtrip(raw in entry_vec(48), index_seed in any::<u64>()) {
            prop_assume!(!raw.is_empty());
            let tree = OrderedLogTree::new(raw.clone());
            let index = (index_seed as usize) % raw.len();
            let proof = tree.inclusion_proof(index as u64).unwrap();
            prop_assert_eq!(proof.tree_size, raw.len() as u64);
            prop_assert!(proof.verify(&raw[index], &tree.root()));
        }

        /// A proof never verifies against a different root, a different entry
        /// or a shifted index (hash-collision-negligible).
        #[test]
        fn inclusion_proof_rejects_tampering(raw in entry_vec(48), index_seed in any::<u64>()) {
            prop_assume!(raw.len() >= 2);
            let tree = OrderedLogTree::new(raw.clone());
            let index = (index_seed as usize) % raw.len();
            let proof = tree.inclusion_proof(index as u64).unwrap();

            let mut bad_root = tree.root();
            bad_root[0] ^= 0xff;
            prop_assert!(!proof.verify(&raw[index], &bad_root));

            let mut bad_entry = raw[index].clone();
            bad_entry.push(0x00);
            prop_assert!(!proof.verify(&bad_entry, &tree.root()));

            let shifted = (index + 1) % raw.len();
            if raw[shifted] != raw[index] {
                let mut moved = proof.clone();
                moved.leaf_index = shifted as u64;
                prop_assert!(!moved.verify(&raw[index], &tree.root()));
            }
        }

        /// The root commits to count: appending always changes it.
        #[test]
        fn root_commits_to_count_property(raw in entry_vec(48), extra in any::<Vec<u8>>()) {
            let tree = OrderedLogTree::new(raw.clone());
            let mut grown = OrderedLogTree::new(raw);
            grown.append(extra);
            prop_assert_ne!(tree.root(), grown.root());
            prop_assert_eq!(grown.tree_size(), tree.tree_size() + 1);
        }

        /// The root commits to order: swapping two distinct entries changes it.
        #[test]
        fn root_commits_to_order_property(raw in entry_vec(48)) {
            prop_assume!(raw.len() >= 2);
            let tree = OrderedLogTree::new(raw.clone());
            let mut swapped = raw.clone();
            let last = swapped.len() - 1;
            swapped.swap(0, last);
            if swapped != raw {
                prop_assert_ne!(tree.root(), OrderedLogTree::new(swapped).root());
            }
        }

        /// Append-only growth is auditable between any two sizes.
        #[test]
        fn consistency_proof_roundtrip(raw in entry_vec(64), m_seed in any::<u64>()) {
            prop_assume!(raw.len() >= 2);
            let tree = OrderedLogTree::new(raw.clone());
            let m = ((m_seed as usize) % (raw.len() - 1)) + 1;
            let proof = tree.consistency_proof(m as u64).unwrap();
            let first_root = mth(&raw[..m]);
            prop_assert!(proof.verify(&first_root, &tree.root()));

            let mut bad_first = first_root;
            bad_first[0] ^= 0xff;
            prop_assert!(!proof.verify(&bad_first, &tree.root()));
        }

        /// Leaf hashes and node hashes live in disjoint worlds for any input.
        #[test]
        fn leaf_node_domain_separation_property(data in any::<Vec<u8>>()) {
            let leaf = leaf_hash(&data);
            let as_node = node_hash(&leaf, &leaf);
            prop_assert_ne!(leaf, as_node);
        }
    }
}
