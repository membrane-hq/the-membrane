use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Domain {
    FeatureChunk = 0x00,
    BusEvent = 0x01,
    CpHash = 0x02,
    WitnessKey = 0x03,
}

impl Domain {
    pub fn prefix(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone)]
pub struct MerkleTree {
    leaves: Vec<[u8; 32]>,
    root: Option<[u8; 32]>,
}

impl MerkleTree {
    pub fn from_domain_leaves(domain: Domain, raw_leaves: &[Vec<u8>]) -> Self {
        let leaves: Vec<[u8; 32]> = raw_leaves
            .iter()
            .map(|leaf| prefixed_hash(domain, leaf))
            .collect();
        let root = compute_root(&leaves);
        Self { leaves, root }
    }

    pub fn from_prefixed_leaves(mut leaves: Vec<[u8; 32]>) -> Self {
        leaves.sort();
        let root = compute_root(&leaves);
        Self { leaves, root }
    }

    pub fn root(&self) -> Option<[u8; 32]> {
        self.root
    }

    pub fn root_hex(&self) -> Option<String> {
        self.root.map(hex::encode)
    }

    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }
}

pub fn prefixed_hash(domain: Domain, data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([domain.prefix()]);
    hasher.update(data);
    hasher.finalize().into()
}

fn compute_root(level: &[[u8; 32]]) -> Option<[u8; 32]> {
    if level.is_empty() {
        return None;
    }
    if level.len() == 1 {
        return Some(level[0]);
    }

    let mut current: Vec<[u8; 32]> = level.to_vec();
    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        let mut i = 0;
        while i < current.len() {
            let left = current[i];
            let right = if i + 1 < current.len() {
                current[i + 1]
            } else {
                current[i]
            };
            next.push(parent_hash(&left, &right));
            i += 2;
        }
        current = next;
    }
    current.first().copied()
}

fn parent_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    if left <= right {
        hasher.update(left);
        hasher.update(right);
    } else {
        hasher.update(right);
        hasher.update(left);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bus_domain_prefix() {
        let leaf = prefixed_hash(Domain::BusEvent, b"event-a");
        let tree = MerkleTree::from_prefixed_leaves(vec![leaf]);
        assert!(tree.root_hex().is_some());
    }

    #[test]
    fn odd_leaf_duplicates_last() {
        let a = prefixed_hash(Domain::FeatureChunk, b"a");
        let b = prefixed_hash(Domain::FeatureChunk, b"b");
        let c = prefixed_hash(Domain::FeatureChunk, b"c");
        let root = MerkleTree::from_prefixed_leaves(vec![a, b, c]);
        let dup = MerkleTree::from_prefixed_leaves(vec![a, b, c, c]);
        assert_eq!(root.root(), dup.root());
    }

    #[test]
    fn leaves_sorted_lexicographically() {
        let hi = prefixed_hash(Domain::CpHash, b"z");
        let lo = prefixed_hash(Domain::CpHash, b"a");
        let unsorted = MerkleTree::from_prefixed_leaves(vec![hi, lo]);
        let sorted = MerkleTree::from_prefixed_leaves(vec![lo, hi]);
        assert_eq!(unsorted.root(), sorted.root());
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    fn leaf_vec(max_len: usize) -> impl Strategy<Value = Vec<Vec<u8>>> {
        proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..64), 0..max_len)
    }

    proptest! {
        /// Set trees are permutation-invariant: the root commits to the set of
        /// leaves, not their arrival order. This is intended behavior (spec
        /// §5.1 sorts leaves before pairing).
        #[test]
        fn set_tree_root_is_permutation_invariant(raw in leaf_vec(12)) {
            let leaves: Vec<[u8; 32]> = raw
                .iter()
                .map(|l| prefixed_hash(Domain::BusEvent, l))
                .collect();
            let mut shuffled = leaves.clone();
            shuffled.reverse();
            prop_assert_eq!(
                MerkleTree::from_prefixed_leaves(leaves).root(),
                MerkleTree::from_prefixed_leaves(shuffled).root()
            );
        }

        /// Empty set trees have no root; a single-leaf tree's root is the leaf.
        #[test]
        fn set_tree_root_edge_cases(raw in leaf_vec(12)) {
            let leaves: Vec<[u8; 32]> = raw
                .iter()
                .map(|l| prefixed_hash(Domain::BusEvent, l))
                .collect();
            let tree = MerkleTree::from_prefixed_leaves(leaves.clone());
            prop_assert_eq!(tree.root().is_some(), !leaves.is_empty());
            prop_assert_eq!(tree.leaf_count(), leaves.len());
            if leaves.len() == 1 {
                prop_assert_eq!(tree.root(), Some(leaves[0]));
            }
        }

        /// Distinct leaf sets differing in exactly one element commit to
        /// different roots.
        #[test]
        fn set_tree_root_changes_with_any_leaf(raw in leaf_vec(12), extra in any::<Vec<u8>>()) {
            let mut leaves: Vec<[u8; 32]> = raw
                .iter()
                .map(|l| prefixed_hash(Domain::BusEvent, l))
                .collect();
            let extra_leaf = prefixed_hash(Domain::BusEvent, &extra);
            prop_assume!(!leaves.contains(&extra_leaf));
            let base = MerkleTree::from_prefixed_leaves(leaves.clone()).root();
            if leaves.is_empty() {
                leaves.push(extra_leaf);
            } else {
                leaves[0] = extra_leaf;
            }
            prop_assert_ne!(base, MerkleTree::from_prefixed_leaves(leaves).root());
        }

        /// KNOWN LIMITATION, issue #62: an odd leaf count duplicates the last
        /// leaf, so a root does not commit to the exact leaf count -
        /// [a, b, c] and [a, b, c, c] collide. Spec §5.1 documents this
        /// construction. This test pins the current behavior so the eventual
        /// fix changes it deliberately, not silently. It is not an
        /// endorsement of the behavior.
        #[test]
        fn known_limitation_odd_leaf_duplication_preserves_root(raw in leaf_vec(12)) {
            let leaves: Vec<[u8; 32]> = raw
                .iter()
                .map(|l| prefixed_hash(Domain::BusEvent, l))
                .collect();
            prop_assume!(leaves.len() >= 3 && leaves.len() % 2 == 1);
            // The tree sorts leaves, so the duplicated "last" leaf is the
            // maximum digest, not the last element before sorting.
            let max_leaf = *leaves.iter().max().unwrap();
            let mut padded = leaves.clone();
            padded.push(max_leaf);
            prop_assert_eq!(
                MerkleTree::from_prefixed_leaves(leaves).root(),
                MerkleTree::from_prefixed_leaves(padded).root()
            );
        }

        /// Domain prefixes separate trees: the same bytes hash differently
        /// under every domain.
        #[test]
        fn domain_prefixes_separate(data in any::<Vec<u8>>()) {
            let hashes = [
                prefixed_hash(Domain::FeatureChunk, &data),
                prefixed_hash(Domain::BusEvent, &data),
                prefixed_hash(Domain::CpHash, &data),
                prefixed_hash(Domain::WitnessKey, &data),
            ];
            for (i, a) in hashes.iter().enumerate() {
                for b in &hashes[i + 1..] {
                    prop_assert_ne!(a, b);
                }
            }
        }

        /// Ordered (domain-leaf) trees are deterministic and preserve leaf
        /// count. Note: order is only committed across pairs - the pair-sorted
        /// parent hash makes within-pair swaps invisible (see issue #62), so
        /// no order-sensitivity property is asserted here.
        #[test]
        fn ordered_tree_is_deterministic(raw in leaf_vec(12)) {
            let first = MerkleTree::from_domain_leaves(Domain::FeatureChunk, &raw);
            let second = MerkleTree::from_domain_leaves(Domain::FeatureChunk, &raw);
            prop_assert_eq!(first.root(), second.root());
            prop_assert_eq!(first.leaf_count(), raw.len());
            prop_assert_eq!(first.root().is_some(), !raw.is_empty());
        }
    }
}
