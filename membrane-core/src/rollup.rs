//! Daily rollup bundle construction (whitepaper §5.1).

pub const GENESIS_CP_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[cfg(feature = "ots")]
use crate::canonical::canonical_json_bytes;
use crate::event::{EventType, MembraneEvent};
#[cfg(feature = "ots")]
use crate::iac::RollupBundle;
#[cfg(feature = "ots")]
use crate::merkle::{prefixed_hash, Domain, MerkleTree};
#[cfg(feature = "ots")]
use anyhow::bail;
use anyhow::{Context, Result};
#[cfg(feature = "ots")]
use nostr::secp256k1::Message;
#[cfg(feature = "ots")]
use nostr::Keys;
#[cfg(feature = "ots")]
use sha2::{Digest, Sha256};

/// Chain-proof event types included in `cp_chain_root`.
pub fn is_cp_event(event_type: EventType) -> bool {
    matches!(
        event_type,
        EventType::CpLiveness | EventType::CpRouter | EventType::CpBci
    )
}

pub fn cp_hash_bytes(event: &MembraneEvent) -> Result<[u8; 32]> {
    event.digest().context("cp event digest")
}

pub fn cp_hash_hex(event: &MembraneEvent) -> Result<String> {
    Ok(hex::encode(cp_hash_bytes(event)?))
}

pub fn last_cp_hash_from_events(events: &[MembraneEvent], subject_pubkey: &str) -> String {
    let mut last = GENESIS_CP_HASH.to_string();
    for event in events {
        if event.subject_pubkey != subject_pubkey {
            continue;
        }
        if !is_cp_event(event.event_type) {
            continue;
        }
        if let Ok(hash) = cp_hash_hex(event) {
            last = hash;
        }
    }
    last
}

#[cfg(feature = "ots")]
pub fn cp_chain_root_from_events(events: &[MembraneEvent]) -> Result<Option<String>> {
    let mut leaves = Vec::new();
    for event in events {
        if !is_cp_event(event.event_type) {
            continue;
        }
        let cp_hash = cp_hash_bytes(event)?;
        leaves.push(prefixed_hash(Domain::CpHash, &cp_hash));
    }
    Ok(MerkleTree::from_prefixed_leaves(leaves).root_hex())
}

#[cfg(feature = "ots")]
pub fn filter_events_in_period(
    events: &[MembraneEvent],
    period_start: i64,
    period_end: i64,
) -> Vec<MembraneEvent> {
    events
        .iter()
        .filter(|e| e.timestamp >= period_start && e.timestamp <= period_end)
        .cloned()
        .collect()
}

#[cfg(feature = "ots")]
pub fn build_rollup_bundle(
    events: &[MembraneEvent],
    subject_pubkey: &str,
    period_start: i64,
    period_end: i64,
) -> Result<RollupBundle> {
    let period_events = filter_events_in_period(events, period_start, period_end);
    let cp_events: Vec<_> = period_events
        .iter()
        .filter(|e| is_cp_event(e.event_type))
        .collect();

    let cp_chain_root =
        cp_chain_root_from_events(&period_events)?.unwrap_or_else(|| "0".repeat(64));
    let last_bus_root =
        crate::bus::bus_root_from_events(&period_events)?.unwrap_or_else(|| "0".repeat(64));
    let last_cp_hash = cp_events
        .last()
        .map(|e| cp_hash_hex(e))
        .transpose()?
        .unwrap_or_else(|| "0".repeat(64));

    // Ordered log tree over the period's receipts in append order: each entry
    // is the event's canonical bytes — the same canonicalization its
    // signature covers (docs/merkle-trees.md §3.2, §3.6).
    let receipt_entries: Vec<Vec<u8>> = period_events
        .iter()
        .map(|e| e.canonical_bytes())
        .collect::<Result<_, _>>()
        .context("canonical receipt bytes")?;
    let log_tree = crate::log_tree::OrderedLogTree::new(receipt_entries);

    Ok(RollupBundle {
        version: RollupBundle::SCHEMA_VERSION.to_string(),
        subject_pubkey: subject_pubkey.to_string(),
        period_start,
        period_end,
        cp_chain_root,
        last_bus_root,
        last_cp_hash,
        log_root: log_tree.root_hex(),
        log_size: log_tree.tree_size(),
    })
}

#[cfg(feature = "ots")]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignedRollupBundle {
    #[serde(flatten)]
    pub bundle: RollupBundle,
    pub signature: String,
    /// Signed tree head over {log_size, log_root, period_end} (whitepaper
    /// §5.1.2). Absent for legacy bundles without a log commitment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sth: Option<crate::log_tree::SignedTreeHead>,
}

#[cfg(feature = "ots")]
impl SignedRollupBundle {
    pub fn sign(bundle: RollupBundle, keys: &Keys) -> Result<Self> {
        let bytes = canonical_json_bytes(&bundle).context("canonical rollup bytes")?;
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        let message = Message::from_digest(digest);
        let sig = keys.sign_schnorr(&message);
        let sth = if bundle.has_log_commitment() {
            let root_bytes: [u8; 32] = hex::decode(&bundle.log_root)
                .context("decode log_root")?
                .try_into()
                .map_err(|_| anyhow::anyhow!("log_root is not 32 bytes"))?;
            let timestamp = u64::try_from(bundle.period_end).context("period_end negative")?;
            Some(crate::log_tree::SignedTreeHead::sign(
                bundle.log_size,
                root_bytes,
                timestamp,
                keys,
            ))
        } else {
            None
        };
        Ok(Self {
            bundle,
            signature: hex::encode(sig.serialize()),
            sth,
        })
    }

    pub fn ots_digest(&self) -> Result<[u8; 32]> {
        let bundle_bytes = canonical_json_bytes(&self.bundle).context("canonical rollup bytes")?;
        let sig_bytes = hex::decode(&self.signature).context("decode rollup signature")?;
        let mut hasher = Sha256::new();
        hasher.update(&bundle_bytes);
        hasher.update(&sig_bytes);
        Ok(hasher.finalize().into())
    }

    pub fn ots_digest_hex(&self) -> Result<String> {
        Ok(hex::encode(self.ots_digest()?))
    }
}

#[cfg(feature = "ots")]
pub fn day_bounds_utc(day: &str) -> Result<(i64, i64)> {
    use chrono::{NaiveDate, TimeZone, Utc};
    let date = NaiveDate::parse_from_str(day, "%Y-%m-%d")
        .with_context(|| format!("invalid day {day:?}, expected YYYY-MM-DD"))?;
    let start = Utc
        .from_utc_datetime(&date.and_hms_opt(0, 0, 0).expect("midnight"))
        .timestamp();
    let end = Utc
        .from_utc_datetime(&date.and_hms_opt(23, 59, 59).expect("end of day"))
        .timestamp();
    Ok((start, end))
}

#[cfg(feature = "ots")]
pub fn validate_rollup_bundle(bundle: &RollupBundle) -> Result<()> {
    for field in [
        &bundle.cp_chain_root,
        &bundle.last_bus_root,
        &bundle.last_cp_hash,
        &bundle.log_root,
        &bundle.subject_pubkey,
    ] {
        if field.len() != 64 || !field.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!("rollup field must be 64 hex chars: {field}");
        }
    }
    if bundle.period_end < bundle.period_start {
        bail!("period_end before period_start");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{MembranePayload, RouterSessionPayload};

    fn router_event(ts: i64, nonce: u64) -> MembraneEvent {
        MembraneEvent::new(
            EventType::CpRouter,
            "aa".repeat(32),
            "00".repeat(64),
            ts,
            MembranePayload::Router(RouterSessionPayload {
                model_id: "demo".into(),
                context_merkle_root: "bb".repeat(32),
                session_nonce: nonce,
                parent_cp_hash: "cc".repeat(32),
                iac_hash: "dd".repeat(32),
                scope_id: None,
                tool_id: None,
                policy_digest: None,
                policy_revision: None,
            }),
        )
    }

    #[test]
    fn chain_hash_and_bootstrap_are_available_without_ots() {
        let event = router_event(100, 1);
        let hash = cp_hash_hex(&event).unwrap();
        assert_eq!(hash.len(), 64);
        assert!(is_cp_event(event.event_type));
        assert_eq!(last_cp_hash_from_events(&[event], &"aa".repeat(32)), hash);
    }

    #[cfg(feature = "ots")]
    #[test]
    fn cp_chain_root_is_stable() {
        let events = vec![router_event(100, 1), router_event(101, 2)];
        let root_a = cp_chain_root_from_events(&events).unwrap();
        let root_b = cp_chain_root_from_events(&events).unwrap();
        assert_eq!(root_a, root_b);
        assert!(root_a.unwrap().len() == 64);
    }

    #[cfg(feature = "ots")]
    #[test]
    fn signed_rollup_ots_digest_is_deterministic() {
        let bundle = RollupBundle {
            version: RollupBundle::SCHEMA_VERSION.to_string(),
            subject_pubkey: Keys::generate().public_key().to_hex(),
            period_start: 1,
            period_end: 2,
            cp_chain_root: "11".repeat(64),
            last_bus_root: "22".repeat(64),
            last_cp_hash: "33".repeat(64),
            log_root: "44".repeat(32),
            log_size: 3,
        };
        let keys = Keys::generate();
        let signed = SignedRollupBundle::sign(bundle, &keys).unwrap();
        assert_eq!(
            signed.ots_digest_hex().unwrap(),
            signed.ots_digest_hex().unwrap()
        );
        // The STH binds {log_size, log_root, period_end} under the node key.
        let sth = signed.sth.as_ref().expect("sth for committed log");
        assert_eq!(sth.tree_size, 3);
        assert_eq!(sth.root, "44".repeat(32));
        assert_eq!(sth.timestamp, 2);
        sth.verify(&keys.public_key().to_hex()).unwrap();
    }

    #[cfg(feature = "ots")]
    #[test]
    fn rollup_bundle_carries_ordered_log_commitment() {
        let events = vec![router_event(100, 1), router_event(101, 2)];
        let bundle = build_rollup_bundle(&events, &"aa".repeat(32), 0, 200).unwrap();
        assert!(bundle.has_log_commitment());
        assert_eq!(bundle.log_size, 2);
        assert_eq!(bundle.log_root.len(), 64);
        validate_rollup_bundle(&bundle).unwrap();

        // The log root is the ordered MTH over the events' canonical bytes in
        // append order, and each receipt proves inclusion.
        let entries: Vec<Vec<u8>> = events
            .iter()
            .map(|e| e.canonical_bytes().unwrap())
            .collect();
        let tree = crate::log_tree::OrderedLogTree::new(entries.clone());
        assert_eq!(bundle.log_root, tree.root_hex());
        for (i, entry) in entries.iter().enumerate() {
            let proof = tree.inclusion_proof(i as u64).unwrap();
            assert!(proof.verify(entry, &tree.root()));
        }

        // Order matters: reversed receipts commit to a different log root.
        let reversed = build_rollup_bundle(
            &[events[1].clone(), events[0].clone()],
            &"aa".repeat(32),
            0,
            200,
        )
        .unwrap();
        assert_ne!(bundle.log_root, reversed.log_root);

        // An empty period commits to the empty ordered tree (log_size 0).
        let empty = build_rollup_bundle(&[], &"aa".repeat(32), 300, 400).unwrap();
        assert!(empty.has_log_commitment());
        assert_eq!(empty.log_size, 0);
        assert_eq!(
            empty.log_root,
            crate::log_tree::OrderedLogTree::new(vec![]).root_hex()
        );
    }

    #[cfg(feature = "ots")]
    #[test]
    fn legacy_bundle_without_log_fields_deserializes() {
        let json = serde_json::json!({
            "version": "0.9.14",
            "subject_pubkey": "aa".repeat(32),
            "period_start": 1,
            "period_end": 2,
            "cp_chain_root": "11".repeat(64),
            "last_bus_root": "22".repeat(64),
            "last_cp_hash": "33".repeat(64),
        });
        let bundle: RollupBundle = serde_json::from_value(json).unwrap();
        assert!(!bundle.has_log_commitment());
        assert_eq!(bundle.log_size, 0);
        // No STH is signed for a bundle with no log commitment.
        let keys = Keys::generate();
        let signed = SignedRollupBundle::sign(bundle, &keys).unwrap();
        assert!(signed.sth.is_none());
    }
}
