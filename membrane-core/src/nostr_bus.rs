use crate::bus::bus_root_from_events;
use crate::canonical::canonical_json_bytes;
use crate::event::{EventType, MembraneEvent};
use crate::rollup::{is_cp_event, last_cp_hash_from_events};
use anyhow::{bail, Context, Result};
use nostr::event::builder::EventBuilder;
use nostr::secp256k1::Message;
use nostr::{Event, EventId, Filter, Keys, Kind, Tag, Timestamp, ToBech32};
use nostr_sdk::prelude::*;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tracing::{info, warn};

pub const KIND_MEMBRANE: u16 = 31990;
pub const KIND_ALERT: u16 = 31991;

/// Verify the Schnorr signature on a MembraneEvent against `expected_pubkey_hex`.
/// The event's own `subject_pubkey` must equal the expected key.
pub fn verify_membrane_event_signature(
    event: &MembraneEvent,
    expected_pubkey_hex: &str,
) -> Result<()> {
    use nostr::secp256k1::{schnorr::Signature, XOnlyPublicKey};
    if event.subject_pubkey != expected_pubkey_hex {
        bail!("subject_pubkey does not match expected signer");
    }
    let sig_hex = event.signature.as_deref().context("event is unsigned")?;
    let sig_bytes = hex::decode(sig_hex).context("signature is not hex")?;
    let sig = Signature::from_slice(&sig_bytes).context("malformed signature")?;
    let pk_bytes = hex::decode(expected_pubkey_hex).context("pubkey is not hex")?;
    let pk = XOnlyPublicKey::from_slice(&pk_bytes).context("malformed pubkey")?;
    let digest: [u8; 32] = Sha256::digest(&event.canonical_bytes()?).into();
    let message = Message::from_digest(digest);
    nostr::secp256k1::Secp256k1::verification_only()
        .verify_schnorr(&sig, &message, &pk)
        .map_err(|_| anyhow::anyhow!("signature does not verify"))
}

pub fn membrane_kind_for(event_type: EventType) -> u16 {
    match event_type {
        EventType::AlertDegraded | EventType::ActionBlocked => KIND_ALERT,
        _ => KIND_MEMBRANE,
    }
}

#[derive(Debug, Clone)]
pub struct BusPublisherConfig {
    pub relay_url: String,
    pub keys: Keys,
}

pub struct BusPublisher {
    config: BusPublisherConfig,
}

impl BusPublisher {
    pub fn new(config: BusPublisherConfig) -> Self {
        Self { config }
    }

    pub fn relay_url(&self) -> &str {
        &self.config.relay_url
    }

    pub fn keys(&self) -> &Keys {
        &self.config.keys
    }

    pub async fn publish(
        &self,
        event: &mut MembraneEvent,
        prev_event_id: Option<&str>,
    ) -> Result<EventId> {
        Ok(self.publish_with_receipt(event, prev_event_id).await?.id)
    }

    /// Publish and retain the exact signed Nostr envelope for offline evidence.
    /// Its ID hashes the envelope content, so it cannot be embedded in that
    /// content without creating a circular hash.
    pub async fn publish_with_receipt(
        &self,
        event: &mut MembraneEvent,
        prev_event_id: Option<&str>,
    ) -> Result<Event> {
        self.sign_membrane_event(event)?;
        let nostr_event = self.to_nostr_event(event, prev_event_id)?;
        let event_id = nostr_event.id;

        // Local-only demo / tests: sign and assign id without a live relay.
        if self.config.relay_url.starts_with("memory://")
            || self.config.relay_url.starts_with("local://")
        {
            info!(
                event_id = %event_id.to_hex(),
                kind = membrane_kind_for(event.event_type),
                "signed MembraneEvent (in-memory bus)"
            );
            return Ok(nostr_event);
        }

        let client = self.connect().await?;
        client.send_event(&nostr_event).await?;
        info!(
            event_id = %event_id.to_hex(),
            kind = membrane_kind_for(event.event_type),
            "published MembraneEvent to attestation bus"
        );
        Ok(nostr_event)
    }

    pub fn sign_membrane_event(&self, event: &mut MembraneEvent) -> Result<()> {
        // Set the signer first so the signature covers subject_pubkey.
        event.subject_pubkey = self.config.keys.public_key().to_hex();
        let signable = event.signable_view();
        let bytes = canonical_json_bytes(&signable).context("canonical event bytes")?;
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        let message = Message::from_digest(digest);
        let sig = self.config.keys.sign_schnorr(&message);
        event.signature = Some(hex::encode(sig.serialize()));
        Ok(())
    }

    pub fn to_nostr_event(
        &self,
        event: &MembraneEvent,
        prev_event_id: Option<&str>,
    ) -> Result<Event> {
        let kind = Kind::Custom(membrane_kind_for(event.event_type));
        let content = serde_json::to_string(event).context("serialize membrane event")?;

        let mut tags = vec![Tag::parse(vec![
            "k".to_string(),
            event.event_type.nostr_tag_suffix().to_string(),
        ])?];

        tags.push(Tag::public_key(self.config.keys.public_key()));

        if let Some(prev) = prev_event_id {
            tags.push(Tag::parse(vec!["e".to_string(), prev.to_string()])?);
        }

        let unsigned = EventBuilder::new(kind, content)
            .tags(tags)
            .custom_created_at(Timestamp::from(event.timestamp as u64))
            .sign_with_keys(&self.config.keys)?;

        Ok(unsigned)
    }

    async fn connect(&self) -> Result<Client> {
        let client = Client::new(self.config.keys.clone());
        client.add_relay(&self.config.relay_url).await?;
        client.connect().await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        Ok(client)
    }
}

pub async fn fetch_membrane_events(
    relay_url: &str,
    since: Option<i64>,
    limit: usize,
) -> Result<Vec<MembraneEvent>> {
    Ok(fetch_membrane_bus_events(relay_url, since, limit)
        .await?
        .into_iter()
        .map(|e| e.event)
        .collect())
}

pub fn parse_membrane_event(event: &Event) -> Result<MembraneEvent> {
    let kind = event.kind.as_u16();
    if kind != KIND_MEMBRANE && kind != KIND_ALERT {
        bail!("unexpected kind {kind}");
    }
    let membrane: MembraneEvent =
        serde_json::from_str(&event.content).context("parse membrane event JSON")?;
    event.verify().context("invalid Nostr envelope")?;
    if kind != membrane_kind_for(membrane.event_type) {
        bail!("event kind does not match inner type");
    }
    if event.created_at.as_secs() != membrane.timestamp as u64 || membrane.timestamp < 0 {
        bail!("envelope timestamp does not match inner timestamp");
    }
    verify_membrane_event_signature(&membrane, &event.pubkey.to_hex())?;
    Ok(membrane)
}

pub async fn subscribe_and_compute_bus_root(
    relay_url: &str,
    since: Option<i64>,
) -> Result<(Vec<MembraneEvent>, Option<String>)> {
    let events = fetch_membrane_events(relay_url, since, 1_000).await?;
    let root = bus_root_from_events(&events)?;
    Ok((events, root))
}

pub fn keys_from_nsec(nsec: &str) -> Result<Keys> {
    Keys::parse(nsec).context("parse NOSTR_NSEC")
}

#[derive(Debug, Clone)]
pub struct MembraneBusEvent {
    pub id: EventId,
    pub event: MembraneEvent,
}

pub async fn fetch_membrane_bus_events(
    relay_url: &str,
    since: Option<i64>,
    limit: usize,
) -> Result<Vec<MembraneBusEvent>> {
    let client = Client::new(Keys::generate());
    client.add_relay(relay_url).await?;
    client.connect().await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut filter = Filter::new()
        .kind(Kind::Custom(KIND_MEMBRANE))
        .kind(Kind::Custom(KIND_ALERT))
        .limit(limit);
    if let Some(s) = since {
        filter = filter.since(Timestamp::from(s as u64));
    }

    let events = client.fetch_events(filter, Duration::from_secs(10)).await?;
    let mut parsed = Vec::new();

    for event in events {
        match parse_membrane_event(&event) {
            Ok(me) => parsed.push(MembraneBusEvent {
                id: event.id,
                event: me,
            }),
            Err(err) => {
                warn!(event_id = %event.id.to_hex(), error = %err, "skip non-membrane event")
            }
        }
    }

    parsed.sort_by_key(|e| e.event.timestamp);
    Ok(parsed)
}

pub fn last_bus_event_id(bus_events: &[MembraneBusEvent], subject_pubkey: &str) -> Option<String> {
    bus_events
        .iter()
        .filter(|e| e.event.subject_pubkey == subject_pubkey)
        .rfind(|e| is_cp_event(e.event.event_type))
        .map(|e| e.id.to_hex())
}

pub async fn fetch_session_chain_bootstrap(
    relay_url: &str,
    subject_pubkey: &str,
) -> Result<(String, Option<String>, u64)> {
    let since = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64)
        - 86_400 * 7;
    let bus_events = fetch_membrane_bus_events(relay_url, Some(since), 5_000).await?;
    let membrane_events: Vec<_> = bus_events.iter().map(|e| e.event.clone()).collect();
    let last_cp_hash = last_cp_hash_from_events(&membrane_events, subject_pubkey);
    let last_event_id = last_bus_event_id(&bus_events, subject_pubkey);
    let session_nonce =
        crate::session::SessionChainState::from_bus_events(&membrane_events, subject_pubkey)
            .session_nonce;
    Ok((last_cp_hash, last_event_id, session_nonce))
}

pub fn npub_from_keys(keys: &Keys) -> Result<String> {
    keys.public_key().to_bech32().context("encode npub")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{MembranePayload, RouterSessionPayload};

    #[test]
    fn recovery_rejects_unsigned_spoofed_inner_events() {
        let attacker = Keys::generate();
        let operator = Keys::generate();
        let publisher = BusPublisher::new(BusPublisherConfig {
            relay_url: "memory://test".into(),
            keys: attacker.clone(),
        });
        let event = MembraneEvent::new(
            EventType::AlertDegraded,
            operator.public_key().to_hex(),
            "00".repeat(32),
            100,
            crate::session::alert_degraded_payload("subject_sever", "scope-a", None, 300),
        );
        let outer = publisher.to_nostr_event(&event, None).unwrap();
        assert!(parse_membrane_event(&outer).is_err());
    }

    #[test]
    fn recovery_verifies_both_signatures_and_kind() {
        let keys = Keys::generate();
        let publisher = BusPublisher::new(BusPublisherConfig {
            relay_url: "memory://test".into(),
            keys: keys.clone(),
        });
        let mut inner = MembraneEvent::new(
            EventType::AlertDegraded,
            "",
            "00".repeat(32),
            100,
            crate::session::alert_degraded_payload("subject_sever", "scope-a", None, 300),
        );
        publisher.sign_membrane_event(&mut inner).unwrap();
        let good = publisher.to_nostr_event(&inner, None).unwrap();
        assert!(parse_membrane_event(&good).is_ok());
        let wrong_kind = EventBuilder::new(
            Kind::Custom(KIND_MEMBRANE),
            serde_json::to_string(&inner).unwrap(),
        )
        .custom_created_at(Timestamp::from(100))
        .sign_with_keys(&keys)
        .unwrap();
        assert!(parse_membrane_event(&wrong_kind).is_err());
        inner.timestamp += 1;
        assert!(parse_membrane_event(&publisher.to_nostr_event(&inner, None).unwrap()).is_err());
        let mut bad_outer = good;
        bad_outer.content.push(' ');
        assert!(parse_membrane_event(&bad_outer).is_err());
    }
    #[test]
    fn maps_router_kind() {
        assert_eq!(membrane_kind_for(EventType::CpRouter), KIND_MEMBRANE);
        assert_eq!(membrane_kind_for(EventType::AlertDegraded), KIND_ALERT);
    }

    #[test]
    fn builds_nostr_event() {
        let keys = Keys::generate();
        let publisher = BusPublisher::new(BusPublisherConfig {
            relay_url: "ws://localhost:7777".into(),
            keys: keys.clone(),
        });
        let mut event = MembraneEvent::new(
            EventType::CpRouter,
            "",
            "00".repeat(32),
            1_700_000_000,
            MembranePayload::Router(RouterSessionPayload {
                model_id: "demo".into(),
                context_merkle_root: "aa".repeat(32),
                session_nonce: 1,
                parent_cp_hash: "bb".repeat(32),
                iac_hash: "cc".repeat(32),
                scope_id: None,
                tool_id: None,
            }),
        );
        publisher.sign_membrane_event(&mut event).unwrap();
        let nostr = publisher.to_nostr_event(&event, None).unwrap();
        assert_eq!(nostr.kind, Kind::Custom(KIND_MEMBRANE));
    }
}
