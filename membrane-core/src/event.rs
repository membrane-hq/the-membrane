use crate::canonical::canonical_json_bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SCHEMA_VERSION: &str = "0.9.14";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    #[serde(rename = "membrane.cp.liveness")]
    CpLiveness,
    #[serde(rename = "membrane.cp.router")]
    CpRouter,
    #[serde(rename = "membrane.cp.bci")]
    CpBci,
    #[serde(rename = "membrane.iac")]
    Iac,
    #[serde(rename = "membrane.anchor.ots")]
    AnchorOts,
    #[serde(rename = "membrane.alert.degraded")]
    AlertDegraded,
    #[serde(rename = "membrane.action.blocked")]
    ActionBlocked,
    #[serde(rename = "membrane.approval.decision")]
    ApprovalDecision,
}

impl EventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CpLiveness => "membrane.cp.liveness",
            Self::CpRouter => "membrane.cp.router",
            Self::CpBci => "membrane.cp.bci",
            Self::Iac => "membrane.iac",
            Self::AnchorOts => "membrane.anchor.ots",
            Self::AlertDegraded => "membrane.alert.degraded",
            Self::ActionBlocked => "membrane.action.blocked",
            Self::ApprovalDecision => "membrane.approval.decision",
        }
    }

    pub fn nostr_tag_suffix(&self) -> &'static str {
        match self {
            Self::CpLiveness => "the-membrane-liveness",
            Self::CpRouter => "the-membrane-router",
            Self::CpBci => "the-membrane-bci",
            Self::Iac => "the-membrane-iac",
            Self::AnchorOts => "the-membrane-anchor-ots",
            Self::AlertDegraded => "the-membrane-alert-degraded",
            Self::ActionBlocked => "the-membrane-action-blocked",
            Self::ApprovalDecision => "the-membrane-approval-decision",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MembranePayload {
    Router(RouterSessionPayload),
    Generic(serde_json::Value),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterSessionPayload {
    pub model_id: String,
    pub context_merkle_root: String,
    pub session_nonce: u64,
    pub parent_cp_hash: String,
    pub iac_hash: String,
    /// Scope the call ran under. Covered by the event hash and signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_id: Option<String>,
    /// Tool the call invoked, when the gate routed a tool call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembraneEvent {
    pub version: String,
    #[serde(rename = "type")]
    pub event_type: EventType,
    pub subject_pubkey: String,
    pub prev_cp_hash: String,
    pub timestamp: i64,
    pub payload: MembranePayload,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignableMembraneEvent {
    pub version: String,
    #[serde(rename = "type")]
    pub event_type: EventType,
    pub subject_pubkey: String,
    pub prev_cp_hash: String,
    pub timestamp: i64,
    pub payload: MembranePayload,
}

impl MembraneEvent {
    pub fn new(
        event_type: EventType,
        subject_pubkey: impl Into<String>,
        prev_cp_hash: impl Into<String>,
        timestamp: i64,
        payload: MembranePayload,
    ) -> Self {
        Self {
            version: SCHEMA_VERSION.to_string(),
            event_type,
            subject_pubkey: subject_pubkey.into(),
            prev_cp_hash: prev_cp_hash.into(),
            timestamp,
            payload,
            signature: None,
        }
    }

    pub fn signable_view(&self) -> SignableMembraneEvent {
        SignableMembraneEvent {
            version: self.version.clone(),
            event_type: self.event_type,
            subject_pubkey: self.subject_pubkey.clone(),
            prev_cp_hash: self.prev_cp_hash.clone(),
            timestamp: self.timestamp,
            payload: self.payload.clone(),
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, crate::canonical::CanonicalError> {
        canonical_json_bytes(&self.signable_view())
    }

    pub fn digest(&self) -> Result<[u8; 32], crate::canonical::CanonicalError> {
        let bytes = self.canonical_bytes()?;
        Ok(Sha256::digest(bytes).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn router_payload_roundtrip() {
        let event = MembraneEvent::new(
            EventType::CpRouter,
            "abc123",
            "0000000000000000000000000000000000000000000000000000000000000000",
            1_700_000_000,
            MembranePayload::Router(RouterSessionPayload {
                model_id: "sha256:demo".into(),
                context_merkle_root: "deadbeef".into(),
                session_nonce: 1,
                parent_cp_hash: "cafe".into(),
                iac_hash: "babe".into(),
                scope_id: None,
                tool_id: None,
            }),
        );
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("membrane.cp.router"));
    }
}
