//! Vendor-neutral SIEM export records for Membrane authorization telemetry.
//!
//! The JSON Lines record is the stable Membrane schema. The OCSF projection is
//! deliberately labelled "OCSF-inspired": certified class identifiers are not
//! claimed until the mapping has been validated against a pinned OCSF release.

use crate::{cp_hash_hex, EventType, MembraneEvent, MembranePayload};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const SIEM_SCHEMA_VERSION: &str = "1.0.0";
pub const OCSF_INSPIRED_SCHEMA: &str = "ocsf-inspired-1.0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SiemEvent {
    pub schema_version: String,
    pub timestamp: i64,
    pub event_id: String,
    pub event_type: String,
    pub outcome: String,
    pub severity: String,
    pub agent_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub models: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_receipt_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub simulation: bool,
    pub source_event_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsfInspiredPack {
    pub format: String,
    pub schema: String,
    pub schema_note: String,
    pub exported_at: i64,
    pub events: Vec<Value>,
}

impl SiemEvent {
    /// Map a signed attestation-bus event without carrying signatures, payload
    /// bodies, prompts, credentials, or other plaintext secret material.
    pub fn from_membrane_event(event: &MembraneEvent, source_event_id: Option<&str>) -> Self {
        let generic = match &event.payload {
            MembranePayload::Generic(value) => Some(value),
            MembranePayload::Router(_) => None,
        };
        let reason = string_field(generic, "reason");
        let scope_id = string_field(generic, "scope_id");
        let mut models = string_array_field(generic, "model_allowlist");
        let tools = string_array_field(generic, "tool_allowlist");
        let policy_hash = string_field(generic, "iac_hash");
        let session_id = string_field(generic, "session_id");

        let (event_type, outcome, severity, receipt_hash) = match &event.payload {
            MembranePayload::Router(payload) if event.event_type == EventType::CpRouter => {
                models.push(payload.model_id.clone());
                (
                    "allowed_action",
                    "allowed",
                    "informational",
                    cp_hash_hex(event).ok(),
                )
            }
            _ if event.event_type == EventType::Iac => (
                "authorization_issued",
                "issued",
                "informational",
                event.digest().ok().map(hex::encode),
            ),
            _ if event.event_type == EventType::ActionBlocked => (
                "blocked_action",
                "blocked",
                "high",
                event.digest().ok().map(hex::encode),
            ),
            _ if event.event_type == EventType::ApprovalDecision => (
                "approval_decision",
                "decided",
                "informational",
                event.digest().ok().map(hex::encode),
            ),
            _ if event.event_type == EventType::AlertDegraded
                && reason.as_deref() == Some("subject_sever") =>
            {
                (
                    "sever",
                    "severed",
                    "high",
                    event.digest().ok().map(hex::encode),
                )
            }
            _ if event.event_type == EventType::AlertDegraded => (
                "degraded",
                "degraded",
                "high",
                event.digest().ok().map(hex::encode),
            ),
            _ => (
                "membrane_telemetry",
                "observed",
                "informational",
                event.digest().ok().map(hex::encode),
            ),
        };

        let router_policy_hash = match &event.payload {
            MembranePayload::Router(payload) => Some(payload.iac_hash.clone()),
            _ => None,
        };
        let router_session_id = match &event.payload {
            MembranePayload::Router(payload) => Some(payload.session_nonce.to_string()),
            _ => None,
        };

        Self {
            schema_version: SIEM_SCHEMA_VERSION.into(),
            timestamp: event.timestamp,
            event_id: source_event_id
                .map(str::to_owned)
                .or_else(|| receipt_hash.clone())
                .unwrap_or_else(|| format!("{}:{}", event.event_type.as_str(), event.timestamp)),
            event_type: event_type.into(),
            outcome: outcome.into(),
            severity: severity.into(),
            agent_id: event.subject_pubkey.clone(),
            session_id: session_id.or(router_session_id),
            scope_id,
            models,
            tools,
            policy_hash: policy_hash.or(router_policy_hash),
            receipt_hash,
            parent_receipt_hash: nonzero_hash(&event.prev_cp_hash),
            reason,
            simulation: false,
            source_event_type: event.event_type.as_str().into(),
        }
    }

    pub fn to_ocsf_inspired(&self) -> Value {
        let status = match self.outcome.as_str() {
            "allowed" | "issued" | "observed" => "Success",
            "blocked" | "severed" | "degraded" => "Failure",
            _ => "Unknown",
        };
        json!({
            "time": self.timestamp.saturating_mul(1000),
            "category_name": "Identity & Access Management",
            "class_name": "Authorization and Action Receipt",
            "activity_name": activity_name(&self.event_type),
            "severity": self.severity,
            "status": status,
            "status_detail": self.reason,
            "actor": {
                "user": { "uid": self.agent_id }
            },
            "session": {
                "uid": self.session_id,
                "scope_id": self.scope_id
            },
            "api": {
                "operation": self.tools.first(),
                "service": { "name": "The Membrane" }
            },
            "model": {
                "name": self.models.first()
            },
            "policy": {
                "uid": self.policy_hash
            },
            "metadata": {
                "product": {
                    "name": "The Membrane",
                    "vendor_name": "The Membrane"
                },
                "version": SIEM_SCHEMA_VERSION,
                "log_name": "membrane.action_receipt",
                "profiles": ["membrane/action-receipt"]
            },
            "unmapped": {
                "membrane": self
            }
        })
    }
}

pub fn render_jsonl(events: &[SiemEvent]) -> Result<String, serde_json::Error> {
    let mut output = String::new();
    for event in events {
        output.push_str(&serde_json::to_string(event)?);
        output.push('\n');
    }
    Ok(output)
}

pub fn build_ocsf_inspired_pack(events: &[SiemEvent], exported_at: i64) -> OcsfInspiredPack {
    OcsfInspiredPack {
        format: "ocsf".into(),
        schema: OCSF_INSPIRED_SCHEMA.into(),
        schema_note:
            "OCSF-inspired projection; no certified OCSF class or activity identifiers are claimed."
                .into(),
        exported_at,
        events: events.iter().map(SiemEvent::to_ocsf_inspired).collect(),
    }
}

fn string_field(value: Option<&Value>, name: &str) -> Option<String> {
    value?
        .get(name)?
        .as_str()
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn string_array_field(value: Option<&Value>, name: &str) -> Vec<String> {
    value
        .and_then(|value| value.get(name))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn nonzero_hash(value: &str) -> Option<String> {
    (!value.is_empty() && value.bytes().any(|byte| byte != b'0')).then(|| value.to_owned())
}

fn activity_name(event_type: &str) -> &'static str {
    match event_type {
        "authorization_issued" => "Authorization Issued",
        "allowed_action" => "Action Allowed",
        "blocked_action" => "Action Blocked",
        "sever" => "Session Severed",
        "degraded" => "Session Degraded or Stale",
        _ => "Membrane Telemetry",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MembranePayload, RouterSessionPayload, GENESIS_CP_HASH};

    #[test]
    fn maps_router_receipt_to_allowed_action() {
        let event = MembraneEvent::new(
            EventType::CpRouter,
            "agent-1",
            "ab".repeat(32),
            1_700_000_000,
            MembranePayload::Router(RouterSessionPayload {
                model_id: "allowlisted-model".into(),
                context_merkle_root: "cd".repeat(32),
                session_nonce: 7,
                parent_cp_hash: "ab".repeat(32),
                iac_hash: "ef".repeat(32),
                scope_id: None,
                tool_id: None,
            }),
        );
        let mapped = SiemEvent::from_membrane_event(&event, Some("bus-1"));
        assert_eq!(mapped.event_type, "allowed_action");
        assert_eq!(mapped.outcome, "allowed");
        assert_eq!(mapped.models, vec!["allowlisted-model"]);
        assert_eq!(mapped.policy_hash, Some("ef".repeat(32)));
        assert!(mapped.receipt_hash.is_some());
    }

    #[test]
    fn maps_sever_and_stale_alerts() {
        for (reason, expected_type) in
            [("subject_sever", "sever"), ("delta_t_exceeded", "degraded")]
        {
            let event = MembraneEvent::new(
                EventType::AlertDegraded,
                "agent-1",
                GENESIS_CP_HASH,
                1_700_000_000,
                MembranePayload::Generic(json!({
                    "scope_id": "scope-1",
                    "reason": reason
                })),
            );
            let mapped = SiemEvent::from_membrane_event(&event, None);
            assert_eq!(mapped.event_type, expected_type);
            assert_eq!(mapped.reason.as_deref(), Some(reason));
        }
    }

    #[test]
    fn jsonl_roundtrip_and_ocsf_sanity() {
        let record = SiemEvent {
            schema_version: SIEM_SCHEMA_VERSION.into(),
            timestamp: 1_700_000_000,
            event_id: "act-1".into(),
            event_type: "blocked_action".into(),
            outcome: "blocked".into(),
            severity: "high".into(),
            agent_id: "agent-1".into(),
            session_id: Some("session-1".into()),
            scope_id: Some("scope-1".into()),
            models: vec!["allowlisted-model".into()],
            tools: vec!["tool.write".into()],
            policy_hash: Some("aa".repeat(32)),
            receipt_hash: None,
            parent_receipt_hash: Some("bb".repeat(32)),
            reason: Some("tool not in allowlist".into()),
            simulation: true,
            source_event_type: "demo.timeline.blocked".into(),
        };
        let rendered = render_jsonl(std::slice::from_ref(&record)).unwrap();
        let decoded: SiemEvent = serde_json::from_str(rendered.trim()).unwrap();
        assert_eq!(decoded, record);

        let ocsf = record.to_ocsf_inspired();
        assert_eq!(ocsf["activity_name"], "Action Blocked");
        assert_eq!(ocsf["status"], "Failure");
        assert_eq!(ocsf["time"], 1_700_000_000_000_i64);
        assert!(ocsf.get("class_uid").is_none());
    }
}
