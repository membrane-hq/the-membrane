pub mod oidc;
pub mod operations;
use membrane_core::event::{EventType, MembraneEvent, MembranePayload, RouterSessionPayload};
use membrane_core::iac::IntentAuthorizationCredential;
use membrane_core::merkle::{Domain, MerkleTree};
use membrane_core::nostr_bus::BusPublisher;
use membrane_core::rollup::cp_hash_hex;
use membrane_core::{
    alert_degraded_payload, map_and_spawn_siem_ship, SessionChainState, SiemWebhookShipper,
};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GateError {
    #[error("caller authentication failed: {0}")]
    IdentityAuthentication(String),
    #[error("identity grant denied: {0}")]
    IdentityGrant(String),
    #[error("identity grant outside its time window: {0}")]
    GrantWindow(String),
    #[error("no valid IAC: {0}")]
    NoValidIac(String),
    #[error("invalid IAC signature: {0}")]
    InvalidIacSignature(String),
    #[error("channel not permitted: {0}")]
    ChannelDenied(String),
    #[error("model not in allowlist: {0}")]
    ModelDenied(String),
    #[error("tool not in allowlist: {0}")]
    ToolDenied(String),
    #[error("repo not in allowlist: {0}")]
    RepoDenied(String),
    #[error("export forbidden: {0}")]
    ExportForbidden(String),
    #[error("context merkle root exceeds IAC bound")]
    ContextBoundExceeded,
    #[error("session degraded ({0}): {1}")]
    SessionDegraded(String, String),
    #[error("router CP stale: last CP {0}s ago exceeds Δt={1}s")]
    SessionStale(i64, u64),
    #[error("connector misconfigured: {0}")]
    Connector(String),
    #[error("registry error: {0}")]
    Registry(String),
    #[error("spend denied: {0}")]
    Spend(String),
    #[error("SIEM export: {0}")]
    SiemExport(String),
    #[error("bus error: {0}")]
    Bus(#[from] anyhow::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelRegistry {
    /// Exact caller public keys. Empty or absent denies every production caller.
    #[serde(default)]
    pub identities: std::collections::BTreeMap<String, identity::IdentityGrant>,
    pub permitted_channels: Vec<String>,
    pub forbidden_exports: Vec<String>,
    pub model_allowlist: Vec<String>,
    #[serde(default = "default_delta_t_secs")]
    pub delta_t_secs: u64,
    #[serde(default, alias = "llama_cpp_url", alias = "ollama_url")]
    pub model_api_url: Option<String>,
    /// Explicit `owner/name` repos the GitHub connector may touch. Empty = deny all.
    #[serde(default)]
    pub github_repo_allowlist: Vec<String>,
    /// Approval gates. Absent means out-of-scope tool calls are blocked, never held.
    #[serde(default)]
    pub approval: Option<approval::ApprovalPolicy>,
}

fn default_delta_t_secs() -> u64 {
    300
}

impl ChannelRegistry {
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path.as_ref())?;
        Ok(serde_yaml::from_str(&text)?)
    }
}

/// Inputs for a blocked-action event published without a receipt.
#[derive(Debug, Clone, Copy)]
pub struct BlockedAction<'a> {
    pub scope_id: Option<&'a str>,
    pub model_id: Option<&'a str>,
    pub tool_id: Option<&'a str>,
    pub tool_allowlist: &'a [String],
    pub iac_hash: Option<&'a str>,
    pub reason: &'a str,
    pub now: i64,
    pub last_cp_hash: &'a str,
    pub prev_event_id: Option<&'a str>,
}

/// Inputs for a blocked-action event kept as a signed receipt.
#[derive(Debug, Clone, Copy)]
pub struct BlockedReceipt<'a> {
    pub scope_id: Option<&'a str>,
    pub model_id: &'a str,
    pub tool_id: &'a str,
    pub iac_hash: Option<&'a str>,
    pub reason: &'a str,
    pub now: i64,
    pub last_cp_hash: &'a str,
    pub prev_event_id: Option<&'a str>,
}

pub struct Gate {
    registry: ChannelRegistry,
    publisher: BusPublisher,
    iac_signer_pubkey: String,
    operator_oidc: Option<oidc::OperatorOidc>,
    siem_shipper: Option<Arc<SiemWebhookShipper>>,
    siem_export: Option<Arc<siem_export::SiemExporter>>,
    identity_registry_path: Option<std::path::PathBuf>,
    caller_challenge: String,
    replay: std::sync::Mutex<std::collections::BTreeMap<String, i64>>,
}

#[derive(Debug, Clone)]
pub struct RouterSessionRequest {
    pub model_id: String,
    pub context_chunks: Vec<Vec<u8>>,
    pub session_nonce: u64,
    pub parent_cp_hash: String,
    /// Recorded in the signed event so receipts bind scope and tool.
    pub scope_id: Option<String>,
    pub tool_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RouterSessionOutcome {
    pub event: MembraneEvent,
    pub bus_event: nostr::Event,
    pub context_merkle_root: String,
    pub cp_hash: String,
    pub bus_event_id: Option<String>,
}

impl Gate {
    pub fn new(registry: ChannelRegistry, publisher: BusPublisher) -> Self {
        let iac_signer_pubkey = publisher.keys().public_key().to_hex();
        Self {
            registry,
            publisher,
            iac_signer_pubkey,
            operator_oidc: None,
            siem_shipper: None,
            siem_export: None,
            identity_registry_path: None,
            caller_challenge: nostr::Keys::generate().public_key().to_hex(),
            replay: Default::default(),
        }
    }

    /// Re-read operator identity grants for each request. A bad/missing file denies.
    pub fn with_identity_registry_path(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.identity_registry_path = Some(path.into());
        self
    }

    pub fn with_siem_shipper(mut self, shipper: Arc<SiemWebhookShipper>) -> Self {
        self.siem_shipper = Some(shipper);
        self
    }

    pub fn with_siem_export(mut self, exporter: Arc<siem_export::SiemExporter>) -> Self {
        self.siem_export = Some(exporter);
        self
    }

    pub fn siem_export(&self) -> Option<&Arc<siem_export::SiemExporter>> {
        self.siem_export.as_ref()
    }

    /// Refuses new authorizations when a `fail_closed` export cannot keep up.
    pub fn siem_admission(&self) -> Result<(), GateError> {
        match &self.siem_export {
            Some(e) => e.admission(),
            None => Ok(()),
        }
    }

    pub fn siem_shipper(&self) -> Option<&Arc<SiemWebhookShipper>> {
        self.siem_shipper.as_ref()
    }

    pub fn registry(&self) -> &ChannelRegistry {
        &self.registry
    }

    fn enqueue_siem(&self, event: &MembraneEvent, bus_event_id: Option<&str>) {
        map_and_spawn_siem_ship(&self.siem_shipper, event, bus_event_id);
        if let Some(exporter) = &self.siem_export {
            exporter.enqueue(membrane_core::SiemEvent::from_membrane_event(
                event,
                bus_event_id,
            ));
        }
    }

    pub fn validate_iac(
        &self,
        iac: Option<&IntentAuthorizationCredential>,
        now: i64,
    ) -> Result<(), GateError> {
        let iac = iac.ok_or_else(|| GateError::NoValidIac("missing IAC".into()))?;
        iac.verify_signature(&self.iac_signer_pubkey)
            .map_err(|e| GateError::InvalidIacSignature(e.to_string()))?;
        if !iac.is_valid_at(now) {
            return Err(GateError::NoValidIac("IAC expired".into()));
        }
        if !iac.permits_channel("local-llm") {
            return Err(GateError::ChannelDenied(
                "IAC does not permit local-llm".into(),
            ));
        }
        for channel in &self.registry.permitted_channels {
            if !iac.permits_channel(channel) {
                return Err(GateError::ChannelDenied(channel.clone()));
            }
        }
        Ok(())
    }

    pub fn check_session_liveness(
        &self,
        chain: &SessionChainState,
        scope_id: &str,
        now: i64,
    ) -> Result<(), GateError> {
        if chain.is_scope_degraded(scope_id) {
            let reason = chain
                .degraded_scopes
                .get(scope_id)
                .map(|(reason, _)| reason.clone())
                .or_else(|| chain.degraded_reason.clone())
                .unwrap_or_else(|| "degraded".into());
            return Err(GateError::SessionDegraded(scope_id.to_string(), reason));
        }
        if chain
            .scope_router_cp_age_secs(scope_id, now)
            .is_some_and(|age| age > self.registry.delta_t_secs as i64)
        {
            let age = chain
                .scope_router_cp_age_secs(scope_id, now)
                .unwrap_or(self.registry.delta_t_secs as i64);
            return Err(GateError::SessionStale(age, self.registry.delta_t_secs));
        }
        Ok(())
    }

    pub async fn publish_alert_degraded(
        &self,
        scope_id: &str,
        reason: &str,
        now: i64,
        last_cp_hash: &str,
        last_cp_age_secs: Option<i64>,
        prev_event_id: Option<&str>,
    ) -> Result<String, GateError> {
        let payload = alert_degraded_payload(
            reason,
            scope_id,
            last_cp_age_secs,
            self.registry.delta_t_secs,
        );
        let mut event =
            MembraneEvent::new(EventType::AlertDegraded, "", last_cp_hash, now, payload);
        let id = self
            .publisher
            .publish(&mut event, prev_event_id)
            .await
            .map_err(GateError::Bus)?
            .to_hex();
        self.enqueue_siem(&event, Some(&id));
        Ok(id)
    }

    /// Publish a blocked-action event for a request that carried no usable scope.
    pub async fn publish_action_blocked(
        &self,
        blocked: &BlockedAction<'_>,
    ) -> Result<String, GateError> {
        let BlockedAction {
            scope_id,
            model_id,
            tool_id,
            tool_allowlist,
            iac_hash,
            reason,
            now,
            last_cp_hash,
            prev_event_id,
        } = *blocked;
        let payload = MembranePayload::Generic(serde_json::json!({
            "scope_id": scope_id,
            "model_allowlist": model_id.into_iter().collect::<Vec<_>>(),
            "tool_id": tool_id,
            "tool_allowlist": tool_allowlist,
            "iac_hash": iac_hash,
            "reason": reason,
        }));
        let mut event =
            MembraneEvent::new(EventType::ActionBlocked, "", last_cp_hash, now, payload);
        let id = self
            .publisher
            .publish(&mut event, prev_event_id)
            .await
            .map_err(GateError::Bus)?
            .to_hex();
        self.enqueue_siem(&event, Some(&id));
        Ok(id)
    }

    /// Like `publish_action_blocked`, but returns the signed event so
    /// callers can keep it as a receipt.
    pub async fn publish_action_blocked_event(
        &self,
        receipt: &BlockedReceipt<'_>,
    ) -> Result<(MembraneEvent, nostr::Event), GateError> {
        let BlockedReceipt {
            scope_id,
            model_id,
            tool_id,
            iac_hash,
            reason,
            now,
            last_cp_hash,
            prev_event_id,
        } = *receipt;
        let payload = MembranePayload::Generic(serde_json::json!({
            "scope_id": scope_id,
            "model_id": model_id,
            "tool_id": tool_id,
            "iac_hash": iac_hash,
            "reason": reason,
        }));
        let mut event =
            MembraneEvent::new(EventType::ActionBlocked, "", last_cp_hash, now, payload);
        let bus_event = self
            .publisher
            .publish_with_receipt(&mut event, prev_event_id)
            .await
            .map_err(GateError::Bus)?;
        let id = bus_event.id.to_hex();
        self.enqueue_siem(&event, Some(&id));
        Ok((event, bus_event))
    }

    /// Publish the operator's decision on a held call as a signed bus event, so the
    /// hold, the decision and the execution all sit in the receipt chain.
    pub async fn publish_approval_decision(
        &self,
        decision: serde_json::Value,
        now: i64,
        last_cp_hash: &str,
        prev_event_id: Option<&str>,
    ) -> Result<String, GateError> {
        let payload = MembranePayload::Generic(decision);
        let mut event =
            MembraneEvent::new(EventType::ApprovalDecision, "", last_cp_hash, now, payload);
        let id = self
            .publisher
            .publish(&mut event, prev_event_id)
            .await
            .map_err(GateError::Bus)?
            .to_hex();
        self.enqueue_siem(&event, Some(&id));
        Ok(id)
    }

    pub async fn open_router_session(
        &self,
        iac: Option<&IntentAuthorizationCredential>,
        req: RouterSessionRequest,
        now: i64,
        prev_event_id: Option<&str>,
    ) -> Result<RouterSessionOutcome, GateError> {
        self.validate_iac(iac, now)?;
        let iac = iac.expect("validated");

        if !iac.model_allowed(&req.model_id) {
            return Err(GateError::ModelDenied(req.model_id.clone()));
        }
        if !self.registry.model_allowlist.contains(&req.model_id) {
            return Err(GateError::ModelDenied(req.model_id.clone()));
        }
        for export in &self.registry.forbidden_exports {
            if !iac.forbidden_exports.iter().any(|f| f == export) {
                return Err(GateError::ExportForbidden(format!(
                    "IAC missing forbidden export: {export}"
                )));
            }
        }

        let context_merkle_root = context_root_hex(&req.context_chunks)?;
        if context_merkle_root > iac.context_merkle_bound {
            return Err(GateError::ContextBoundExceeded);
        }

        let iac_hash = iac
            .hash_hex()
            .map_err(|e| GateError::Bus(anyhow::anyhow!(e)))?;

        let mut event = MembraneEvent::new(
            EventType::CpRouter,
            "",
            req.parent_cp_hash.clone(),
            now,
            MembranePayload::Router(RouterSessionPayload {
                model_id: req.model_id,
                context_merkle_root: context_merkle_root.clone(),
                session_nonce: req.session_nonce,
                parent_cp_hash: req.parent_cp_hash,
                iac_hash,
                scope_id: req.scope_id,
                tool_id: req.tool_id,
            }),
        );

        let bus_event = self
            .publisher
            .publish_with_receipt(&mut event, prev_event_id)
            .await
            .map_err(GateError::Bus)?;
        let bus_event_id = bus_event.id.to_hex();
        self.enqueue_siem(&event, Some(&bus_event_id));

        let cp_hash = cp_hash_hex(&event).map_err(GateError::Bus)?;

        Ok(RouterSessionOutcome {
            event,
            bus_event,
            context_merkle_root,
            cp_hash,
            bus_event_id: Some(bus_event_id),
        })
    }

    /// Fail-closed tool check against the live IAC (product agent scopes).
    pub fn authorize_tool(
        &self,
        iac: &IntentAuthorizationCredential,
        tool_id: &str,
        now: i64,
    ) -> Result<(), GateError> {
        self.validate_iac(Some(iac), now)?;
        if !iac.tool_allowed(tool_id) {
            return Err(GateError::ToolDenied(tool_id.to_string()));
        }
        Ok(())
    }

    pub fn publisher_pubkey_hex(&self) -> String {
        self.iac_signer_pubkey.clone()
    }

    pub fn publisher(&self) -> &BusPublisher {
        &self.publisher
    }
}

pub fn context_root_hex(chunks: &[Vec<u8>]) -> Result<String, GateError> {
    let tree = MerkleTree::from_domain_leaves(Domain::FeatureChunk, chunks);
    tree.root_hex()
        .ok_or_else(|| GateError::Registry("empty context".into()))
}

pub mod alarm;
pub mod approval;
pub mod audit;
pub mod demo;
pub mod github;
pub mod identity;
pub mod liveness;
pub mod proxy;
pub mod readings;
pub mod routstr;
pub mod server;
pub mod siem_export;
pub mod spend;
pub mod watchdog;

pub use demo::{
    demo_registry, run_demo_dashboard, verify_evidence_pack, verify_evidence_pack_pinned,
    DemoRuntime, DemoServerState, EvidencePack, DEMO_ALLOWED_TOOLS, DEMO_BLOCKED_TOOL, DEMO_MODEL,
    DEMO_SWAP_MODEL, DEMO_TTL_SECS,
};
pub use github::{
    authorize_repo_and_args, body_sha256_hex, is_github_tool, GitHubConnector,
    GitHubConnectorConfig, GitHubConnectorError, ToolInvokeRequest, ToolReceiptContext,
    ENV_TOKEN_FALLBACK, ENV_TOKEN_PRIMARY, TOOL_GITHUB_COMMENT, TOOL_GITHUB_ISSUE_READ,
    TOOL_GITHUB_MERGE,
};
pub use proxy::{ChatMessage, ChatRequest, ChatResponse, LlmProxy};
pub use server::{run_gate_server, GateServerState, SessionReceipt};

#[cfg(test)]
mod tests {
    use super::*;
    use membrane_core::{
        alert_degraded_payload, BusPublisher, BusPublisherConfig, ALERT_REASON_SUBJECT_SEVER,
    };
    use nostr::Keys;

    fn test_gate(delta_t: u64) -> Gate {
        let keys = Keys::generate();
        let registry = ChannelRegistry {
            approval: None,
            identities: Default::default(),
            permitted_channels: vec!["local-llm".into()],
            forbidden_exports: vec!["cloud-telemetry".into(), "training-retention".into()],
            model_allowlist: vec!["demo".into()],
            delta_t_secs: delta_t,
            model_api_url: None,
            github_repo_allowlist: vec![],
        };
        let publisher = BusPublisher::new(BusPublisherConfig {
            relay_url: "ws://localhost:7777".into(),
            keys,
        });
        Gate::new(registry, publisher)
    }

    #[test]
    fn rejects_degraded_scope() {
        let gate = test_gate(300);
        let mut chain = SessionChainState::genesis();
        chain.mark_degraded("scope-a", ALERT_REASON_SUBJECT_SEVER, 100);
        let err = gate
            .check_session_liveness(&chain, "scope-a", 200)
            .unwrap_err();
        assert!(matches!(err, GateError::SessionDegraded(_, _)));
    }

    #[test]
    fn rejects_stale_router_cp() {
        let gate = test_gate(300);
        let mut chain = SessionChainState::genesis();
        chain.active_scope_id = Some("scope-a".into());
        chain.last_router_cp_at = Some(1_000);
        let err = gate
            .check_session_liveness(&chain, "scope-a", 1_400)
            .unwrap_err();
        assert!(matches!(err, GateError::SessionStale(400, 300)));
    }

    #[test]
    fn fresh_router_cp_passes() {
        let gate = test_gate(300);
        let mut chain = SessionChainState::genesis();
        chain.active_scope_id = Some("scope-a".into());
        chain.last_router_cp_at = Some(1_000);
        gate.check_session_liveness(&chain, "scope-a", 1_200)
            .unwrap();
    }

    #[test]
    fn alert_payload_includes_delta_t() {
        let payload = alert_degraded_payload("subject_sever", "scope-x", Some(10), 300);
        let MembranePayload::Generic(v) = payload else {
            panic!("expected generic");
        };
        assert_eq!(v["reason"], "subject_sever");
        assert_eq!(v["delta_t_secs"], 300);
    }

    #[test]
    fn rejects_unknown_tool() {
        let keys = Keys::generate();
        let registry = ChannelRegistry {
            approval: None,
            identities: Default::default(),
            permitted_channels: vec!["local-llm".into()],
            forbidden_exports: vec!["cloud-telemetry".into(), "training-retention".into()],
            model_allowlist: vec!["demo".into()],
            delta_t_secs: 300,
            model_api_url: None,
            github_repo_allowlist: vec!["acme/pilot".into()],
        };
        let publisher = BusPublisher::new(BusPublisherConfig {
            relay_url: "memory://test".into(),
            keys: keys.clone(),
        });
        let gate = Gate::new(registry, publisher);
        let mut iac = IntentAuthorizationCredential::new_session_with_tools(
            "scope",
            "demo",
            "0".repeat(64),
            4_102_444_800,
            vec!["local-llm".into()],
            vec!["cloud-telemetry".into(), "training-retention".into()],
            vec!["github.comment".into()],
        );
        iac.sign(&keys).unwrap();
        let err = gate
            .authorize_tool(&iac, "github.merge", 1_000)
            .unwrap_err();
        assert!(matches!(err, GateError::ToolDenied(_)));
        gate.authorize_tool(&iac, "github.comment", 1_000).unwrap();
    }
}

pub mod reconciliation;
