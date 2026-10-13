//! Local UI verification fixture. Synthetic rows; no external tool calls or credentials.
use membrane_core::{BusPublisher, BusPublisherConfig, SessionChainState};
use membrane_gate::{
    audit::{bind, AuditLog},
    ChannelRegistry, Gate, GateServerState, GitHubConnector, GitHubConnectorConfig, LlmProxy,
};
use std::sync::Arc;
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let registry = ChannelRegistry {
        approval: None,
        identities: Default::default(),
        permitted_channels: vec!["local-llm".into()],
        forbidden_exports: vec!["cloud-telemetry".into(), "training-retention".into()],
        model_allowlist: vec!["local-model".into()],
        delta_t_secs: 300,
        model_api_url: None,
        github_repo_allowlist: vec!["acme/pilot".into()],
    };
    let keys = nostr::Keys::generate();
    let gate = Arc::new(Gate::new(
        registry,
        BusPublisher::new(BusPublisherConfig {
            relay_url: "memory://audit-preview".into(),
            keys,
        }),
    ));
    let audit = Arc::new(AuditLog::default());
    for (outcome, rule, scope, action) in [
        (
            "allow",
            "all_authorization_checks_passed",
            Some("preview-scope".into()),
            "chat",
        ),
        ("deny", "tool_allowlist", None, "tool"),
        ("deny", "iac_signature", None, "chat"),
    ] {
        audit.record(outcome, rule, gate.publisher_pubkey_hex(), scope, action);
    }
    for (outcome, rule, action, id) in [
        (
            "allow",
            "all_authorization_checks_passed",
            "chat",
            "a1b2c3d4e5f60718",
        ),
        (
            "allow",
            "all_authorization_checks_passed",
            "chat",
            "a1b2c3d4e5f60718",
        ),
        (
            "allow",
            "all_authorization_checks_passed",
            "tool",
            "a1b2c3d4e5f60718",
        ),
        ("deny", "tool_allowlist", "tool", "9f8e7d6c5b4a3921"),
        ("deny", "repository_allowlist", "tool", "9f8e7d6c5b4a3921"),
    ] {
        audit.record_authenticated(
            outcome,
            rule,
            gate.publisher_pubkey_hex(),
            None,
            action,
            None,
            Some(id.into()),
        );
    }
    audit.record_alarm(
        membrane_gate::alarm::Alarm {
            kind: membrane_gate::alarm::AlarmKind::FirstSeenIdentity,
            raised_at: chrono::Utc::now().timestamp(),
            identity: Some("9f8e7d6c5b4a3921".into()),
            summary: "Synthetic preview alarm: first request from a new identity.".into(),
        },
        membrane_gate::alarm::Delivery::NotConfigured,
    );
    let state = GateServerState {
        gate,
        proxy: Arc::new(LlmProxy::new(None).with_dev_mock(true)),
        default_iac: None,
        session_chain: Arc::new(tokio::sync::Mutex::new(SessionChainState::genesis())),
        operations: Arc::new(membrane_gate::operations::OperationJournal::from_env()),
        github: Arc::new(GitHubConnector::new(GitHubConnectorConfig {
            repo_allowlist: vec![],
            api_base: "http://127.0.0.1:1".into(),
            token: None,
        })),
        audit,
        spend: None,
        approvals: None,
    };
    let task = bind(state, "127.0.0.1:8788").await?;
    println!("Synthetic audit preview on 127.0.0.1:8788; not a running production gate");
    tokio::signal::ctrl_c().await?;
    task.abort();
    Ok(())
}
