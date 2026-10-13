//! Bounded, observational telemetry. Never an authorization input or receipt substitute.
use crate::alarm::{Alarm, AlarmRecord, Delivery, ALARM_LOG_CAPACITY};
use crate::{server::GateServerState, GateError};
use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Json,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

pub const CAPACITY: usize = 500;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    pub sequence: u64,
    pub timestamp: i64,
    pub outcome: String,
    pub rule: String,
    /// Gate signing identity, not a caller-supplied agent header.
    pub agent: String,
    /// Caller key verified by proof of possession. Never copied from a claimed header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticated_identity: Option<String>,
    pub scope: Option<String>,
    pub action: String,
    /// The model, tool or repository a denial named. Caller-chosen, so untrusted
    /// text: bounded and sanitized here, and observational only (never an
    /// authorization input). Absent on allows and on older gates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}
#[derive(Debug, Default)]
struct Buffer {
    sequence: u64,
    decisions: VecDeque<Decision>,
    alarm_sequence: u64,
    alarms: VecDeque<AlarmRecord>,
}
#[derive(Debug, Default)]
pub struct AuditLog(Mutex<Buffer>, Arc<crate::liveness::Liveness>);
impl AuditLog {
    /// Gate process liveness (heartbeat stamped by a background task).
    pub fn liveness(&self) -> Arc<crate::liveness::Liveness> {
        self.1.clone()
    }
    pub fn record(
        &self,
        outcome: &str,
        rule: &str,
        agent: String,
        scope: Option<String>,
        action: &str,
    ) {
        self.record_with_subject(outcome, rule, agent, scope, action, None);
    }
    pub fn record_with_subject(
        &self,
        outcome: &str,
        rule: &str,
        agent: String,
        scope: Option<String>,
        action: &str,
        subject: Option<String>,
    ) {
        self.record_authenticated(outcome, rule, agent, scope, action, subject, None);
    }
    // Existing telemetry API preserves all identity and decision fields.
    #[allow(clippy::too_many_arguments)]
    pub fn record_authenticated(
        &self,
        outcome: &str,
        rule: &str,
        agent: String,
        scope: Option<String>,
        action: &str,
        subject: Option<String>,
        authenticated_identity: Option<String>,
    ) {
        // Telemetry failure must neither authorize an action nor panic the gate.
        let Ok(mut buffer) = self.0.lock() else {
            return;
        };
        buffer.sequence = buffer.sequence.saturating_add(1);
        let sequence = buffer.sequence;
        buffer.decisions.push_back(Decision {
            sequence,
            authenticated_identity,
            timestamp: chrono::Utc::now().timestamp(),
            outcome: outcome.into(),
            rule: rule.into(),
            agent,
            scope,
            action: action.into(),
            subject,
        });
        if buffer.decisions.len() > CAPACITY {
            buffer.decisions.pop_front();
        }
    }
    /// Store an alarm raised by the alarm task. Observational only.
    pub fn record_alarm(&self, alarm: Alarm, delivery: Delivery) -> Option<AlarmRecord> {
        let mut buffer = self.0.lock().ok()?;
        buffer.alarm_sequence = buffer.alarm_sequence.saturating_add(1);
        let record = AlarmRecord {
            id: buffer.alarm_sequence,
            alarm,
            delivery,
        };
        buffer.alarms.push_back(record.clone());
        if buffer.alarms.len() > ALARM_LOG_CAPACITY {
            buffer.alarms.pop_front();
        }
        Some(record)
    }
    pub fn set_alarm_delivery(&self, id: u64, delivery: Delivery) {
        if let Ok(mut buffer) = self.0.lock() {
            if let Some(r) = buffer.alarms.iter_mut().find(|r| r.id == id) {
                r.delivery = delivery;
            }
        }
    }
    /// Newest first.
    pub fn alarms(&self) -> Vec<AlarmRecord> {
        self.0
            .lock()
            .map(|b| b.alarms.iter().rev().cloned().collect())
            .unwrap_or_default()
    }
    pub fn snapshot(&self) -> Option<(u64, Vec<Decision>)> {
        self.0
            .lock()
            .ok()
            .map(|b| (b.sequence, b.decisions.iter().rev().cloned().collect()))
    }
}
pub fn rule(err: &GateError) -> &'static str {
    match err {
        GateError::IdentityAuthentication(_) => "identity_authentication",
        GateError::IdentityGrant(_) => "identity_grant",
        GateError::GrantWindow(_) => "grant_window",
        GateError::NoValidIac(_) => "iac_validity",
        GateError::InvalidIacSignature(_) => "iac_signature",
        GateError::ChannelDenied(_) => "channel_allowlist",
        GateError::ModelDenied(_) => "model_allowlist",
        GateError::ToolDenied(_) => "tool_allowlist",
        GateError::RepoDenied(_) => "repository_allowlist",
        GateError::ExportForbidden(_) => "export_restriction",
        GateError::ContextBoundExceeded => "context_bound",
        GateError::SessionDegraded(_, _) => "session_degraded",
        GateError::SessionStale(_, _) => "session_stale",
        GateError::Connector(_) => "connector_unavailable",
        GateError::Spend(_) => "spend_policy",
        GateError::Registry(_) => "request_or_registry_invalid",
        GateError::SiemExport(_) => "audit_export_unavailable",
        GateError::Bus(_) => "receipt_or_upstream_unavailable",
    }
}
/// The caller-named object of a denial, when the rule names one. Control characters
/// are dropped and length is capped; consumers must still validate before use.
pub fn subject(err: &GateError) -> Option<String> {
    let raw = match err {
        GateError::ModelDenied(s) | GateError::ToolDenied(s) | GateError::RepoDenied(s) => s,
        _ => return None,
    };
    Some(raw.chars().filter(|c| !c.is_control()).take(128).collect())
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyView {
    pub permitted_channels: Vec<String>,
    pub forbidden_exports: Vec<String>,
    pub model_allowlist: Vec<String>,
    pub github_repo_allowlist: Vec<String>,
    pub delta_t_secs: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub schema_version: u8,
    pub observed_at: i64,
    pub status: String,
    pub last_cp_age_secs: Option<i64>,
    pub router_stale: bool,
    pub degraded: bool,
    pub policy: PolicyView,
    pub decisions: Vec<Decision>,
    pub total_observed: u64,
    pub retained: usize,
    pub allowed: usize,
    pub denied: usize,
    pub deny_rate: Option<f64>,
    pub audit_available: bool,
    /// Clocked alarms raised by the gate, newest first, with delivery status.
    #[serde(default)]
    pub alarms: Vec<AlarmRecord>,
    /// Summaries computed from the retained decisions.
    #[serde(default)]
    pub readings: Option<crate::readings::Readings>,
    /// Gate process uptime and heartbeat. Separate from the router checkpoint.
    #[serde(default)]
    pub liveness: Option<crate::liveness::LivenessReport>,
}
pub async fn snapshot(state: &GateServerState) -> Snapshot {
    let now = chrono::Utc::now().timestamp();
    let chain = state.session_chain.lock().await;
    let registry = state.gate.registry();
    let stale = chain.is_router_stale(now, registry.delta_t_secs);
    let degraded = chain.degraded_scope_id.is_some();
    let data = state.audit.snapshot();
    let available = data.is_some();
    let (total, decisions) = data.unwrap_or_default();
    let allowed = decisions.iter().filter(|d| d.outcome == "allow").count();
    let denied = decisions.iter().filter(|d| d.outcome == "deny").count();
    let gate_live = state.audit.liveness().report(now);
    let readings = available.then(|| crate::readings::compute(now, total, &decisions));
    Snapshot {
        schema_version: 1,
        observed_at: now,
        status: if !available {
            "unknown"
        } else if stale || degraded || !gate_live.heartbeat_ok {
            "degraded"
        } else if chain.active_scope_id.is_none() {
            "idle"
        } else {
            "live"
        }
        .into(),
        last_cp_age_secs: chain.last_router_cp_age_secs(now),
        router_stale: stale,
        degraded,
        policy: PolicyView {
            permitted_channels: registry.permitted_channels.clone(),
            forbidden_exports: registry.forbidden_exports.clone(),
            model_allowlist: registry.model_allowlist.clone(),
            github_repo_allowlist: registry.github_repo_allowlist.clone(),
            delta_t_secs: registry.delta_t_secs,
        },
        retained: decisions.len(),
        decisions,
        total_observed: total,
        allowed,
        denied,
        deny_rate: (allowed + denied > 0).then(|| denied as f64 / (allowed + denied) as f64),
        audit_available: available,
        alarms: state.audit.alarms(),
        readings,
        liveness: Some(gate_live),
    }
}
pub fn loopback_address(value: &str) -> anyhow::Result<SocketAddr> {
    let address: SocketAddr = value.parse()?;
    anyhow::ensure!(
        address.ip().is_loopback(),
        "audit listeners must bind to a literal loopback address"
    );
    Ok(address)
}
/// Reject cross-origin browser reads and DNS rebinding; no CORS permission is emitted.
pub async fn local_only(req: Request, next: Next) -> Response {
    let valid_host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|h| {
            h.parse::<SocketAddr>().is_ok_and(|a| a.ip().is_loopback())
                || h.strip_prefix("localhost:")
                    .is_some_and(|p| p.parse::<u16>().is_ok())
        });
    let valid_origin = req
        .headers()
        .get(header::ORIGIN)
        .map(|o| {
            o.to_str().ok().is_some_and(|o| {
                req.headers()
                    .get(header::HOST)
                    .and_then(|h| h.to_str().ok())
                    .is_some_and(|h| o == format!("http://{h}"))
            })
        })
        .unwrap_or(true);
    // Browser requests must not cause reconciliation, even same-origin.
    let browser_write = req.method() != axum::http::Method::GET
        && (req.headers().contains_key(header::ORIGIN)
            || req.headers().contains_key("sec-fetch-site"));
    if !valid_host || !valid_origin || browser_write {
        return StatusCode::FORBIDDEN.into_response();
    }
    let mut response = next.run(req).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
        .headers_mut()
        .insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    response.headers_mut().insert(header::CONTENT_SECURITY_POLICY, "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'".parse().unwrap());
    response
}
async fn endpoint(State(state): State<GateServerState>) -> Json<Snapshot> {
    Json(snapshot(&state).await)
}
pub fn router(state: GateServerState) -> axum::Router {
    axum::Router::new()
        .route("/audit", get(endpoint))
        .route("/operations", get(crate::reconciliation::list))
        .route(
            "/operations/reconcile",
            axum::routing::post(crate::reconciliation::run),
        )
        .with_state(state)
        .layer(middleware::from_fn(local_only))
}
pub async fn bind(
    state: GateServerState,
    listen: &str,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let listener = tokio::net::TcpListener::bind(loopback_address(listen)?).await?;
    // Whoever serves the snapshot also stamps the heartbeat it reports.
    crate::liveness::spawn_heartbeat(state.audit.liveness());
    Ok(tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, router(state)).await {
            tracing::error!(%err, "audit listener stopped");
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_newest_first() {
        let log = AuditLog::default();
        for _ in 0..CAPACITY + 2 {
            log.record("deny", "iac_validity", "gate".into(), None, "chat");
        }
        let (total, rows) = log.snapshot().unwrap();
        assert_eq!(total, 502);
        assert_eq!(rows.len(), CAPACITY);
        assert_eq!(rows[0].sequence, 502);
        assert_eq!(rows.last().unwrap().sequence, 3);
    }
    #[test]
    fn denial_subject_is_bounded_and_only_for_named_rules() {
        let long = "x".repeat(500);
        let s = subject(&GateError::RepoDenied(format!("a/b\n{long}"))).unwrap();
        assert!(s.len() <= 128 && !s.contains('\n'));
        assert!(subject(&GateError::NoValidIac("x".into())).is_none());
        assert!(subject(&GateError::ChannelDenied("x".into())).is_none());
        let log = AuditLog::default();
        log.record_with_subject(
            "deny",
            "tool_allowlist",
            "g".into(),
            None,
            "tool",
            Some("t".into()),
        );
        assert_eq!(log.snapshot().unwrap().1[0].subject.as_deref(), Some("t"));
    }
    #[test]
    fn non_loopback_is_rejected() {
        assert!(loopback_address("0.0.0.0:8788").is_err());
        assert!(loopback_address("example.com:8788").is_err());
        assert!(loopback_address("[::1]:8788").is_ok());
    }
}
