use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json,
};
use membrane_core::iac::IntentAuthorizationCredential;
use membrane_core::rollup::cp_hash_hex;
use membrane_core::{SessionChainState, ALERT_REASON_DELTA_T_EXCEEDED};
use serde_json::json;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::github::{is_github_tool, GitHubConnector, ToolInvokeRequest};
use crate::proxy::{ChatRequest, ChatResponse, LlmProxy};
use crate::watchdog::spawn_delta_t_watchdog;
use crate::{Gate, GateError, RouterSessionRequest};

/// Per-turn attestation receipt returned to chat clients.
#[derive(Debug, Clone)]
pub struct SessionReceipt {
    pub scope_id: String,
    pub session_nonce: u64,
    pub cp_hash: String,
    pub context_merkle_root: String,
    pub parent_cp_hash: String,
    pub bus_event_id: Option<String>,
}

#[derive(Clone)]
pub struct GateServerState {
    pub gate: Arc<Gate>,
    pub proxy: Arc<LlmProxy>,
    pub default_iac: Option<IntentAuthorizationCredential>,
    pub session_chain: Arc<Mutex<SessionChainState>>,
    /// GitHub connector (operator installs). Demo dashboard does not use this.
    pub github: Arc<GitHubConnector>,
    pub operations: Arc<crate::operations::OperationJournal>,
    pub audit: Arc<crate::audit::AuditLog>,
    /// Paid Routstr calls. None means the spend route is off and denies everything.
    pub spend: Option<Arc<crate::routstr::SpendService>>,
}

pub async fn run_gate_server(state: GateServerState, listen: &str) -> anyhow::Result<()> {
    // Dedicated loopback-only telemetry listener, never the production write router.
    let audit_listen =
        std::env::var("MEMBRANE_AUDIT_LISTEN").unwrap_or_else(|_| "127.0.0.1:8788".into());
    let listener = tokio::net::TcpListener::bind(listen).await?;
    let audit_task = crate::audit::bind(state.clone(), &audit_listen).await?;
    spawn_delta_t_watchdog(
        state.gate.clone(),
        state.session_chain.clone(),
        state.operations.clone(),
    );
    let report = crate::reconciliation::reconcile(&state).await?;
    warn!(
        unresolved = report["operations"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0),
        legacy = report["legacy_reservations"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0),
        "startup operation reconciliation; inspect loopback /operations (no retries)"
    );
    // Invalid alarm settings stop startup; they never silently disable alarms.
    let alarm_config = crate::alarm::AlarmConfig::from_env().map_err(anyhow::Error::msg)?;
    crate::alarm::spawn_alarm_task(state.audit.clone(), state.gate.clone(), alarm_config);

    let app = axum::Router::new()
        .route("/health", get(health))
        .route("/v1/operator/iac", post(operator_iac))
        .route("/v1/chat/completions", post(chat_completions))
        .route("/v1/tools/invoke", post(tools_invoke))
        .route("/v1/spend/chat", post(spend_chat))
        .with_state(state);

    info!(listen = %listen, "membrane gate listening");
    let result = axum::serve(listener, app).await;
    audit_task.abort();
    result?;
    Ok(())
}

async fn operator_iac(
    State(state): State<GateServerState>,
    headers: HeaderMap,
    Json(request): Json<crate::oidc::OperatorIacRequest>,
) -> Response {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));
    let Some(token) = token else {
        let err = GateError::IdentityAuthentication("operator bearer token required".into());
        record_denied(&state, &err, "operator.iac.issue");
        return gate_error_response(err);
    };
    let parent = state.session_chain.lock().await.last_cp_hash.clone();
    match state
        .gate
        .issue_operator_iac(token, &request, &parent)
        .await
    {
        Ok((operator, iac)) => {
            state.audit.record_authenticated(
                "allow",
                "operator_oidc",
                state.gate.publisher_pubkey_hex(),
                Some(iac.scope_id.clone()),
                "operator.iac.issue",
                None,
                Some(operator),
            );
            Json(iac).into_response()
        }
        Err(err) => {
            record_denied(&state, &err, "operator.iac.issue");
            gate_error_response(err)
        }
    }
}

async fn health(State(state): State<GateServerState>) -> impl IntoResponse {
    let now = now_secs();
    let chain = state.session_chain.lock().await;
    let delta_t_secs = state.gate.registry().delta_t_secs;
    let last_cp_age_secs = chain.last_router_cp_age_secs(now);
    let router_stale = chain.is_router_stale(now, delta_t_secs);
    let active_scope = chain.active_scope_id.clone();
    let degraded_scope = chain.degraded_scope_id.clone();

    let journal = state.operations.unresolved();
    let recovery = state.operations.recover(&state.gate.publisher_pubkey_hex());
    let journal_blocked = recovery
        .as_ref()
        .map(|r| !r.pending.is_empty())
        .unwrap_or(true);
    Json(json!({
        "journal_available": journal.is_ok() && recovery.is_ok(),
        "journal_dispatch_blocked": journal_blocked,
        "unresolved_operations": journal.as_ref().map(|v| v.len()).ok(),
        "status": if router_stale || degraded_scope.is_some() || journal_blocked { "degraded" } else { "ok" },
        "gate": "membrane-phase-0",
        "caller_audience": state.gate.caller_audience(),
        "delta_t_secs": delta_t_secs,
        "last_cp_age_secs": last_cp_age_secs,
        "router_stale": router_stale,
        "active_scope_id": active_scope,
        "degraded_scope_id": degraded_scope,
        "degraded_reason": chain.degraded_reason,
        "siem_export": match state.gate.siem_export() {
            Some(e) => serde_json::to_value(e.status()).unwrap_or(json!({"enabled": true})),
            None => json!({"enabled": false}),
        },
        "github_connector": {
            "repo_allowlist": state.gate.registry().github_repo_allowlist,
            "token_configured": state.github.config().has_token(),
        },
    }))
}

async fn chat_completions(
    State(state): State<GateServerState>,
    headers: HeaderMap,
    request: Result<Json<ChatRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let req = match request {
        Ok(Json(req)) => req,
        Err(rejection) => {
            record_denied(
                &state,
                &GateError::Registry("invalid JSON request".into()),
                "chat",
            );
            return rejection.into_response();
        }
    };
    let mut identity = None;
    let authorization = (|| {
        let iac = load_iac(&headers, state.default_iac.as_ref())?;
        let proof = load_caller_proof(&headers)?;
        identity = Some(state.gate.authenticate_caller(
            &iac,
            &proof,
            "/v1/chat/completions",
            &req,
            now_secs(),
        )?);
        state
            .gate
            .authorize_identity(identity.as_deref().unwrap(), &iac, &req.model, None)
    })();
    if let Err(err) = authorization {
        record_denied_identity(&state, &err, "chat", identity);
        return gate_error_response(err);
    }
    let mut authorized = false;
    match handle_chat(&state, &headers, &req, &mut authorized).await {
        Ok((resp, receipt)) => chat_success_response(resp, &receipt),
        Err(err) => {
            if !authorized {
                record_denied_identity(&state, &err, "chat", identity.clone());
            }
            publish_blocked_receipt(&state, &headers, Some(&req.model), None, &err).await;
            gate_error_response(err)
        }
    }
}

async fn tools_invoke(
    State(state): State<GateServerState>,
    headers: HeaderMap,
    request: Result<Json<ToolInvokeRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let req = match request {
        Ok(Json(req)) => req,
        Err(rejection) => {
            record_denied(
                &state,
                &GateError::Registry("invalid JSON request".into()),
                "tool",
            );
            return rejection.into_response();
        }
    };
    let mut identity = None;
    let authorization = (|| {
        let iac = load_iac(&headers, state.default_iac.as_ref())?;
        let proof = load_caller_proof(&headers)?;
        identity = Some(state.gate.authenticate_caller(
            &iac,
            &proof,
            "/v1/tools/invoke",
            &req,
            now_secs(),
        )?);
        state.gate.authorize_identity(
            identity.as_deref().unwrap(),
            &iac,
            &req.model,
            Some((
                req.tool.as_str(),
                format!("{}/{}", req.owner, req.repo).as_str(),
            )),
        )
    })();
    if let Err(err) = authorization {
        record_denied_identity(&state, &err, "tool", identity);
        return gate_error_response(err);
    }
    let mut authorized = false;
    match handle_tool_invoke(&state, &headers, &req, &mut authorized).await {
        Ok((body, receipt)) => tool_success_response(body, &receipt),
        Err(err) => {
            if !authorized {
                record_denied_identity(&state, &err, "tool", identity.clone());
            }
            if authorized {
                // Dispatch has begun. Do not describe an upstream or journal
                // failure as a blocked action, or invite a blind write retry.
                return (StatusCode::BAD_GATEWAY, Json(json!({
                    "ok": false, "status": "uncertain", "operation_id": req.operation_id,
                    "error": err.to_string(), "message": "Reconcile upstream before retrying this operation."
                }))).into_response();
            }
            publish_blocked_receipt(&state, &headers, Some(&req.model), Some(&req.tool), &err)
                .await;
            gate_error_response(err)
        }
    }
}

/// Body of a paid chat call: the caller's idempotency id plus an ordinary
/// chat-completions body. Budget, limits and rail come from the operator's grant,
/// never from this request.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SpendChatRequest {
    pub operation_id: String,
    #[serde(flatten)]
    pub chat: serde_json::Map<String, serde_json::Value>,
}

fn valid_operation_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

/// Reservation ids are bound to the authenticated caller and scope, so one
/// caller can never collide with or replay another's operation id.
fn spend_reservation_id(identity: &str, scope: &str, operation_id: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(
        format!("membrane-spend-v1\0{identity}\0{scope}\0{operation_id}").as_bytes(),
    ))
}

async fn spend_chat(
    State(state): State<GateServerState>,
    headers: HeaderMap,
    request: Result<Json<SpendChatRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    use crate::routstr::{AdapterError, UNIT};
    use crate::spend::SpendError;
    let req = match request {
        Ok(Json(req)) => req,
        Err(rejection) => {
            record_denied(
                &state,
                &GateError::Registry("invalid JSON request".into()),
                "spend",
            );
            return rejection.into_response();
        }
    };
    let mut identity = None;
    let mut iac_scope = None;
    let authorization = (|| {
        let iac = load_iac(&headers, state.default_iac.as_ref())?;
        let proof = load_caller_proof(&headers)?;
        identity = Some(state.gate.authenticate_caller(
            &iac,
            &proof,
            "/v1/spend/chat",
            &req,
            now_secs(),
        )?);
        let model = req
            .chat
            .get("model")
            .and_then(|m| m.as_str())
            .ok_or_else(|| GateError::Registry("request has no model".into()))?;
        iac_scope = Some(iac.scope_id.clone());
        state
            .gate
            .authorize_spend(identity.as_deref().unwrap(), &iac, model)
    })();
    let grant = match authorization {
        Ok(grant) => grant,
        Err(err) => {
            record_denied_identity(&state, &err, "spend", identity);
            return gate_error_response(err);
        }
    };
    let (identity, scope) = (identity.unwrap_or_default(), iac_scope.unwrap_or_default());
    let deny = |state: &GateServerState, why: String| {
        let err = GateError::Spend(why);
        record_denied_identity(state, &err, "spend", Some(identity.clone()));
        gate_error_response(err)
    };
    let Some(service) = state.spend.clone() else {
        return deny(&state, "spend is not configured on this gate".into());
    };
    if !valid_operation_id(&req.operation_id) {
        return deny(
            &state,
            "operation_id must be 1-128 of [A-Za-z0-9._:-]".into(),
        );
    }
    if let Err(e) = service
        .ledger
        .open_budget(&grant.budget, UNIT, grant.budget_cap_msat)
    {
        return deny(&state, format!("budget unavailable: {e}"));
    }
    let reservation = spend_reservation_id(&identity, &scope, &req.operation_id);
    let result = service
        .adapter
        .dispatch_with_limit(
            &grant.budget,
            &reservation,
            serde_json::Value::Object(req.chat.clone()),
            Some(grant.per_call_ceiling_msat),
        )
        .await;
    let dispatched = |state: &GateServerState| {
        state.audit.record_authenticated(
            "allow",
            "spend_dispatched",
            state.gate.publisher_pubkey_hex(),
            Some(scope.clone()),
            "spend.chat",
            None,
            Some(identity.clone()),
        );
    };
    match result {
        Ok(done) => {
            dispatched(&state);
            Json(json!({
                "ok": true, "status": "settled", "operation_id": req.operation_id,
                "receipt": done.receipt, "response": done.reply,
            }))
            .into_response()
        }
        Err(AdapterError::Rejected(why)) => {
            dispatched(&state);
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({
                    "ok": false, "status": "rejected", "operation_id": req.operation_id,
                    "message": format!("Rail refused the call and charged nothing: {why}"),
                })),
            )
                .into_response()
        }
        Err(AdapterError::Uncertain(why)) => {
            dispatched(&state);
            (StatusCode::BAD_GATEWAY, Json(json!({
                "ok": false, "status": "uncertain", "operation_id": req.operation_id,
                "error": why, "message": "The call may have been charged. Budget stays held; reconcile before retrying.",
            }))).into_response()
        }
        Err(AdapterError::AlreadyDispatched(_)) => {
            let err = GateError::Spend("operation_id already used".into());
            record_denied_identity(&state, &err, "spend", Some(identity.clone()));
            (StatusCode::CONFLICT, Json(json!({
                "ok": false, "status": "duplicate", "operation_id": req.operation_id,
                "message": "This operation_id was already submitted; it will not be dispatched again.",
            }))).into_response()
        }
        Err(AdapterError::Budget(SpendError::Insufficient { .. })) => {
            let err = GateError::Spend("budget exhausted".into());
            record_denied_identity(&state, &err, "spend", Some(identity.clone()));
            (StatusCode::PAYMENT_REQUIRED, Json(json!({
                "ok": false, "status": "blocked", "message": "Budget cannot cover this call's ceiling.",
            }))).into_response()
        }
        Err(e) => deny(&state, e.to_string()),
    }
}

fn record_allowed(state: &GateServerState, iac: &IntentAuthorizationCredential, action: &str) {
    state.audit.record_authenticated(
        "allow",
        "all_authorization_checks_passed",
        state.gate.publisher_pubkey_hex(),
        Some(iac.scope_id.clone()),
        action,
        None,
        iac.caller_pubkey.clone(),
    );
}
fn record_denied(state: &GateServerState, err: &GateError, action: &str) {
    record_denied_identity(state, err, action, None);
}
fn record_denied_identity(
    state: &GateServerState,
    err: &GateError,
    action: &str,
    identity: Option<String>,
) {
    state.audit.record_authenticated(
        "deny",
        crate::audit::rule(err),
        state.gate.publisher_pubkey_hex(),
        None,
        action,
        crate::audit::subject(err),
        identity,
    );
}

async fn publish_blocked_receipt(
    state: &GateServerState,
    headers: &HeaderMap,
    model: Option<&str>,
    tool_id: Option<&str>,
    err: &GateError,
) {
    let iac = load_iac(headers, state.default_iac.as_ref()).ok();
    let scope_id = iac.as_ref().map(|iac| iac.scope_id.as_str());
    let iac_hash = iac.as_ref().and_then(|iac| iac.hash_hex().ok());
    let tools = iac
        .as_ref()
        .map(|iac| iac.tool_allowlist.clone())
        .unwrap_or_default();
    let model_id = model.and_then(|m| {
        state
            .gate
            .registry()
            .model_allowlist
            .contains(&m.to_string())
            .then_some(m)
    });
    let (last_cp_hash, prev_event_id) = {
        let chain = state.session_chain.lock().await;
        (chain.last_cp_hash.clone(), chain.last_event_id.clone())
    };

    if let Err(publish_err) = state
        .gate
        .publish_action_blocked(&crate::BlockedAction {
            scope_id,
            model_id,
            tool_id,
            tool_allowlist: &tools,
            iac_hash: iac_hash.as_deref(),
            reason: &err.to_string(),
            now: now_secs(),
            last_cp_hash: &last_cp_hash,
            prev_event_id: prev_event_id.as_deref(),
        })
        .await
    {
        warn!(error = %publish_err, "failed to publish blocked-action receipt");
    }
}

async fn handle_chat(
    state: &GateServerState,
    headers: &HeaderMap,
    req: &ChatRequest,
    authorized: &mut bool,
) -> Result<(ChatResponse, SessionReceipt), GateError> {
    let iac = load_iac(headers, state.default_iac.as_ref())?;
    let now = now_secs();

    state.gate.validate_iac(Some(&iac), now)?;
    state.gate.siem_admission()?;

    let mut chain = state.session_chain.lock().await;
    ensure_live_session(state, &iac, &mut chain, now).await?;

    let parent_cp_hash = chain.next_parent_cp_hash(&iac.parent_cp_hash);
    let session_nonce = chain
        .session_nonce
        .checked_add(1)
        .ok_or_else(|| GateError::Connector("scope nonce exhausted".into()))?;
    let prev_event_id = chain.last_event_id.clone();

    let session_req = RouterSessionRequest {
        model_id: req.model.clone(),
        context_chunks: req
            .messages
            .iter()
            .map(|m| serde_json::to_vec(m).map_err(|e| GateError::Registry(e.to_string())))
            .collect::<Result<_, _>>()?,
        session_nonce,
        parent_cp_hash: parent_cp_hash.clone(),
        scope_id: Some(iac.scope_id.clone()),
        tool_id: None,
    };

    let publication = state.operations.begin_publication()?;
    let outcome = state
        .gate
        .open_router_session(Some(&iac), session_req, now, prev_event_id.as_deref())
        .await;
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(err) => {
            if !matches!(err, GateError::Bus(_)) {
                state
                    .operations
                    .append(crate::operations::Record::PublicationAborted { token: publication })?;
                *chain = state
                    .operations
                    .recover(&state.gate.publisher_pubkey_hex())?
                    .chain;
            }
            return Err(err);
        }
    };

    let cp_hash = cp_hash_hex(&outcome.event).map_err(GateError::Bus)?;
    state
        .operations
        .append(crate::operations::Record::Checkpoint {
            token: publication,
            caller: iac.caller_pubkey.clone().unwrap_or_default(),
            event: outcome.event.clone(),
            bus_event_id: outcome.bus_event_id.clone(),
        })?;
    chain.session_nonce = session_nonce;
    chain.record_cp(cp_hash.clone(), outcome.bus_event_id.clone(), now);

    let receipt = SessionReceipt {
        scope_id: iac.scope_id.clone(),
        session_nonce,
        cp_hash: cp_hash.clone(),
        context_merkle_root: outcome.context_merkle_root.clone(),
        parent_cp_hash,
        bus_event_id: outcome.bus_event_id.clone(),
    };

    info!(
        scope_id = %iac.scope_id,
        session_nonce,
        cp_hash = %cp_hash,
        "membrane.cp.router published"
    );

    drop(chain);

    state.gate.authorize_identity(
        iac.caller_pubkey
            .as_deref()
            .ok_or_else(|| GateError::IdentityAuthentication("missing caller binding".into()))?,
        &iac,
        &req.model,
        None,
    )?;
    *authorized = true;
    record_allowed(state, &iac, "chat");
    let response = state.proxy.chat(req).await.map_err(GateError::Bus)?;
    Ok((response, receipt))
}

/// Production tool path: IAC + allowlist + liveness first; GitHub only after allow.
async fn handle_tool_invoke(
    state: &GateServerState,
    headers: &HeaderMap,
    req: &ToolInvokeRequest,
    authorized: &mut bool,
) -> Result<(serde_json::Value, SessionReceipt), GateError> {
    let iac = load_iac(headers, state.default_iac.as_ref())?;
    let now = now_secs();

    state.gate.validate_iac(Some(&iac), now)?;
    state.gate.siem_admission()?;

    if !iac.model_allowed(&req.model) || !state.gate.registry().model_allowlist.contains(&req.model)
    {
        return Err(GateError::ModelDenied(req.model.clone()));
    }

    // Hard block out-of-scope tools before any upstream connector call.
    state.gate.authorize_tool(&iac, &req.tool, now)?;

    if !is_github_tool(&req.tool) {
        return Err(GateError::Connector(format!(
            "no connector configured for tool '{}'; supported: github.comment, github.merge, github.issue.read",
            req.tool
        )));
    }

    // Repo allowlist + token presence — still before GitHub HTTP.
    state.github.preflight(req).map_err(map_github_err)?;

    // Serialize validation, intent publication and dispatch with sever/staleness changes.
    // The receipt attests the request intent, not a completed upstream effect.
    let mut chain = state.session_chain.lock().await;
    ensure_live_session(state, &iac, &mut chain, now).await?;
    let parent_cp_hash = chain.next_parent_cp_hash(&iac.parent_cp_hash);
    let session_nonce = chain
        .session_nonce
        .checked_add(1)
        .ok_or_else(|| GateError::Connector("scope nonce exhausted".into()))?;
    let prev_event_id = chain.last_event_id.clone();
    let context_chunks =
        vec![serde_json::to_vec(req).map_err(|e| GateError::Registry(e.to_string()))?];

    let reservation = if req.tool == crate::github::TOOL_GITHUB_ISSUE_READ {
        None
    } else {
        Some(state.operations.reserve_in_scope(
            iac.caller_pubkey.as_deref().unwrap_or(""),
            &iac.scope_id,
            req,
        )?)
    };
    let publication = state.operations.begin_publication()?;
    let outcome = state
        .gate
        .open_router_session(
            Some(&iac),
            RouterSessionRequest {
                model_id: req.model.clone(),
                context_chunks,
                session_nonce,
                parent_cp_hash: parent_cp_hash.clone(),
                scope_id: Some(iac.scope_id.clone()),
                tool_id: Some(req.tool.clone()),
            },
            now,
            prev_event_id.as_deref(),
        )
        .await;
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(err) => {
            if !matches!(err, GateError::Bus(_)) {
                state
                    .operations
                    .append(crate::operations::Record::PublicationAborted { token: publication })?;
                *chain = state
                    .operations
                    .recover(&state.gate.publisher_pubkey_hex())?
                    .chain;
            }
            return Err(err);
        }
    };

    let cp_hash = cp_hash_hex(&outcome.event).map_err(GateError::Bus)?;
    state
        .operations
        .append(crate::operations::Record::Checkpoint {
            token: publication,
            caller: iac.caller_pubkey.clone().unwrap_or_default(),
            event: outcome.event.clone(),
            bus_event_id: outcome.bus_event_id.clone(),
        })?;
    chain.session_nonce = session_nonce;
    chain.record_cp(cp_hash.clone(), outcome.bus_event_id.clone(), now);

    let receipt = SessionReceipt {
        scope_id: iac.scope_id.clone(),
        session_nonce,
        cp_hash: cp_hash.clone(),
        context_merkle_root: outcome.context_merkle_root.clone(),
        parent_cp_hash,
        bus_event_id: outcome.bus_event_id.clone(),
    };

    // Publication may have taken time; recheck expiry and scope liveness as well
    // as identity immediately before dispatch, still under the session lock.
    state.gate.validate_iac(Some(&iac), now_secs())?;
    state
        .gate
        .check_session_liveness(&chain, &iac.scope_id, now_secs())?;
    state.gate.authorize_identity(
        iac.caller_pubkey
            .as_deref()
            .ok_or_else(|| GateError::IdentityAuthentication("missing caller binding".into()))?,
        &iac,
        &req.model,
        Some((&req.tool, &format!("{}/{}", req.owner, req.repo))),
    )?;
    *authorized = true;
    record_allowed(state, &iac, "tool");
    let execution = state.github.execute(req).await;
    if let Some(path) = reservation {
        state.operations.finish(&path, execution.is_ok())?;
    }
    let tool_ctx = execution.map_err(map_github_err)?;

    info!(
        scope_id = %iac.scope_id,
        tool = %req.tool,
        cp_hash = %cp_hash,
        "membrane tool invoke allowed"
    );

    let body = json!({
        "ok": true,
        "status": "allowed",
        "simulation": false,
        "tool": req.tool,
        "model": req.model,
        "owner": req.owner,
        "repo": req.repo,
        "body_sha256": tool_ctx.body_sha256,
        "result": tool_ctx.result,
        "receipt": {
            "scope_id": receipt.scope_id,
            "session_nonce": receipt.session_nonce,
            "cp_hash": receipt.cp_hash,
            "context_merkle_root": receipt.context_merkle_root,
            "parent_cp_hash": receipt.parent_cp_hash,
            "bus_event_id": receipt.bus_event_id,
        }
    });

    Ok((body, receipt))
}

async fn ensure_live_session(
    state: &GateServerState,
    iac: &IntentAuthorizationCredential,
    chain: &mut SessionChainState,
    now: i64,
) -> Result<(), GateError> {
    state.operations.assert_ready(
        &state.gate.publisher_pubkey_hex(),
        iac.caller_pubkey.as_deref().unwrap_or(""),
        &iac.scope_id,
    )?;
    // Authenticate severance from the operator bus on every dispatch, not just
    // startup. Relay failure fails closed; local test/demo buses have no relay.
    let relay = state.gate.publisher().relay_url();
    if !relay.starts_with("memory://") && !relay.starts_with("local://") {
        let events = membrane_core::nostr_bus::fetch_membrane_events(relay, None, 5_000)
            .await
            .map_err(GateError::Bus)?;
        apply_operator_severs(chain, &events, &state.gate.publisher_pubkey_hex());
        for (scope, (reason, at)) in &chain.degraded_scopes {
            state.operations.append(crate::operations::Record::Sever {
                scope: scope.clone(),
                reason: reason.clone(),
                at: *at,
            })?;
        }
    }
    // Check degraded before begin_scope — switching onto a severed scope must not clear it.
    if let Err(err) = state.gate.check_session_liveness(chain, &iac.scope_id, now) {
        if matches!(err, GateError::SessionDegraded(_, _)) {
            return Err(err);
        }
        if matches!(err, GateError::SessionStale(_, _)) {
            let age = chain.scope_router_cp_age_secs(&iac.scope_id, now);
            let prev = chain.last_event_id.clone();
            let cp_hash = chain.last_cp_hash.clone();
            let scope_id = iac.scope_id.clone();
            state
                .gate
                .publish_alert_degraded(
                    &scope_id,
                    ALERT_REASON_DELTA_T_EXCEEDED,
                    now,
                    &cp_hash,
                    age,
                    prev.as_deref(),
                )
                .await?;
            state.operations.append(crate::operations::Record::Sever {
                scope: iac.scope_id.clone(),
                reason: ALERT_REASON_DELTA_T_EXCEEDED.into(),
                at: now,
            })?;
            chain.mark_degraded(&iac.scope_id, ALERT_REASON_DELTA_T_EXCEEDED, now);
            return Err(err);
        }
        return Err(err);
    }

    let new_scope = chain.active_scope_id.as_deref() != Some(&iac.scope_id)
        && !chain.scopes.contains_key(&iac.scope_id);
    chain
        .validate_iac_anchor(&iac.parent_cp_hash, new_scope)
        .map_err(GateError::NoValidIac)?;
    // A rejected anchor must not make the next identical retry look established.
    chain.begin_scope(&iac.scope_id);
    Ok(())
}

fn apply_operator_severs(
    chain: &mut SessionChainState,
    events: &[membrane_core::event::MembraneEvent],
    operator: &str,
) {
    use membrane_core::event::EventType;
    for event in events {
        if event.event_type != EventType::AlertDegraded
            || membrane_core::nostr_bus::verify_membrane_event_signature(event, operator).is_err()
        {
            continue;
        }
        let (reason, scope) = membrane_core::session::alert_degraded_fields(&event.payload);
        if let (Some(reason), Some(scope)) = (reason, scope) {
            chain.mark_degraded(&scope, &reason, event.timestamp);
        }
    }
}

fn map_github_err(err: crate::github::GitHubConnectorError) -> GateError {
    use crate::github::GitHubConnectorError;
    match err {
        GitHubConnectorError::TokenMissing => GateError::Connector(err.to_string()),
        GitHubConnectorError::RepoDenied(r) => GateError::RepoDenied(r),
        GitHubConnectorError::UnsupportedTool(t) => {
            GateError::Connector(format!("unsupported tool: {t}"))
        }
        GitHubConnectorError::InvalidArgs(m) => GateError::Registry(m),
        GitHubConnectorError::Api { status, message } => {
            GateError::Connector(format!("GitHub API {status}: {message}"))
        }
        GitHubConnectorError::Http(m) => GateError::Connector(m),
    }
}

fn chat_success_response(resp: ChatResponse, receipt: &SessionReceipt) -> Response {
    let mut headers = HeaderMap::new();
    attach_receipt_headers(&mut headers, receipt);
    (StatusCode::OK, headers, Json(resp)).into_response()
}

fn tool_success_response(body: serde_json::Value, receipt: &SessionReceipt) -> Response {
    let mut headers = HeaderMap::new();
    attach_receipt_headers(&mut headers, receipt);
    (StatusCode::OK, headers, Json(body)).into_response()
}

fn attach_receipt_headers(headers: &mut HeaderMap, receipt: &SessionReceipt) {
    set_header(headers, "x-membrane-scope-id", &receipt.scope_id);
    set_header(
        headers,
        "x-membrane-session-nonce",
        &receipt.session_nonce.to_string(),
    );
    set_header(headers, "x-membrane-cp-hash", &receipt.cp_hash);
    set_header(
        headers,
        "x-membrane-context-root",
        &receipt.context_merkle_root,
    );
    set_header(
        headers,
        "x-membrane-parent-cp-hash",
        &receipt.parent_cp_hash,
    );
    if let Some(id) = &receipt.bus_event_id {
        set_header(headers, "x-membrane-bus-event-id", id);
    }
}

fn set_header(headers: &mut HeaderMap, name: &'static str, value: &str) {
    if let Ok(v) = HeaderValue::from_str(value) {
        headers.insert(name, v);
    }
}

fn load_caller_proof(headers: &HeaderMap) -> Result<membrane_core::caller::CallerProof, GateError> {
    let raw = headers
        .get("x-membrane-caller-proof")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| GateError::IdentityAuthentication("missing caller proof".into()))?;
    serde_json::from_str(raw)
        .map_err(|_| GateError::IdentityAuthentication("invalid caller proof".into()))
}

fn load_iac(
    headers: &HeaderMap,
    default: Option<&IntentAuthorizationCredential>,
) -> Result<IntentAuthorizationCredential, GateError> {
    if let Some(raw) = headers.get("x-membrane-iac").and_then(|v| v.to_str().ok()) {
        return parse_iac_header(raw);
    }
    if let Some(iac) = default {
        return Ok(iac.clone());
    }
    Err(GateError::NoValidIac(
        "missing X-Membrane-IAC header and no default IAC configured".into(),
    ))
}

fn parse_iac_header(raw: &str) -> Result<IntentAuthorizationCredential, GateError> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let trimmed = raw.trim();
    let json = if trimmed.starts_with('{') {
        trimmed.to_string()
    } else {
        let bytes = STANDARD
            .decode(trimmed)
            .map_err(|e| GateError::NoValidIac(format!("invalid base64 IAC: {e}")))?;
        String::from_utf8(bytes)
            .map_err(|e| GateError::NoValidIac(format!("invalid utf8 IAC: {e}")))?
    };
    serde_json::from_str(&json).map_err(|e| GateError::NoValidIac(format!("invalid IAC JSON: {e}")))
}

fn gate_error_response(err: GateError) -> Response {
    warn!(error = %err, "gate fail-closed");
    let status = match &err {
        GateError::IdentityAuthentication(_)
        | GateError::IdentityGrant(_)
        | GateError::GrantWindow(_)
        | GateError::NoValidIac(_)
        | GateError::InvalidIacSignature(_)
        | GateError::ChannelDenied(_)
        | GateError::ModelDenied(_)
        | GateError::ToolDenied(_)
        | GateError::RepoDenied(_)
        | GateError::ExportForbidden(_)
        | GateError::ContextBoundExceeded
        | GateError::SessionDegraded(_, _)
        | GateError::SessionStale(_, _)
        | GateError::Spend(_)
        | GateError::Connector(_) => StatusCode::FORBIDDEN,
        GateError::SiemExport(_) => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::BAD_REQUEST,
    };
    (
        status,
        Json(json!({
            "error": {
                "message": err.to_string(),
                "type": "membrane_gate_error"
            },
            "ok": false,
            "status": "blocked",
            "simulation": false,
        })),
    )
        .into_response()
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
}

#[cfg(test)]
mod tool_invoke_policy_tests {
    use super::*;
    use crate::github::{GitHubConnectorConfig, TOOL_GITHUB_COMMENT, TOOL_GITHUB_MERGE};
    use crate::ChannelRegistry;
    use membrane_core::{BusPublisher, BusPublisherConfig};
    use nostr::Keys;

    #[tokio::test]
    async fn operator_exchange_http_missing_invalid_and_unconfigured_denied() {
        let (state, _) = test_state(vec![], vec![]);
        let request = || crate::oidc::OperatorIacRequest {
            caller_pubkey: "a".repeat(64),
            scope_id: "s".into(),
            model: "m".into(),
            tools: vec![],
            ttl_secs: 60,
        };
        let response = operator_iac(State(state.clone()), HeaderMap::new(), Json(request())).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Basic invalid"),
        );
        let response = operator_iac(State(state.clone()), headers.clone(), Json(request())).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer invalid"),
        );
        let response = operator_iac(State(state.clone()), headers, Json(request())).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let (_, decisions) = state.audit.snapshot().unwrap();
        assert_eq!(decisions.len(), 3);
        assert!(decisions.iter().all(|d| d.outcome == "deny"));
        assert!(state.operations.unresolved().unwrap().is_empty());
    }

    fn test_state(
        tools: Vec<String>,
        repos: Vec<String>,
    ) -> (GateServerState, IntentAuthorizationCredential) {
        let keys = Keys::generate();
        let registry = ChannelRegistry {
            identities: [(
                keys.public_key().to_hex(),
                crate::identity::IdentityGrant {
                    revoked: false,
                    scopes: vec!["pilot-scope".into()],
                    permitted_channels: vec!["local-llm".into()],
                    model_allowlist: vec!["demo".into()],
                    tool_allowlist: tools.clone(),
                    github_repo_allowlist: repos.clone(),
                    not_before: None,
                    expires_at: None,
                    valid_for: None,
                    spend: Some(crate::identity::SpendGrant {
                        budget: "pilot".into(),
                        budget_cap_msat: 1_000_000,
                        per_call_ceiling_msat: 50_000,
                    }),
                },
            )]
            .into(),
            permitted_channels: vec!["local-llm".into()],
            forbidden_exports: vec!["cloud-telemetry".into(), "training-retention".into()],
            model_allowlist: vec!["demo".into()],
            delta_t_secs: 300,
            model_api_url: None,
            github_repo_allowlist: repos.clone(),
        };
        let publisher = BusPublisher::new(BusPublisherConfig {
            relay_url: "memory://tool-policy".into(),
            keys: keys.clone(),
        });
        let gate = Gate::new(registry, publisher);
        let mut iac = IntentAuthorizationCredential::new_session_with_tools(
            "pilot-scope",
            "demo",
            "0".repeat(64),
            4_102_444_800,
            vec!["local-llm".into()],
            vec!["cloud-telemetry".into(), "training-retention".into()],
            tools,
        );
        iac.caller_pubkey = Some(keys.public_key().to_hex());
        iac.sign(&keys).unwrap();
        let github = GitHubConnector::new(GitHubConnectorConfig {
            repo_allowlist: repos,
            api_base: "http://127.0.0.1:9".into(),
            token: Some("test-token".into()),
        });
        let state = GateServerState {
            gate: Arc::new(gate),
            proxy: Arc::new(LlmProxy::new(None).with_dev_mock(true)),
            default_iac: Some(iac.clone()),
            session_chain: Arc::new(Mutex::new(SessionChainState::genesis())),
            github: Arc::new(github),
            operations: Arc::new(crate::operations::OperationJournal::new(
                std::env::temp_dir().join(Keys::generate().public_key().to_hex()),
            )),
            audit: Arc::new(crate::audit::AuditLog::default()),
            spend: None,
        };
        (state, iac)
    }

    fn comment_request() -> ToolInvokeRequest {
        ToolInvokeRequest {
            operation_id: Some("test-operation".into()),
            tool: TOOL_GITHUB_COMMENT.into(),
            model: "demo".into(),
            owner: "acme".into(),
            repo: "pilot".into(),
            issue_number: Some(1),
            pull_number: None,
            body: Some("local test".into()),
            commit_title: None,
        }
    }

    mod spend_route {
        use super::*;
        use crate::routstr::{
            ChatCall, ChatReply, Pricing, RailError, RoutstrAdapter, RoutstrPolicy, RoutstrRail,
            SpendService,
        };
        use crate::spend::BudgetLedger;
        use std::sync::atomic::{AtomicUsize, Ordering};

        #[derive(Clone)]
        struct Rail {
            calls: Arc<AtomicUsize>,
            fail_unknown: bool,
        }
        #[async_trait::async_trait]
        impl RoutstrRail for Rail {
            async fn chat(&self, _: &ChatCall) -> Result<ChatReply, RailError> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                if self.fail_unknown {
                    return Err(RailError::Unknown("timeout".into()));
                }
                Ok(ChatReply {
                    body: json!({"choices":[],"usage":{"prompt_tokens":10,"completion_tokens":20}}),
                })
            }
            async fn balance_msat(&self) -> Result<u64, RailError> {
                Ok(0)
            }
        }

        fn with_spend(fail_unknown: bool) -> (GateServerState, Arc<AtomicUsize>) {
            let (mut state, _) = test_state(vec![], vec![]);
            let calls = Arc::new(AtomicUsize::new(0));
            let dir = std::env::temp_dir().join(format!(
                "spend-route-{}",
                Keys::generate().public_key().to_hex()
            ));
            let ledger = Arc::new(BudgetLedger::open(dir).unwrap());
            let policy = RoutstrPolicy {
                node: "https://node.test/v1".into(),
                models: [(
                    "demo".to_string(),
                    Pricing {
                        input_msat_per_mtok: 1_000_000,
                        output_msat_per_mtok: 2_000_000,
                        request_fee_msat: 10,
                    },
                )]
                .into(),
                per_call_ceiling_msat: 100_000,
            };
            let rail: Box<dyn RoutstrRail> = Box::new(Rail {
                calls: calls.clone(),
                fail_unknown,
            });
            state.spend = Some(Arc::new(SpendService {
                ledger: ledger.clone(),
                adapter: RoutstrAdapter::new(ledger, rail, policy),
            }));
            (state, calls)
        }

        fn request(op: &str, max_tokens: u64) -> SpendChatRequest {
            let chat = json!({"model":"demo","max_tokens":max_tokens,"messages":[{"role":"user","content":"hi"}]});
            SpendChatRequest {
                operation_id: op.into(),
                chat: chat.as_object().unwrap().clone(),
            }
        }

        async fn call(
            state: &GateServerState,
            req: &SpendChatRequest,
        ) -> (StatusCode, serde_json::Value) {
            let proof = membrane_core::caller::CallerProof::sign(
                state.gate.publisher().keys(),
                &state.gate.caller_audience(),
                "/v1/spend/chat",
                req,
                state.default_iac.as_ref().unwrap(),
                now_secs(),
                Keys::generate().public_key().to_hex(),
            )
            .unwrap();
            let mut headers = HeaderMap::new();
            headers.insert(
                "x-membrane-caller-proof",
                serde_json::to_string(&proof).unwrap().parse().unwrap(),
            );
            let response = spend_chat(State(state.clone()), headers, Ok(Json(req.clone()))).await;
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .unwrap();
            (
                status,
                serde_json::from_slice(&bytes).unwrap_or(json!(null)),
            )
        }

        #[tokio::test]
        async fn settles_and_replays_once() {
            let (state, calls) = with_spend(false);
            let (status, body) = call(&state, &request("op-1", 100)).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(body["status"], "settled");
            assert_eq!(body["receipt"]["final_cost"], 60);
            let ledger = &state.spend.as_ref().unwrap().ledger;
            let v = ledger.budget("pilot").unwrap();
            assert_eq!((v.spent, v.held, v.cap), (60, 0, 1_000_000));
            // same operation id again, fresh proof nonce: never dispatched twice
            let (status, body) = call(&state, &request("op-1", 100)).await;
            assert_eq!(status, StatusCode::CONFLICT, "{body}");
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(ledger.budget("pilot").unwrap().spent, 60);
        }

        #[tokio::test]
        async fn denies_without_spend_config_or_over_the_grant_limit() {
            let (mut state, calls) = with_spend(false);
            // grant limit is 50_000 msat; max_tokens 30_000 at 2 msat/token = 60_000
            let (status, _) = call(&state, &request("op-big", 30_000)).await;
            assert_eq!(status, StatusCode::FORBIDDEN);
            let (status, _) = call(&state, &request("bad id!", 10)).await;
            assert_eq!(status, StatusCode::FORBIDDEN);
            state.spend = None;
            let (status, _) = call(&state, &request("op-2", 10)).await;
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            let (_, decisions) = state.audit.snapshot().unwrap();
            assert!(decisions.iter().all(|d| d.outcome == "deny"));
        }

        #[tokio::test]
        async fn identity_without_a_spend_grant_is_denied() {
            let (mut state, calls) = with_spend(false);
            let gate = Arc::get_mut(&mut state.gate).unwrap();
            for grant in gate.registry.identities.values_mut() {
                grant.spend = None;
            }
            let (status, _) = call(&state, &request("op-3", 10)).await;
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }

        #[tokio::test]
        async fn exhausted_budget_is_payment_required() {
            let (state, calls) = with_spend(false);
            let ledger = state.spend.as_ref().unwrap().ledger.clone();
            ledger.open_budget("pilot", "msat", 1_000_000).unwrap();
            ledger.reserve("pilot", "someone-else", 999_990).unwrap();
            let (status, _) = call(&state, &request("op-4", 100)).await;
            assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }

        #[tokio::test]
        async fn timeout_holds_budget_and_is_listed_for_reconciliation() {
            let (state, calls) = with_spend(true);
            let (status, body) = call(&state, &request("op-5", 100)).await;
            assert_eq!(status, StatusCode::BAD_GATEWAY);
            assert_eq!(body["status"], "uncertain");
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            let report = crate::reconciliation::reconcile(&state).await.unwrap();
            assert_eq!(report["spend_open"].as_array().unwrap().len(), 1);
            assert_eq!(report["spend_open"][0]["state"], "uncertain");
            assert_eq!(report["automatic_retry"], false);
            // retry of the same operation never re-sends
            let (status, _) = call(&state, &request("op-5", 100)).await;
            assert_eq!(status, StatusCode::CONFLICT);
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
    }

    #[tokio::test]
    async fn repeated_write_id_executes_once_with_new_proof_nonce() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let (mut state, _) =
            test_state(vec![TOOL_GITHUB_COMMENT.into()], vec!["acme/pilot".into()]);
        let hits = Arc::new(AtomicUsize::new(0));
        let count = hits.clone();
        let app = axum::Router::new().route(
            "/repos/acme/pilot/issues/1/comments",
            post(move || {
                let count = count.clone();
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    Json(json!({"id":42,"html_url":"http://localhost/comment/42"}))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        state.github = Arc::new(GitHubConnector::new(GitHubConnectorConfig {
            api_base: format!("http://{address}"),
            repo_allowlist: vec!["acme/pilot".into()],
            token: Some("fake".into()),
        }));
        let req = comment_request();
        for attempt in 0..2 {
            let mut headers = HeaderMap::new();
            let proof = membrane_core::caller::CallerProof::sign(
                state.gate.publisher().keys(),
                &state.gate.caller_audience(),
                "/v1/tools/invoke",
                &req,
                state.default_iac.as_ref().unwrap(),
                now_secs(),
                Keys::generate().public_key().to_hex(),
            )
            .unwrap();
            headers.insert(
                "x-membrane-caller-proof",
                serde_json::to_string(&proof).unwrap().parse().unwrap(),
            );
            let response = tools_invoke(State(state.clone()), headers, Ok(Json(req.clone()))).await;
            if attempt == 0 {
                assert_eq!(response.status(), StatusCode::OK);
            } else {
                assert_ne!(response.status(), StatusCode::OK);
            }
        }
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        server.abort();
    }

    #[tokio::test]
    async fn relay_failure_does_not_dispatch() {
        let (mut state, _) =
            test_state(vec![TOOL_GITHUB_COMMENT.into()], vec!["acme/pilot".into()]);
        let gate = Gate::new(
            state.gate.registry().clone(),
            BusPublisher::new(BusPublisherConfig {
                relay_url: "invalid-relay-url".into(),
                keys: state.gate.publisher().keys().clone(),
            }),
        );
        state.gate = Arc::new(gate);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        state.github = Arc::new(GitHubConnector::new(GitHubConnectorConfig {
            api_base: format!("http://{}", listener.local_addr().unwrap()),
            repo_allowlist: vec!["acme/pilot".into()],
            token: Some("fake".into()),
        }));
        let result =
            handle_tool_invoke(&state, &HeaderMap::new(), &comment_request(), &mut false).await;
        assert!(matches!(result, Err(GateError::Bus(_))));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn fresh_scope_recovers_without_reviving_stale_scope() {
        let (state, mut iac) = test_state(vec![], vec![]);
        let mut chain = state.session_chain.lock().await;
        chain.begin_scope("old");
        chain.next_session_nonce();
        chain.record_cp("aa".repeat(32), None, 1);
        iac.parent_cp_hash = chain.last_cp_hash.clone();
        ensure_live_session(&state, &iac, &mut chain, now_secs())
            .await
            .unwrap();
        assert_eq!(chain.last_router_cp_at, None);
        assert!(state
            .gate
            .check_session_liveness(&chain, "old", now_secs())
            .is_err());
    }

    #[tokio::test]
    async fn signed_cli_sever_blocks_running_dispatch() {
        let (state, iac) = test_state(vec![TOOL_GITHUB_COMMENT.into()], vec!["acme/pilot".into()]);
        let mut event = membrane_core::event::MembraneEvent::new(
            membrane_core::event::EventType::AlertDegraded,
            "",
            "0".repeat(64),
            now_secs(),
            membrane_core::session::alert_degraded_payload(
                "subject_sever",
                &iac.scope_id,
                None,
                300,
            ),
        );
        state
            .gate
            .publisher()
            .sign_membrane_event(&mut event)
            .unwrap();
        let envelope = state.gate.publisher().to_nostr_event(&event, None).unwrap();
        let parsed = membrane_core::nostr_bus::parse_membrane_event(&envelope).unwrap();
        {
            let mut chain = state.session_chain.lock().await;
            apply_operator_severs(&mut chain, &[parsed], &state.gate.publisher_pubkey_hex());
        }
        let result =
            handle_tool_invoke(&state, &HeaderMap::new(), &comment_request(), &mut false).await;
        assert!(matches!(result, Err(GateError::SessionDegraded(_, _))));
        assert_eq!(
            state.session_chain.lock().await.last_cp_hash,
            "0".repeat(64)
        );
    }
    #[tokio::test]
    async fn rejected_anchor_retry_never_changes_chain() {
        let (state, iac) = test_state(vec![TOOL_GITHUB_COMMENT.into()], vec!["acme/pilot".into()]);
        let mut chain = state.session_chain.lock().await;
        chain.last_cp_hash = "aa".repeat(32);
        let before = chain.clone();
        for _ in 0..2 {
            assert!(matches!(
                ensure_live_session(&state, &iac, &mut chain, now_secs()).await,
                Err(GateError::NoValidIac(_))
            ));
            assert_eq!(*chain, before);
        }
    }

    #[tokio::test]
    async fn context_denial_never_reaches_upstream() {
        let (mut state, mut iac) =
            test_state(vec![TOOL_GITHUB_COMMENT.into()], vec!["acme/pilot".into()]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        state.github = Arc::new(GitHubConnector::new(GitHubConnectorConfig {
            api_base: format!("http://{}", listener.local_addr().unwrap()),
            repo_allowlist: vec!["acme/pilot".into()],
            token: Some("fake".into()),
        }));
        iac.context_merkle_bound = "0".repeat(64);
        iac.sign(state.gate.publisher().keys()).unwrap();
        state.default_iac = Some(iac);
        let result =
            handle_tool_invoke(&state, &HeaderMap::new(), &comment_request(), &mut false).await;
        assert!(matches!(result, Err(GateError::ContextBoundExceeded)));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
        assert_eq!(
            state.session_chain.lock().await.last_cp_hash,
            "0".repeat(64)
        );
    }

    #[tokio::test]
    async fn authorization_receipt_precedes_upstream_failure() {
        let (state, _) = test_state(vec![TOOL_GITHUB_COMMENT.into()], vec!["acme/pilot".into()]);
        let mut authorized = false;
        assert!(matches!(
            handle_tool_invoke(
                &state,
                &HeaderMap::new(),
                &comment_request(),
                &mut authorized
            )
            .await,
            Err(GateError::Connector(_))
        ));
        assert!(authorized);
        assert_ne!(
            state.session_chain.lock().await.last_cp_hash,
            "0".repeat(64)
        );
    }

    #[tokio::test]
    async fn handler_records_denial_without_trusting_agent_headers() {
        let (state, _) = test_state(vec![], vec!["acme/pilot".into()]);
        let req = ToolInvokeRequest {
            operation_id: Some("test-operation".into()),
            tool: TOOL_GITHUB_MERGE.into(),
            model: "demo".into(),
            owner: "acme".into(),
            repo: "pilot".into(),
            issue_number: None,
            pull_number: None,
            body: None,
            commit_title: None,
        };
        let mut headers = HeaderMap::new();
        headers.insert("x-agent-id", "spoofed-agent".parse().unwrap());
        let proof = membrane_core::caller::CallerProof::sign(
            state.gate.publisher().keys(),
            &state.gate.caller_audience(),
            "/v1/tools/invoke",
            &req,
            state.default_iac.as_ref().unwrap(),
            now_secs(),
            nostr::Keys::generate().public_key().to_hex(),
        )
        .unwrap();
        headers.insert(
            "x-membrane-caller-proof",
            serde_json::to_string(&proof).unwrap().parse().unwrap(),
        );
        let response = tools_invoke(State(state.clone()), headers, Ok(Json(req))).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let view = crate::audit::snapshot(&state).await;
        assert_eq!(view.denied, 1);
        assert_eq!(view.allowed, 0);
        assert_eq!(view.decisions[0].rule, "tool_allowlist");
        assert_eq!(view.decisions[0].agent, state.gate.publisher_pubkey_hex());
        assert_eq!(view.deny_rate, Some(1.0));
        assert_eq!(view.status, "idle");
    }
    #[tokio::test]
    async fn upstream_failure_does_not_rewrite_allow_as_deny() {
        let (state, _) = test_state(vec![TOOL_GITHUB_COMMENT.into()], vec!["acme/pilot".into()]);
        let req = ToolInvokeRequest {
            operation_id: Some("test-operation".into()),
            tool: TOOL_GITHUB_COMMENT.into(),
            model: "demo".into(),
            owner: "acme".into(),
            repo: "pilot".into(),
            issue_number: Some(1),
            pull_number: None,
            body: Some("local test".into()),
            commit_title: None,
        };
        let mut headers = HeaderMap::new();
        let proof = membrane_core::caller::CallerProof::sign(
            state.gate.publisher().keys(),
            &state.gate.caller_audience(),
            "/v1/tools/invoke",
            &req,
            state.default_iac.as_ref().unwrap(),
            now_secs(),
            nostr::Keys::generate().public_key().to_hex(),
        )
        .unwrap();
        headers.insert(
            "x-membrane-caller-proof",
            serde_json::to_string(&proof).unwrap().parse().unwrap(),
        );
        let _ = tools_invoke(State(state.clone()), headers, Ok(Json(req))).await;
        let view = crate::audit::snapshot(&state).await;
        assert_eq!(view.allowed, 1);
        assert_eq!(view.denied, 0);
        assert_eq!(view.decisions[0].rule, "all_authorization_checks_passed");
    }
    #[tokio::test]
    async fn metrics_empty_and_degraded_are_honest() {
        let (state, iac) = test_state(vec![], vec![]);
        let view = crate::audit::snapshot(&state).await;
        assert_eq!(view.deny_rate, None);
        state
            .session_chain
            .lock()
            .await
            .mark_degraded(&iac.scope_id, "subject_sever", now_secs());
        let view = crate::audit::snapshot(&state).await;
        assert_eq!(view.status, "degraded");
        assert!(view.degraded);
    }

    #[tokio::test]
    async fn stale_gate_heartbeat_shows_degraded_and_never_live() {
        let (state, _) = test_state(vec![], vec![]);
        let view = crate::audit::snapshot(&state).await;
        let live = view.liveness.expect("liveness reported");
        assert!(live.heartbeat_ok);
        assert_ne!(view.status, "degraded");
        state.audit.liveness().beat(now_secs() - 600);
        let view = crate::audit::snapshot(&state).await;
        assert_eq!(view.status, "degraded");
        assert!(!view.liveness.unwrap().heartbeat_ok);
        // Liveness is observational: authorization state is untouched.
        assert!(!view.router_stale && !view.degraded);
    }

    #[tokio::test]
    async fn blocks_merge_before_github_http() {
        let (state, _) = test_state(vec![TOOL_GITHUB_COMMENT.into()], vec!["acme/pilot".into()]);
        let headers = HeaderMap::new();
        let req = ToolInvokeRequest {
            operation_id: Some("test-operation".into()),
            tool: TOOL_GITHUB_MERGE.into(),
            model: "demo".into(),
            owner: "acme".into(),
            repo: "pilot".into(),
            issue_number: None,
            pull_number: Some(1),
            body: None,
            commit_title: None,
        };
        let err = handle_tool_invoke(&state, &headers, &req, &mut false)
            .await
            .unwrap_err();
        assert!(matches!(err, GateError::ToolDenied(_)));
    }

    #[tokio::test]
    async fn blocks_unlisted_repo_before_github_http() {
        let (state, _) = test_state(vec![TOOL_GITHUB_COMMENT.into()], vec!["acme/pilot".into()]);
        let headers = HeaderMap::new();
        let req = ToolInvokeRequest {
            operation_id: Some("test-operation".into()),
            tool: TOOL_GITHUB_COMMENT.into(),
            model: "demo".into(),
            owner: "acme".into(),
            repo: "other".into(),
            issue_number: Some(1),
            pull_number: None,
            body: Some("nope".into()),
            commit_title: None,
        };
        let err = handle_tool_invoke(&state, &headers, &req, &mut false)
            .await
            .unwrap_err();
        assert!(matches!(err, GateError::RepoDenied(_)));
        // The audit log names the denied repo so a read-only advisor can act on it.
        record_denied(&state, &err, "tool");
        let (_, rows) = state.audit.snapshot().unwrap();
        assert_eq!(rows[0].rule, "repository_allowlist");
        assert_eq!(rows[0].subject.as_deref(), Some("acme/other"));
    }

    #[tokio::test]
    async fn fails_closed_after_sever() {
        use membrane_core::ALERT_REASON_SUBJECT_SEVER;
        let (state, _) = test_state(vec![TOOL_GITHUB_COMMENT.into()], vec!["acme/pilot".into()]);
        {
            let mut chain = state.session_chain.lock().await;
            chain.mark_degraded("pilot-scope", ALERT_REASON_SUBJECT_SEVER, now_secs());
        }
        let headers = HeaderMap::new();
        let req = ToolInvokeRequest {
            operation_id: Some("test-operation".into()),
            tool: TOOL_GITHUB_COMMENT.into(),
            model: "demo".into(),
            owner: "acme".into(),
            repo: "pilot".into(),
            issue_number: Some(1),
            pull_number: None,
            body: Some("after sever".into()),
            commit_title: None,
        };
        let err = handle_tool_invoke(&state, &headers, &req, &mut false)
            .await
            .unwrap_err();
        assert!(matches!(err, GateError::SessionDegraded(_, _)));
    }
    #[tokio::test]
    async fn unauthenticated_handler_has_no_identity_and_never_allows() {
        let (state, _) = test_state(vec![TOOL_GITHUB_COMMENT.into()], vec!["acme/pilot".into()]);
        let req = ToolInvokeRequest {
            operation_id: Some("test-operation".into()),
            tool: TOOL_GITHUB_COMMENT.into(),
            model: "demo".into(),
            owner: "acme".into(),
            repo: "pilot".into(),
            issue_number: Some(1),
            pull_number: None,
            body: Some("test".into()),
            commit_title: None,
        };
        let mut h = HeaderMap::new();
        h.insert("x-agent-id", "forged".parse().unwrap());
        let response = tools_invoke(State(state.clone()), h, Ok(Json(req))).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let v = crate::audit::snapshot(&state).await;
        assert_eq!(v.allowed, 0);
        assert_eq!(v.decisions[0].rule, "identity_authentication");
        assert_eq!(v.decisions[0].authenticated_identity, None);
    }
    #[tokio::test]
    async fn distinct_caller_is_recorded_on_chat_allow_and_identity_denial() {
        let (mut state, mut iac) = test_state(vec![], vec![]);
        let caller = Keys::generate();
        let id = caller.public_key().to_hex();
        iac.caller_pubkey = Some(id.clone());
        iac.sign(state.gate.publisher().keys()).unwrap();
        let mut registry = state.gate.registry().clone();
        let mut grant = registry.identities.values().next().unwrap().clone();
        registry.identities = [(id.clone(), grant.clone())].into();
        state.gate = Arc::new(Gate::new(
            registry.clone(),
            BusPublisher::new(BusPublisherConfig {
                relay_url: "memory://identity-http".into(),
                keys: state.gate.publisher().keys().clone(),
            }),
        ));
        state.default_iac = Some(iac.clone());
        let req = ChatRequest {
            model: "demo".into(),
            messages: vec![crate::ChatMessage {
                role: "user".into(),
                content: "hello".into(),
            }],
            stream: false,
        };
        let proof = membrane_core::caller::CallerProof::sign(
            &caller,
            &state.gate.caller_audience(),
            "/v1/chat/completions",
            &req,
            &iac,
            now_secs(),
            Keys::generate().public_key().to_hex(),
        )
        .unwrap();
        let mut h = HeaderMap::new();
        h.insert(
            "x-membrane-caller-proof",
            serde_json::to_string(&proof).unwrap().parse().unwrap(),
        );
        assert_eq!(
            chat_completions(State(state.clone()), h, Ok(Json(req.clone())))
                .await
                .status(),
            StatusCode::OK
        );
        let v = crate::audit::snapshot(&state).await;
        assert_eq!(v.allowed, 1);
        assert_eq!(
            v.decisions[0].authenticated_identity.as_deref(),
            Some(id.as_str())
        );
        assert_ne!(v.decisions[0].agent, id);
        grant.revoked = true;
        registry.identities.insert(id.clone(), grant);
        state.gate = Arc::new(Gate::new(
            registry,
            BusPublisher::new(BusPublisherConfig {
                relay_url: "memory://identity-http".into(),
                keys: state.gate.publisher().keys().clone(),
            }),
        ));
        let proof = membrane_core::caller::CallerProof::sign(
            &caller,
            &state.gate.caller_audience(),
            "/v1/chat/completions",
            &req,
            &iac,
            now_secs(),
            Keys::generate().public_key().to_hex(),
        )
        .unwrap();
        let mut h = HeaderMap::new();
        h.insert(
            "x-membrane-caller-proof",
            serde_json::to_string(&proof).unwrap().parse().unwrap(),
        );
        assert_eq!(
            chat_completions(State(state.clone()), h, Ok(Json(req)))
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        let v = crate::audit::snapshot(&state).await;
        assert_eq!(v.decisions[0].rule, "identity_grant");
        assert_eq!(
            v.decisions[0].authenticated_identity.as_deref(),
            Some(id.as_str())
        );
    }
    #[tokio::test]
    async fn reconciliation_reads_only_and_never_unblocks_same_id() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let (mut state, iac) =
            test_state(vec![TOOL_GITHUB_COMMENT.into()], vec!["acme/pilot".into()]);
        let reads = Arc::new(AtomicUsize::new(0));
        let writes = Arc::new(AtomicUsize::new(0));
        let r = reads.clone();
        let w = writes.clone();
        let app = axum::Router::new().route(
            "/repos/acme/pilot/issues/1/comments",
            get(move || {
                let r = r.clone();
                async move {
                    r.fetch_add(1, Ordering::SeqCst);
                    Json(json!([{"id":42,"body":"local test"}]))
                }
            })
            .post(move || {
                let w = w.clone();
                async move {
                    w.fetch_add(1, Ordering::SeqCst);
                    Json(json!({"id":42}))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        state.github = Arc::new(GitHubConnector::new(GitHubConnectorConfig {
            repo_allowlist: vec!["acme/pilot".into()],
            api_base: format!("http://{}", listener.local_addr().unwrap()),
            token: Some("fake".into()),
        }));
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let req = comment_request();
        let path = state
            .operations
            .reserve_in_scope(iac.caller_pubkey.as_deref().unwrap(), &iac.scope_id, &req)
            .unwrap();
        state.operations.finish(&path, false).unwrap();
        let report = crate::reconciliation::reconcile(&state).await.unwrap();
        assert_eq!(report["operations"][0]["state"], "operator_review");
        assert_eq!(report["operations"][0]["evidence"]["matching_ids"][0], 42);
        assert_eq!(
            report["operations"][0]["evidence"]["attribution_verified"],
            false
        );
        assert!(
            handle_tool_invoke(&state, &HeaderMap::new(), &req, &mut false)
                .await
                .is_err()
        );
        assert_eq!(reads.load(Ordering::SeqCst), 1);
        assert_eq!(writes.load(Ordering::SeqCst), 0);
        task.abort();
    }

    #[tokio::test]
    async fn unavailable_reconciliation_is_operator_review_not_absence() {
        let (state, iac) = test_state(vec![TOOL_GITHUB_COMMENT.into()], vec!["acme/pilot".into()]);
        let req = comment_request();
        state
            .operations
            .reserve_in_scope(iac.caller_pubkey.as_deref().unwrap(), &iac.scope_id, &req)
            .unwrap();
        let report = crate::reconciliation::reconcile(&state).await.unwrap();
        assert_eq!(report["operations"][0]["state"], "operator_review");
        assert_eq!(
            report["operations"][0]["evidence"]["observation"],
            "unverifiable"
        );
    }
    #[tokio::test]
    async fn handler_restart_restores_receipt_and_preserves_deduplication() {
        let (mut state, iac) =
            test_state(vec![TOOL_GITHUB_COMMENT.into()], vec!["acme/pilot".into()]);
        let req = comment_request();
        let mut authorized = false;
        assert!(
            handle_tool_invoke(&state, &HeaderMap::new(), &req, &mut authorized)
                .await
                .is_err()
        );
        assert!(authorized); // unreachable fake upstream, but durable intent and receipt
        let recovered = state
            .operations
            .import_relay(&[], &state.gate.publisher_pubkey_hex())
            .unwrap();
        assert_eq!(recovered.scopes[&iac.scope_id].0, 1);
        state.session_chain = Arc::new(Mutex::new(recovered));
        let before = state.session_chain.lock().await.last_cp_hash.clone();
        assert!(
            handle_tool_invoke(&state, &HeaderMap::new(), &req, &mut false)
                .await
                .is_err()
        );
        assert_eq!(state.session_chain.lock().await.last_cp_hash, before);
        assert_eq!(state.operations.unresolved().unwrap()[0].state, "uncertain");
    }
}
