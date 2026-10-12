//! No connector here proves causality. Evidence is review-only; never delete reservations.
use crate::{operations::Record, server::GateServerState, GateError};
use axum::{extract::State, http::StatusCode, Json};
use serde_json::{json, Value};

pub async fn reconcile(state: &GateServerState) -> Result<Value, GateError> {
    // Same serialization as dispatch, so no observation races with a local write.
    let _chain = state.session_chain.lock().await;
    let unresolved = state.operations.unresolved()?;
    for operation in unresolved {
        let evidence = match state.github.observe(&operation.request).await {
            Ok(evidence) => evidence,
            Err(_) => {
                json!({"observation":"unverifiable", "reason":"connector_unavailable_or_denied"})
            }
        };
        state.operations.append(Record::Review {
            key: operation.key,
            evidence,
        })?;
    }
    Ok(
        json!({"operations":state.operations.unresolved()?, "legacy_reservations":state.operations.legacy_reservations()?, "spend_open":spend_open(state)?, "automatic_retry":false}),
    )
}
/// Spend reservations still holding budget. Reported only; never retried or
/// resolved automatically, because a rail balance cannot attribute one charge.
fn spend_open(state: &GateServerState) -> Result<Value, GateError> {
    match &state.spend {
        None => Ok(json!([])),
        Some(s) => Ok(json!(s
            .ledger
            .open_reservations()
            .map_err(|e| GateError::Spend(e.to_string()))?)),
    }
}
pub async fn list(
    State(state): State<GateServerState>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let _chain = state.session_chain.lock().await;
    Ok(Json(
        json!({"operations":state.operations.unresolved().map_err(error)?, "legacy_reservations":state.operations.legacy_reservations().map_err(error)?, "spend_open":spend_open(&state).map_err(error)?, "automatic_retry":false}),
    ))
}
pub async fn run(
    State(state): State<GateServerState>,
) -> Result<Json<Value>, (StatusCode, String)> {
    reconcile(&state).await.map(Json).map_err(error)
}
fn error(e: GateError) -> (StatusCode, String) {
    (StatusCode::SERVICE_UNAVAILABLE, e.to_string())
}
