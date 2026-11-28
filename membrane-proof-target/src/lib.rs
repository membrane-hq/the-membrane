//! Disposable target fixture for the deploy-boundary proof.
//!
//! A tiny policy-gated HTTP service with a seeded defect: with no mitigation
//! installed it accepts a `count` of any size on `POST /evaluate`. The
//! mitigation is a strict JSON policy artifact (`{"schema_version":1,
//! "max_count":N}`) installed by the gate-side executor through the fixed
//! protocol below. It is deliberately a deployment fixture, not an eBPF or
//! vulnerability-research result.
//!
//! Fixed protocol (the only surface the executor may use):
//! - `GET /health` -> 200
//! - `GET /state` -> `{"policy_sha256","image","state_sha256"}` (digests only)
//! - `GET /policy` -> the installed policy bytes, 404 when the default
//!   (defective) policy is in force
//! - `PUT /policy` (raw bytes) -> validate strictly, atomically replace, 204
//! - `DELETE /policy` -> restore the default policy, 204
//! - `POST /evaluate` `{"count":N}` -> 200, or 422 when policy refuses it
//!
//! Optional `--state-file` persists the policy across restarts (atomic
//! tmp-then-rename writes) so the harness can test restart behavior.

use axum::{
    body::Bytes,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

/// Pinned fixture image identifier, part of the target state digest.
pub const IMAGE_ID: &str = "membrane-proof-target/v1";
pub const MAX_POLICY_BYTES: usize = 4096;
pub const MAX_COUNT_LIMIT: u32 = 100_000;

/// The digest scheme the executor recomputes locally:
/// sha256("membrane-target-state/v1" NUL policy_sha256 NUL image).
pub fn state_digest(policy_sha256: &str, image: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"membrane-target-state/v1\0");
    h.update(policy_sha256.as_bytes());
    h.update(b"\0");
    h.update(image.as_bytes());
    hex::encode(h.finalize())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Strict policy artifact. Unknown keys, another schema version or an
/// out-of-range limit are refused; the target never accepts looser input than
/// the executor was allowed to send.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub schema_version: u32,
    pub max_count: u32,
}

pub fn parse_policy(bytes: &[u8]) -> Result<Policy, String> {
    if bytes.len() > MAX_POLICY_BYTES {
        return Err("policy artifact too large".into());
    }
    let policy: Policy =
        serde_json::from_slice(bytes).map_err(|e| format!("invalid policy: {e}"))?;
    if policy.schema_version != 1 {
        return Err(format!(
            "unsupported schema_version {}",
            policy.schema_version
        ));
    }
    if policy.max_count > MAX_COUNT_LIMIT {
        return Err(format!("max_count above limit {MAX_COUNT_LIMIT}"));
    }
    Ok(policy)
}

struct Target {
    state_file: Option<PathBuf>,
    /// None is the seeded defect: no policy installed, any count is accepted.
    policy: Mutex<Option<Vec<u8>>>,
}

impl Target {
    fn load(state_file: Option<PathBuf>) -> Self {
        let policy = state_file
            .as_ref()
            .and_then(|p| std::fs::read(p).ok())
            .filter(|bytes| parse_policy(bytes).is_ok());
        Self {
            state_file,
            policy: Mutex::new(policy),
        }
    }

    /// Atomic replace: write tmp, fsync, rename, fsync the directory.
    fn persist(&self, policy: &Option<Vec<u8>>) -> Result<(), StatusCode> {
        let Some(path) = &self.state_file else {
            return Ok(());
        };
        match policy {
            Some(bytes) => {
                let tmp = path.with_extension("tmp");
                {
                    use std::io::Write;
                    let mut f = std::fs::File::create(&tmp)
                        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                    f.write_all(bytes)
                        .and_then(|_| f.sync_all())
                        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                }
                std::fs::rename(&tmp, path).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            }
            None => match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
            },
        }
        if let Some(dir) = path.parent() {
            let _ = std::fs::File::open(dir).and_then(|f| f.sync_all());
        }
        Ok(())
    }

    fn policy_digest(&self) -> String {
        let guard = self.policy.lock().expect("not poisoned");
        sha256_hex(guard.as_deref().unwrap_or(&[]))
    }
}

#[derive(Deserialize)]
struct Evaluate {
    count: u32,
}

async fn health() -> StatusCode {
    StatusCode::OK
}

async fn get_state(State(target): State<Arc<Target>>) -> impl IntoResponse {
    let policy_sha256 = target.policy_digest();
    Json(serde_json::json!({
        "policy_sha256": policy_sha256,
        "image": IMAGE_ID,
        "state_sha256": state_digest(&policy_sha256, IMAGE_ID),
    }))
}

async fn get_policy(State(target): State<Arc<Target>>) -> impl IntoResponse {
    let guard = target.policy.lock().expect("not poisoned");
    match guard.as_deref() {
        Some(bytes) => (StatusCode::OK, bytes.to_vec()).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn put_policy(State(target): State<Arc<Target>>, body: Bytes) -> impl IntoResponse {
    if body.len() > MAX_POLICY_BYTES {
        return (StatusCode::PAYLOAD_TOO_LARGE, "policy artifact too large").into_response();
    }
    if let Err(reason) = parse_policy(&body) {
        return (StatusCode::UNPROCESSABLE_ENTITY, reason).into_response();
    }
    let policy = Some(body.to_vec());
    if target.persist(&policy).is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    *target.policy.lock().expect("not poisoned") = policy;
    StatusCode::NO_CONTENT.into_response()
}

async fn delete_policy(State(target): State<Arc<Target>>) -> impl IntoResponse {
    if target.persist(&None).is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    *target.policy.lock().expect("not poisoned") = None;
    StatusCode::NO_CONTENT.into_response()
}

async fn evaluate(
    State(target): State<Arc<Target>>,
    Json(request): Json<Evaluate>,
) -> impl IntoResponse {
    let guard = target.policy.lock().expect("not poisoned");
    if let Some(bytes) = guard.as_deref() {
        if let Ok(policy) = parse_policy(bytes) {
            if request.count > policy.max_count {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(serde_json::json!({"ok": false, "error": "count exceeds policy"})),
                )
                    .into_response();
            }
        }
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({"ok": true, "count": request.count})),
    )
        .into_response()
}

pub fn router(state_file: Option<PathBuf>) -> Router {
    let target = Arc::new(Target::load(state_file));
    Router::new()
        .route("/health", get(health))
        .route("/state", get(get_state))
        .route("/policy", get(get_policy))
        .route("/policy", put(put_policy))
        .route("/policy", delete(delete_policy))
        .route("/evaluate", post(evaluate))
        .with_state(target)
}

pub async fn serve(listen: &str, state_file: Option<PathBuf>) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, router(state_file)).await
}

/// Bind an ephemeral loopback port for tests and the local harness. Returns
/// the base URL and the server task.
pub async fn spawn_ephemeral(
    state_file: Option<PathBuf>,
) -> std::io::Result<(String, tokio::task::JoinHandle<()>)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        axum::serve(listener, router(state_file)).await.ok();
    });
    Ok((format!("http://{address}"), server))
}
