//! Approval gates: a call to a tool the operator marked holdable, which the caller's
//! grant does not cover, is held instead of blocked. A human operator approves or
//! rejects it. An approval authorizes exactly one call, bound to the caller, scope and
//! request bytes, and is consumed when that call is dispatched. The decision is an
//! operator action; it never widens the caller's standing grant.
use crate::GateError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;

/// Operator policy for approval gates, set in the channel registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalPolicy {
    /// Tools that may be held. Any other out-of-scope tool is blocked as before.
    #[serde(default)]
    pub holdable_tools: Vec<String>,
    /// Seconds a hold stays open, and seconds an approval stays usable.
    #[serde(default = "default_ttl_secs")]
    pub ttl_secs: i64,
}

fn default_ttl_secs() -> i64 {
    900
}

impl ApprovalPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=86_400).contains(&self.ttl_secs) {
            return Err("approval ttl_secs must be between 1 and 86400".into());
        }
        if self.holdable_tools.iter().any(|t| t.is_empty()) {
            return Err("approval holdable_tools must not contain empty names".into());
        }
        Ok(())
    }
    pub fn holds(&self, tool: &str) -> bool {
        self.holdable_tools.iter().any(|t| t == tool)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalState {
    Pending,
    Approved,
    Rejected,
    Consumed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    pub id: String,
    pub call_hash: String,
    pub identity: String,
    pub scope_id: String,
    pub tool: String,
    pub target: String,
    pub request: serde_json::Value,
    pub requested_at: i64,
    pub expires_at: i64,
    pub state: ApprovalState,
    #[serde(default)]
    pub decided_by: Option<String>,
    #[serde(default)]
    pub decided_at: Option<i64>,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub consumed_at: Option<i64>,
}

impl Approval {
    pub fn is_expired(&self, now: i64) -> bool {
        now >= self.expires_at
    }
    /// State as seen at `now`: an unused hold or approval past its expiry reads as expired.
    pub fn view(&self, now: i64) -> serde_json::Value {
        let state = match self.state {
            ApprovalState::Pending | ApprovalState::Approved if self.is_expired(now) => "expired",
            ApprovalState::Pending => "pending",
            ApprovalState::Approved => "approved",
            ApprovalState::Rejected => "rejected",
            ApprovalState::Consumed => "consumed",
        };
        serde_json::json!({
            "id": self.id, "state": state, "tool": self.tool, "target": self.target,
            "identity": self.identity, "scope_id": self.scope_id,
            "requested_at": self.requested_at, "expires_at": self.expires_at,
            "decided_by": self.decided_by, "decided_at": self.decided_at,
            "note": self.note, "consumed_at": self.consumed_at,
            "request": self.request,
        })
    }
}

/// Hash that binds an approval to one call: the authenticated caller, the IAC scope
/// and the exact request. Changing any request field needs a new approval.
pub fn call_hash<T: Serialize>(
    identity: &str,
    scope_id: &str,
    request: &T,
) -> Result<String, GateError> {
    let body = serde_json::to_vec(request).map_err(|e| GateError::Registry(e.to_string()))?;
    let mut h = Sha256::new();
    h.update(b"membrane-approval-v1\0");
    h.update(identity.as_bytes());
    h.update(b"\0");
    h.update(scope_id.as_bytes());
    h.update(b"\0");
    h.update(&body);
    Ok(hex::encode(h.finalize()))
}

/// What a caller's retry finds for its call.
#[derive(Debug)]
pub enum Resolution {
    /// Approved and now consumed: the caller may dispatch exactly this call.
    Approved(Approval),
    /// Still waiting for an operator.
    Pending(Approval),
    /// Nothing usable (never held, rejected, expired or already used).
    None,
}

const MAX_OPEN: usize = 1_000;

pub struct ApprovalStore {
    path: Option<PathBuf>,
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    seq: u64,
    items: BTreeMap<String, Approval>,
}

fn store_err(msg: impl Into<String>) -> GateError {
    GateError::Registry(format!("approval store: {}", msg.into()))
}

impl ApprovalStore {
    pub fn in_memory() -> Self {
        Self {
            path: None,
            inner: Mutex::new(Inner::default()),
        }
    }

    /// Durable store: one JSON file, rewritten and fsynced on every change. A store that
    /// cannot be read or written fails closed (no hold opens, no approval is consumed).
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, GateError> {
        let path = path.into();
        let mut inner = Inner::default();
        match std::fs::read(&path) {
            Ok(bytes) => {
                let items: Vec<Approval> = serde_json::from_slice(&bytes)
                    .map_err(|e| store_err(format!("corrupt file: {e}")))?;
                inner.seq = items.len() as u64;
                inner.items = items.into_iter().map(|a| (a.id.clone(), a)).collect();
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(store_err(format!("read failed: {e}"))),
        }
        Ok(Self {
            path: Some(path),
            inner: Mutex::new(inner),
        })
    }

    fn persist(&self, inner: &Inner) -> Result<(), GateError> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let items: Vec<&Approval> = inner.items.values().collect();
        let bytes = serde_json::to_vec_pretty(&items).map_err(|e| store_err(e.to_string()))?;
        let tmp = path.with_extension("tmp");
        {
            use std::io::Write;
            let mut f =
                std::fs::File::create(&tmp).map_err(|e| store_err(format!("write failed: {e}")))?;
            f.write_all(&bytes)
                .map_err(|e| store_err(format!("write failed: {e}")))?;
            f.sync_all()
                .map_err(|e| store_err(format!("fsync failed: {e}")))?;
        }
        std::fs::rename(&tmp, path).map_err(|e| store_err(format!("rename failed: {e}")))
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Inner>, GateError> {
        self.inner.lock().map_err(|_| store_err("lock poisoned"))
    }

    /// Find the caller's hold for this call, or open one. Returns the record and whether
    /// it was newly opened.
    #[allow(clippy::too_many_arguments)]
    pub fn open_hold(
        &self,
        call_hash: &str,
        identity: &str,
        scope_id: &str,
        tool: &str,
        target: &str,
        request: serde_json::Value,
        now: i64,
        ttl_secs: i64,
    ) -> Result<(Approval, bool), GateError> {
        let mut inner = self.lock()?;
        if let Some(existing) = inner.items.values().find(|a| {
            a.call_hash == call_hash && a.state == ApprovalState::Pending && !a.is_expired(now)
        }) {
            return Ok((existing.clone(), false));
        }
        let open = inner
            .items
            .values()
            .filter(|a| {
                matches!(a.state, ApprovalState::Pending | ApprovalState::Approved)
                    && !a.is_expired(now)
            })
            .count();
        if open >= MAX_OPEN {
            return Err(store_err("too many open approvals"));
        }
        inner.seq += 1;
        let id = hex::encode(Sha256::digest(
            format!("{call_hash}\0{now}\0{}", inner.seq).as_bytes(),
        ))[..32]
            .to_string();
        let approval = Approval {
            id: id.clone(),
            call_hash: call_hash.into(),
            identity: identity.into(),
            scope_id: scope_id.into(),
            tool: tool.into(),
            target: target.into(),
            request,
            requested_at: now,
            expires_at: now.saturating_add(ttl_secs),
            state: ApprovalState::Pending,
            decided_by: None,
            decided_at: None,
            note: None,
            consumed_at: None,
        };
        inner.items.insert(id.clone(), approval.clone());
        if let Err(e) = self.persist(&inner) {
            inner.items.remove(&id);
            return Err(e);
        }
        Ok((approval, true))
    }

    /// Record an operator decision on a pending hold.
    pub fn decide(
        &self,
        id: &str,
        approve: bool,
        operator: &str,
        note: Option<String>,
        now: i64,
    ) -> Result<Approval, GateError> {
        let mut inner = self.lock()?;
        let before = inner
            .items
            .get(id)
            .cloned()
            .ok_or_else(|| store_err("unknown approval id"))?;
        if before.state != ApprovalState::Pending {
            return Err(store_err("approval is not pending"));
        }
        if before.is_expired(now) {
            return Err(store_err("approval request expired"));
        }
        let item = inner.items.get_mut(id).expect("present");
        item.state = if approve {
            ApprovalState::Approved
        } else {
            ApprovalState::Rejected
        };
        item.decided_by = Some(operator.into());
        item.decided_at = Some(now);
        item.note = note;
        let updated = item.clone();
        if let Err(e) = self.persist(&inner) {
            inner.items.insert(id.into(), before);
            return Err(e);
        }
        Ok(updated)
    }

    /// For a retried call: consume a matching approval (one use), or report a pending hold.
    pub fn resolve(&self, call_hash: &str, now: i64) -> Result<Resolution, GateError> {
        let mut inner = self.lock()?;
        let approved = inner
            .items
            .values()
            .find(|a| {
                a.call_hash == call_hash && a.state == ApprovalState::Approved && !a.is_expired(now)
            })
            .map(|a| a.id.clone());
        if let Some(id) = approved {
            let before = inner.items.get(&id).cloned().expect("present");
            let item = inner.items.get_mut(&id).expect("present");
            item.state = ApprovalState::Consumed;
            item.consumed_at = Some(now);
            let consumed = item.clone();
            if let Err(e) = self.persist(&inner) {
                inner.items.insert(id, before);
                return Err(e);
            }
            return Ok(Resolution::Approved(consumed));
        }
        Ok(inner
            .items
            .values()
            .find(|a| {
                a.call_hash == call_hash && a.state == ApprovalState::Pending && !a.is_expired(now)
            })
            .cloned()
            .map(Resolution::Pending)
            .unwrap_or(Resolution::None))
    }

    pub fn get(&self, id: &str) -> Result<Option<Approval>, GateError> {
        Ok(self.lock()?.items.get(id).cloned())
    }

    pub fn list(&self) -> Result<Vec<Approval>, GateError> {
        Ok(self.lock()?.items.values().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hold(store: &ApprovalStore, now: i64) -> Approval {
        store
            .open_hold(
                "h",
                "id",
                "scope",
                "github.merge",
                "acme/pilot",
                serde_json::json!({}),
                now,
                100,
            )
            .unwrap()
            .0
    }

    #[test]
    fn hold_is_idempotent_while_pending() {
        let store = ApprovalStore::in_memory();
        let a = hold(&store, 10);
        let (b, fresh) = store
            .open_hold(
                "h",
                "id",
                "scope",
                "github.merge",
                "acme/pilot",
                serde_json::json!({}),
                11,
                100,
            )
            .unwrap();
        assert!(!fresh);
        assert_eq!(a.id, b.id);
    }

    #[test]
    fn approval_is_single_use() {
        let store = ApprovalStore::in_memory();
        let a = hold(&store, 10);
        assert!(matches!(
            store.resolve("h", 11).unwrap(),
            Resolution::Pending(_)
        ));
        store.decide(&a.id, true, "op", None, 12).unwrap();
        assert!(matches!(
            store.resolve("h", 13).unwrap(),
            Resolution::Approved(_)
        ));
        assert!(matches!(store.resolve("h", 14).unwrap(), Resolution::None));
    }

    #[test]
    fn rejected_and_expired_never_execute() {
        let store = ApprovalStore::in_memory();
        let a = hold(&store, 10);
        store
            .decide(&a.id, false, "op", Some("no".into()), 12)
            .unwrap();
        assert!(matches!(store.resolve("h", 13).unwrap(), Resolution::None));
        let b = store
            .open_hold("h2", "id", "scope", "t", "r", serde_json::json!({}), 20, 5)
            .unwrap()
            .0;
        store.decide(&b.id, true, "op", None, 21).unwrap();
        assert!(matches!(store.resolve("h2", 25).unwrap(), Resolution::None));
        assert!(store.decide(&b.id, true, "op", None, 22).is_err());
    }

    #[test]
    fn decision_cannot_be_changed_or_made_after_expiry() {
        let store = ApprovalStore::in_memory();
        let a = hold(&store, 10);
        assert!(store.decide(&a.id, true, "op", None, 200).is_err());
        let b = store
            .open_hold(
                "h3",
                "id",
                "scope",
                "t",
                "r",
                serde_json::json!({}),
                10,
                100,
            )
            .unwrap()
            .0;
        store.decide(&b.id, false, "op", None, 11).unwrap();
        assert!(store.decide(&b.id, true, "op", None, 12).is_err());
    }

    #[test]
    fn call_hash_binds_identity_scope_and_request() {
        let r = serde_json::json!({"a": 1});
        let base = call_hash("id", "s", &r).unwrap();
        assert_ne!(base, call_hash("id2", "s", &r).unwrap());
        assert_ne!(base, call_hash("id", "s2", &r).unwrap());
        assert_ne!(
            base,
            call_hash("id", "s", &serde_json::json!({"a": 2})).unwrap()
        );
    }

    #[test]
    fn durable_store_survives_restart_and_stays_consumed() {
        let dir = std::env::temp_dir().join(format!("membrane-approvals-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("approvals.json");
        let store = ApprovalStore::open(&path).unwrap();
        let a = hold(&store, 10);
        store.decide(&a.id, true, "op", None, 11).unwrap();
        assert!(matches!(
            store.resolve("h", 12).unwrap(),
            Resolution::Approved(_)
        ));
        let reopened = ApprovalStore::open(&path).unwrap();
        assert!(matches!(
            reopened.resolve("h", 13).unwrap(),
            Resolution::None
        ));
        assert_eq!(reopened.list().unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_store_fails_closed() {
        let dir =
            std::env::temp_dir().join(format!("membrane-approvals-bad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("approvals.json");
        std::fs::write(&path, b"not json").unwrap();
        assert!(ApprovalStore::open(&path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
