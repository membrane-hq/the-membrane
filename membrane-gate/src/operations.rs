//! Single-instance, append-only journal. Corrupt/torn records block the gate.
use crate::{deploy::DeployRequest, github::ToolInvokeRequest, GateError};
use membrane_core::{event::MembraneEvent, SessionChainState};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Mutex,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Record {
    Intent {
        key: String,
        caller: String,
        scope: String,
        request: ToolInvokeRequest,
    },
    /// A reserved `deploy.apply` / `deploy.remove`. Same key space and lifecycle
    /// as `Intent`; kept as its own variant so older journals and GitHub
    /// reconciliation are untouched.
    DeployIntent {
        key: String,
        caller: String,
        scope: String,
        request: DeployRequest,
    },
    Outcome {
        key: String,
        state: String,
    },
    Review {
        key: String,
        evidence: serde_json::Value,
    },
    Publishing {
        token: String,
    },
    PublicationAborted {
        token: String,
    },
    Checkpoint {
        token: String,
        caller: String,
        event: MembraneEvent,
        bus_event_id: Option<String>,
    },
    Sever {
        scope: String,
        reason: String,
        at: i64,
    },
}
#[derive(Serialize, Deserialize)]
struct Frame {
    sequence: u64,
    previous: String,
    record: Record,
    checksum: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct UnresolvedOperation {
    pub key: String,
    pub caller: String,
    pub scope: String,
    pub state: String,
    pub request: ToolInvokeRequest,
    pub evidence: Option<serde_json::Value>,
}
#[derive(Debug, Clone, Serialize)]
pub struct UnresolvedDeploy {
    pub key: String,
    pub caller: String,
    pub scope: String,
    pub state: String,
    pub request: DeployRequest,
    pub evidence: Option<serde_json::Value>,
}
#[derive(Default)]
pub struct Recovery {
    pub chain: SessionChainState,
    pub callers: BTreeMap<String, String>,
    pub pending: BTreeMap<String, ()>,
}
pub struct OperationJournal {
    path: PathBuf,
    lock: Mutex<Option<File>>,
    writer: Mutex<()>,
}
impl OperationJournal {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            lock: Mutex::new(None),
            writer: Mutex::new(()),
        }
    }
    pub fn from_env() -> Self {
        Self::new(
            std::env::var_os("MEMBRANE_OPERATION_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(".membrane/tool-operations")),
        )
    }
    fn acquire(&self) -> Result<(), GateError> {
        let mut lock = self
            .lock
            .lock()
            .map_err(|_| failure("poisoned journal lock"))?;
        if lock.is_none() {
            fs::create_dir_all(&self.path).map_err(io_error)?;
            // Persist newly created directory entries through their parent chain.
            let absolute = fs::canonicalize(&self.path).map_err(io_error)?;
            for ancestor in absolute.ancestors() {
                File::open(ancestor)
                    .and_then(|f| f.sync_all())
                    .map_err(io_error)?;
            }
            let mut options = OpenOptions::new();
            options.create(true).truncate(false).read(true).write(true);
            #[cfg(unix)]
            options.mode(0o600);
            let file = options
                .open(self.path.join("instance.lock"))
                .map_err(io_error)?;
            file.try_lock()
                .map_err(|e| failure(format!("instance journal already locked: {e}")))?;
            *lock = Some(file);
        }
        Ok(())
    }
    pub fn records(&self) -> Result<Vec<Record>, GateError> {
        let _writer = self.writer.lock().map_err(|_| failure("poisoned writer"))?;
        self.records_inner()
    }
    fn records_inner(&self) -> Result<Vec<Record>, GateError> {
        self.acquire()?;
        let bytes = match fs::read(self.path.join("journal.jsonl")) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(e) => return Err(io_error(e)),
        };
        if !bytes.is_empty() && !bytes.ends_with(b"\n") {
            return Err(failure("torn journal tail; operator review required"));
        }
        let mut prev = "0".repeat(64);
        let mut records = vec![];
        for (index, line) in bytes
            .strip_suffix(b"\n")
            .unwrap_or(&bytes)
            .split(|b| *b == b'\n')
            .filter(|l| !bytes.is_empty() || !l.is_empty())
            .enumerate()
        {
            let frame: Frame = serde_json::from_slice(line).map_err(|e| failure(e.to_string()))?;
            let checksum = digest(&(frame.sequence, &frame.previous, &frame.record))?;
            if frame.sequence != index as u64
                || frame.previous != prev
                || frame.checksum != checksum
            {
                return Err(failure("journal checksum/sequence discontinuity"));
            }
            prev = frame.checksum;
            records.push(frame.record);
        }
        Ok(records)
    }
    // Gate session mutex serializes journal transitions; the instance lock excludes other processes.
    pub fn append(&self, record: Record) -> Result<(), GateError> {
        let _writer = self.writer.lock().map_err(|_| failure("poisoned writer"))?;
        self.append_inner(record)
    }
    fn append_inner(&self, record: Record) -> Result<(), GateError> {
        let records = self.records_inner()?;
        let mut previous = "0".repeat(64);
        for (i, record) in records.iter().enumerate() {
            previous = digest(&(i as u64, &previous, record))?;
        }
        let sequence = records.len() as u64;
        let checksum = digest(&(sequence, &previous, &record))?;
        let frame = Frame {
            sequence,
            previous,
            record,
            checksum,
        };
        let mut bytes = serde_json::to_vec(&frame).map_err(|e| failure(e.to_string()))?;
        bytes.push(b'\n');
        let mut options = OpenOptions::new();
        options.append(true).create(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options
            .open(self.path.join("journal.jsonl"))
            .map_err(io_error)?;
        file.write_all(&bytes).map_err(io_error)?;
        file.sync_all().map_err(io_error)?;
        File::open(&self.path)
            .and_then(|f| f.sync_all())
            .map_err(io_error)
    }
    pub fn reserve(&self, caller: &str, req: &ToolInvokeRequest) -> Result<PathBuf, GateError> {
        self.reserve_in_scope(caller, "legacy", req)
    }
    pub fn reserve_in_scope(
        &self,
        caller: &str,
        scope: &str,
        req: &ToolInvokeRequest,
    ) -> Result<PathBuf, GateError> {
        let _writer = self.writer.lock().map_err(|_| failure("poisoned writer"))?;
        let id = req
            .operation_id
            .as_deref()
            .filter(|s| !s.trim().is_empty() && s.len() <= 128)
            .ok_or_else(|| failure("mutating tools require operation_id (1-128 bytes)"))?;
        let key = digest(&(caller, id))?;
        let records = self.records_inner()?;
        if self.path.join(format!("{key}.jsonl")).exists()
            || records
                .iter()
                .any(|r| matches!(r, Record::Intent { key: k, .. } | Record::DeployIntent { key: k, .. } if k == &key))
        {
            return Err(failure(
                "operation already reserved; never automatically retry",
            ));
        }
        self.append_inner(Record::Intent {
            key: key.clone(),
            caller: caller.into(),
            scope: scope.into(),
            request: req.clone(),
        })?;
        Ok(self.path.join(key))
    }
    /// Durably reserve a deploy operation before dispatch. The key is
    /// (caller, operation_id), the same key space as `reserve_in_scope`, so one
    /// operation ID can never be reused across tools by the same caller.
    pub fn reserve_deploy_in_scope(
        &self,
        caller: &str,
        scope: &str,
        req: &DeployRequest,
    ) -> Result<PathBuf, GateError> {
        let _writer = self.writer.lock().map_err(|_| failure("poisoned writer"))?;
        if req.operation_id.trim().is_empty() || req.operation_id.len() > 128 {
            return Err(failure("deploy requires operation_id (1-128 bytes)"));
        }
        let key = digest(&(caller, req.operation_id.as_str()))?;
        let records = self.records_inner()?;
        if self.path.join(format!("{key}.jsonl")).exists()
            || records.iter().any(|r| {
                matches!(r, Record::Intent { key: k, .. } | Record::DeployIntent { key: k, .. } if k == &key)
            })
        {
            return Err(failure(
                "operation already reserved; never automatically retry",
            ));
        }
        self.append_inner(Record::DeployIntent {
            key: key.clone(),
            caller: caller.into(),
            scope: scope.into(),
            request: req.clone(),
        })?;
        Ok(self.path.join(key))
    }
    /// A call refused before dispatch: close the reservation with an explicit
    /// outcome. Nothing ran upstream, so there is nothing to reconcile.
    pub fn finish_refused(&self, path: &Path) -> Result<(), GateError> {
        let key = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| failure("invalid operation key"))?
            .to_string();
        if !self.is_unresolved(&key)? {
            return Err(failure("refused outcome missing unresolved intent"));
        }
        self.append(Record::Outcome {
            key,
            state: "refused".into(),
        })
    }
    pub fn finish(&self, path: &Path, success: bool) -> Result<(), GateError> {
        let key = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| failure("invalid operation key"))?
            .to_string();
        if !self.is_unresolved(&key)? {
            return Err(failure("outcome missing unresolved intent"));
        }
        self.append(Record::Outcome {
            key,
            state: if success { "completed" } else { "uncertain" }.into(),
        })
    }
    fn is_unresolved(&self, key: &str) -> Result<bool, GateError> {
        let (tools, deploys) = self.ledger()?;
        Ok(tools.iter().any(|op| op.key == key) || deploys.iter().any(|op| op.key == key))
    }
    pub fn unresolved(&self) -> Result<Vec<UnresolvedOperation>, GateError> {
        Ok(self.ledger()?.0)
    }
    /// Unresolved deploy operations. Reconciliation never retries them; an
    /// uncertain write stays reserved until read-only evidence is reviewed.
    pub fn unresolved_deploys(&self) -> Result<Vec<UnresolvedDeploy>, GateError> {
        Ok(self.ledger()?.1)
    }
    fn ledger(&self) -> Result<(Vec<UnresolvedOperation>, Vec<UnresolvedDeploy>), GateError> {
        let mut operations = BTreeMap::new();
        let mut deploys = BTreeMap::new();
        for record in self.records()? {
            match record {
                Record::Intent {
                    key,
                    caller,
                    scope,
                    request,
                } => {
                    operations.insert(
                        key.clone(),
                        UnresolvedOperation {
                            key,
                            caller,
                            scope,
                            request,
                            state: "reserved".into(),
                            evidence: None,
                        },
                    );
                }
                Record::DeployIntent {
                    key,
                    caller,
                    scope,
                    request,
                } => {
                    deploys.insert(
                        key.clone(),
                        UnresolvedDeploy {
                            key,
                            caller,
                            scope,
                            request,
                            state: "reserved".into(),
                            evidence: None,
                        },
                    );
                }
                Record::Outcome { key, state } => {
                    if let Some(op) = operations.get_mut(&key) {
                        op.state = state;
                    } else if let Some(op) = deploys.get_mut(&key) {
                        op.state = state;
                    } else {
                        return Err(failure("outcome without intent"));
                    }
                }
                Record::Review { key, evidence } => {
                    if let Some(op) = operations.get_mut(&key) {
                        op.state = "operator_review".into();
                        op.evidence = Some(evidence);
                    } else if let Some(op) = deploys.get_mut(&key) {
                        op.state = "operator_review".into();
                        op.evidence = Some(evidence);
                    } else {
                        return Err(failure("review without intent"));
                    }
                }
                _ => {}
            }
        }
        let open = |s: &str| !matches!(s, "completed" | "refused");
        Ok((
            operations
                .into_values()
                .filter(|o| open(&o.state))
                .collect(),
            deploys.into_values().filter(|o| open(&o.state)).collect(),
        ))
    }
    pub fn recover(&self, operator: &str) -> Result<Recovery, GateError> {
        use membrane_core::{event::MembranePayload, rollup::cp_hash_hex};
        let mut recovered = Recovery::default();
        for record in self.records()? {
            match record {
                Record::PublicationAborted { token } => {
                    recovered.pending.remove(&token);
                }
                Record::Publishing { token } => {
                    recovered.pending.insert(token, ());
                }
                Record::Checkpoint {
                    token,
                    caller,
                    event,
                    bus_event_id,
                } => {
                    membrane_core::nostr_bus::verify_membrane_event_signature(&event, operator)
                        .map_err(GateError::Bus)?;
                    if event.prev_cp_hash != recovered.chain.last_cp_hash {
                        return Err(failure("checkpoint chain discontinuity"));
                    }
                    if let MembranePayload::Router(p) = &event.payload {
                        let scope = p
                            .scope_id
                            .as_deref()
                            .ok_or_else(|| failure("checkpoint missing scope"))?;
                        if p.parent_cp_hash != event.prev_cp_hash {
                            return Err(failure("router parent mismatch"));
                        }
                        if let Some(owner) = recovered.callers.get(scope) {
                            if !caller.is_empty() && owner != &caller {
                                return Err(failure("scope reused by another caller"));
                            }
                        }
                        if !caller.is_empty() {
                            recovered.callers.insert(scope.into(), caller);
                        }
                        recovered.chain.begin_scope(scope);
                        if Some(p.session_nonce) != recovered.chain.session_nonce.checked_add(1) {
                            return Err(failure("scope nonce rollback"));
                        }
                        recovered.chain.session_nonce = p.session_nonce;
                    }
                    let hash = cp_hash_hex(&event).map_err(GateError::Bus)?;
                    if event.event_type == membrane_core::event::EventType::CpRouter {
                        recovered
                            .chain
                            .record_cp(hash, bus_event_id, event.timestamp);
                    } else {
                        recovered.chain.last_cp_hash = hash;
                        recovered.chain.last_event_id = bus_event_id;
                    }
                    recovered.pending.remove(&token);
                }
                Record::Sever { scope, reason, at } => {
                    recovered.chain.mark_degraded(&scope, &reason, at)
                }
                _ => {}
            }
        }
        Ok(recovered)
    }
    /// Extend the durable chain from authenticated relay events, never replace it with a window.
    pub fn import_relay(
        &self,
        events: &[membrane_core::nostr_bus::MembraneBusEvent],
        operator: &str,
    ) -> Result<SessionChainState, GateError> {
        use membrane_core::{
            event::EventType,
            rollup::{cp_hash_hex, is_cp_event},
        };
        let mut recovered = self.recover(operator)?;
        if !recovered.pending.is_empty() {
            return Err(failure(
                "publication interrupted; review required before startup",
            ));
        }
        let mut known = std::collections::BTreeSet::new();
        for record in self.records()? {
            if let Record::Checkpoint { event, .. } = record {
                known.insert(cp_hash_hex(&event).map_err(GateError::Bus)?);
            }
        }
        for bus in events.iter().filter(|b| b.event.subject_pubkey == operator) {
            let event = &bus.event;
            membrane_core::nostr_bus::verify_membrane_event_signature(event, operator)
                .map_err(GateError::Bus)?;
            if is_cp_event(event.event_type) {
                let hash = cp_hash_hex(event).map_err(GateError::Bus)?;
                if known.contains(&hash) {
                    continue;
                }
                if event.prev_cp_hash != recovered.chain.last_cp_hash {
                    return Err(failure(
                        "relay history truncated or chain fork; operator review required",
                    ));
                }
                self.append(Record::Checkpoint {
                    token: String::new(),
                    caller: String::new(),
                    event: event.clone(),
                    bus_event_id: Some(bus.id.to_hex()),
                })?;
                known.insert(hash);
                recovered = self.recover(operator)?;
            } else if event.event_type == EventType::AlertDegraded {
                let (reason, scope) = membrane_core::session::alert_degraded_fields(&event.payload);
                if let (Some(reason), Some(scope)) = (reason, scope) {
                    if recovered.chain.degraded_scopes.get(&scope)
                        != Some(&(reason.clone(), event.timestamp))
                    {
                        self.append(Record::Sever {
                            scope,
                            reason,
                            at: event.timestamp,
                        })?;
                        recovered = self.recover(operator)?;
                    }
                }
            }
        }
        Ok(recovered.chain)
    }
    pub fn assert_ready(&self, operator: &str, caller: &str, scope: &str) -> Result<(), GateError> {
        let recovered = self.recover(operator)?;
        if !recovered.pending.is_empty() {
            return Err(failure(
                "unresolved checkpoint publication; operator review required",
            ));
        }
        if recovered.chain.scopes.contains_key(scope) && !recovered.callers.contains_key(scope) {
            return Err(failure(
                "imported scope has no verified caller binding; issue a new scope",
            ));
        }
        if recovered
            .callers
            .get(scope)
            .is_some_and(|owner| owner != caller)
        {
            return Err(failure("scope belongs to a different caller"));
        }
        Ok(())
    }
    pub fn begin_publication(&self) -> Result<String, GateError> {
        let token = nostr::Keys::generate().public_key().to_hex();
        self.append(Record::Publishing {
            token: token.clone(),
        })?;
        Ok(token)
    }
    pub fn legacy_reservations(&self) -> Result<Vec<String>, GateError> {
        self.acquire()?;
        let mut found = vec![];
        for entry in fs::read_dir(&self.path).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name != "journal.jsonl" && name.ends_with(".jsonl") {
                found.push(name);
            }
        }
        found.sort();
        Ok(found)
    }
}
fn digest<T: Serialize>(v: &T) -> Result<String, GateError> {
    Ok(hex::encode(Sha256::digest(
        serde_json::to_vec(v).map_err(|e| failure(e.to_string()))?,
    )))
}
fn io_error(e: std::io::Error) -> GateError {
    failure(e.to_string())
}
fn failure(e: impl std::fmt::Display) -> GateError {
    GateError::Connector(format!("journal failed closed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use membrane_core::{
        event::{EventType, MembranePayload, RouterSessionPayload},
        rollup::GENESIS_CP_HASH,
        BusPublisher, BusPublisherConfig,
    };
    fn directory() -> PathBuf {
        std::env::temp_dir().join(format!(
            "membrane-journal-{}",
            nostr::Keys::generate().public_key().to_hex()
        ))
    }
    fn request() -> ToolInvokeRequest {
        serde_json::from_value(serde_json::json!({"tool":"github.comment","model":"demo","owner":"acme","repo":"pilot","issue_number":1,"body":"first","operation_id":"stable-id"})).unwrap()
    }
    async fn checkpoint(
        j: &OperationJournal,
        keys: &nostr::Keys,
        caller: &str,
        scope: &str,
        at: i64,
    ) -> membrane_core::nostr_bus::MembraneBusEvent {
        let mut chain = j.recover(&keys.public_key().to_hex()).unwrap().chain;
        chain.begin_scope(scope);
        let nonce = chain.next_session_nonce();
        let mut event = MembraneEvent::new(
            EventType::CpRouter,
            "",
            chain.last_cp_hash.clone(),
            at,
            MembranePayload::Router(RouterSessionPayload {
                model_id: "demo".into(),
                context_merkle_root: "bb".repeat(32),
                session_nonce: nonce,
                parent_cp_hash: chain.last_cp_hash,
                iac_hash: "dd".repeat(32),
                scope_id: Some(scope.into()),
                tool_id: None,
                policy_digest: None,
                policy_revision: None,
            }),
        );
        let publisher = BusPublisher::new(BusPublisherConfig {
            relay_url: "memory://journal-test".into(),
            keys: keys.clone(),
        });
        let envelope = publisher
            .publish_with_receipt(&mut event, None)
            .await
            .unwrap();
        let token = j.begin_publication().unwrap();
        j.append(Record::Checkpoint {
            token,
            caller: caller.into(),
            event: event.clone(),
            bus_event_id: Some(envelope.id.to_hex()),
        })
        .unwrap();
        membrane_core::nostr_bus::MembraneBusEvent {
            id: envelope.id,
            event,
        }
    }
    #[test]
    fn reservation_survives_restart_and_rejects_changed_body() {
        let path = directory();
        let j = OperationJournal::new(path.clone());
        let mut req = request();
        let key = j.reserve_in_scope("caller", "scope", &req).unwrap();
        j.finish(&key, false).unwrap();
        drop(j);
        let j = OperationJournal::new(path.clone());
        assert!(j.reserve("caller", &req).is_err());
        req.body = Some("different".into());
        assert!(j.reserve("caller", &req).is_err());
        assert!(j.reserve("other-caller", &req).is_ok());
        assert_eq!(j.unresolved().unwrap().len(), 2);
        drop(j);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn refused_before_dispatch_closes_the_reservation() {
        let dir = std::env::temp_dir().join(format!("membrane-ops-refused-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let j = OperationJournal::new(dir.clone());
        let req = crate::github::ToolInvokeRequest {
            operation_id: Some("op-refused".into()),
            tool: crate::github::TOOL_GITHUB_COMMENT.into(),
            model: "m".into(),
            owner: "a".into(),
            repo: "b".into(),
            issue_number: Some(1),
            pull_number: None,
            body: Some("x".into()),
            commit_title: None,
        };
        let path = j.reserve_in_scope("caller", "scope", &req).unwrap();
        assert_eq!(j.unresolved().unwrap().len(), 1);
        j.finish_refused(&path).unwrap();
        // Closed: no lingering review item, and the refusal is on record.
        assert!(j.unresolved().unwrap().is_empty());
        let records = j.records().unwrap();
        assert!(records.iter().any(|r| matches!(
            r,
            Record::Outcome { state, .. } if state == "refused"
        )));
        // Refusing twice fails closed.
        assert!(j.finish_refused(&path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
    fn deploy_request(op: &str) -> DeployRequest {
        DeployRequest {
            schema_version: crate::deploy::DEPLOY_SCHEMA_VERSION,
            tool: crate::deploy::TOOL_DEPLOY_APPLY.into(),
            operation_id: op.into(),
            model: "client-1".into(),
            artifact_sha256: "c".repeat(64),
            targets: vec!["target-a".into()],
            expected_prior_state_sha256: "a".repeat(64),
            test_report_sha256: "b".repeat(64),
        }
    }

    #[test]
    fn deploy_reservation_blocks_duplicates_across_restart_and_tools() {
        let path = directory();
        let j = OperationJournal::new(path.clone());
        let req = deploy_request("deploy-op-1");
        let key = j.reserve_deploy_in_scope("caller", "scope", &req).unwrap();
        // Same caller and operation ID: refused, including after a changed body.
        assert!(j.reserve_deploy_in_scope("caller", "scope", &req).is_err());
        let mut changed = req.clone();
        changed.targets = vec!["target-b".into()];
        assert!(j
            .reserve_deploy_in_scope("caller", "scope", &changed)
            .is_err());
        // The same operation ID cannot be reused through the GitHub path either.
        let mut gh = request();
        gh.operation_id = Some("deploy-op-1".into());
        assert!(j.reserve_in_scope("caller", "scope", &gh).is_err());
        // Another caller has its own key space.
        assert!(j
            .reserve_deploy_in_scope("other-caller", "scope", &req)
            .is_ok());
        // An uncertain outcome stays unresolved and reserved across a restart.
        j.finish(&key, false).unwrap();
        drop(j);
        let j = OperationJournal::new(path.clone());
        assert!(j.reserve_deploy_in_scope("caller", "scope", &req).is_err());
        let open = j.unresolved_deploys().unwrap();
        assert_eq!(open.len(), 2);
        assert!(open.iter().any(|o| o.state == "uncertain"));
        // GitHub reconciliation never sees deploy operations.
        assert!(j.unresolved().unwrap().is_empty());
        drop(j);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn deploy_refused_before_dispatch_closes_and_review_is_recorded() {
        let path = directory();
        let j = OperationJournal::new(path.clone());
        let a = j
            .reserve_deploy_in_scope("caller", "scope", &deploy_request("op-a"))
            .unwrap();
        j.finish_refused(&a).unwrap();
        assert!(j.unresolved_deploys().unwrap().is_empty());
        assert!(j.finish_refused(&a).is_err());
        let b = j
            .reserve_deploy_in_scope("caller", "scope", &deploy_request("op-b"))
            .unwrap();
        j.append(Record::Review {
            key: b.file_name().unwrap().to_str().unwrap().into(),
            evidence: serde_json::json!({"observation":"unverifiable"}),
        })
        .unwrap();
        let open = j.unresolved_deploys().unwrap();
        assert_eq!(open[0].state, "operator_review");
        assert!(j
            .reserve_deploy_in_scope("caller", "scope", &deploy_request(""))
            .is_err());
        drop(j);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn second_instance_is_excluded_and_lock_releases_on_drop() {
        let path = directory();
        let first = OperationJournal::new(path.clone());
        first.records().unwrap();
        let second = OperationJournal::new(path.clone());
        assert!(second.records().is_err());
        drop(first);
        assert!(second.records().is_ok());
        drop(second);
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn crash_mid_write_and_checksum_corruption_block_recovery() {
        for torn in [true, false] {
            let path = directory();
            let j = OperationJournal::new(path.clone());
            j.reserve("caller", &request()).unwrap();
            drop(j);
            let file = path.join("journal.jsonl");
            let mut bytes = fs::read(&file).unwrap();
            if torn {
                bytes.truncate(bytes.len() - 6);
            } else {
                let i = bytes.windows(6).position(|w| w == b"stable").unwrap();
                bytes[i] = b'x';
            }
            fs::write(file, bytes).unwrap();
            let j = OperationJournal::new(path.clone());
            assert!(j.records().is_err());
            assert!(j.reserve("other", &request()).is_err());
            drop(j);
            fs::remove_dir_all(path).unwrap();
        }
    }
    #[test]
    fn crash_after_intent_and_review_never_unlock_id() {
        let path = directory();
        let j = OperationJournal::new(path.clone());
        j.reserve_in_scope("caller", "scope", &request()).unwrap();
        drop(j);
        let j = OperationJournal::new(path.clone());
        let op = j.unresolved().unwrap().pop().unwrap();
        assert_eq!(op.state, "reserved");
        j.append(Record::Review {
            key: op.key,
            evidence: serde_json::json!({"observation":"absent","attribution_verified":false}),
        })
        .unwrap();
        assert_eq!(j.unresolved().unwrap()[0].state, "operator_review");
        assert!(j.reserve("caller", &request()).is_err());
        drop(j);
        fs::remove_dir_all(path).unwrap();
    }
    #[tokio::test]
    async fn interleaved_callers_scopes_survive_empty_relay_window() {
        let path = directory();
        let keys = nostr::Keys::generate();
        let operator = keys.public_key().to_hex();
        let j = OperationJournal::new(path.clone());
        checkpoint(&j, &keys, "alice", "a", 1).await;
        checkpoint(&j, &keys, "bob", "b", 2).await;
        checkpoint(&j, &keys, "alice", "a", 3).await;
        j.append(Record::Sever {
            scope: "b".into(),
            reason: "subject_sever".into(),
            at: 4,
        })
        .unwrap();
        drop(j);
        let j = OperationJournal::new(path.clone());
        let chain = j.import_relay(&[], &operator).unwrap();
        assert_eq!(chain.scopes["a"].0, 2);
        assert_eq!(chain.scopes["b"].0, 1);
        assert!(chain.is_scope_degraded("b"));
        assert!(j.assert_ready(&operator, "bob", "a").is_err());
        assert!(j.assert_ready(&operator, "alice", "a").is_ok());
        drop(j);
        fs::remove_dir_all(path).unwrap();
    }
    #[tokio::test]
    async fn truncated_relay_missing_prefix_and_fork_are_rejected() {
        let path = directory();
        let keys = nostr::Keys::generate();
        let j = OperationJournal::new(path.clone());
        let first = checkpoint(&j, &keys, "alice", "a", 1).await;
        let second = checkpoint(&j, &keys, "alice", "a", 2).await;
        let fresh_path = directory();
        let fresh = OperationJournal::new(fresh_path.clone());
        assert!(fresh
            .import_relay(std::slice::from_ref(&second), &keys.public_key().to_hex())
            .is_err());
        assert!(j
            .import_relay(std::slice::from_ref(&second), &keys.public_key().to_hex())
            .is_ok());
        // Full prefix authenticates, but historical caller binding cannot be guessed.
        assert!(fresh
            .import_relay(&[first, second], &keys.public_key().to_hex())
            .is_ok());
        assert!(fresh
            .assert_ready(&keys.public_key().to_hex(), "alice", "a")
            .is_err());
        assert_ne!(
            j.recover(&keys.public_key().to_hex())
                .unwrap()
                .chain
                .last_cp_hash,
            GENESIS_CP_HASH
        );
        drop(j);
        drop(fresh);
        fs::remove_dir_all(path).unwrap();
        fs::remove_dir_all(fresh_path).unwrap();
    }
    #[test]
    fn publication_interruption_blocks_new_dispatch_and_startup() {
        let path = directory();
        let keys = nostr::Keys::generate();
        let j = OperationJournal::new(path.clone());
        j.begin_publication().unwrap();
        drop(j);
        let j = OperationJournal::new(path.clone());
        assert!(j
            .assert_ready(&keys.public_key().to_hex(), "alice", "a")
            .is_err());
        assert!(j.import_relay(&[], &keys.public_key().to_hex()).is_err());
        drop(j);
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn old_enforcement_reservations_stay_blocked() {
        let path = directory();
        let j = OperationJournal::new(path.clone());
        j.records().unwrap();
        let key = digest(&("caller", "stable-id")).unwrap();
        fs::write(path.join(format!("{key}.jsonl")), b"legacy").unwrap();
        assert!(j.reserve("caller", &request()).is_err());
        assert_eq!(j.legacy_reservations().unwrap().len(), 1);
        drop(j);
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn concurrent_reservations_only_one_wins() {
        let path = directory();
        let j = std::sync::Arc::new(OperationJournal::new(path.clone()));
        let mut tasks = vec![];
        for _ in 0..8 {
            let j = j.clone();
            tasks.push(std::thread::spawn(move || {
                j.reserve("caller", &request()).is_ok()
            }));
        }
        let count = tasks
            .into_iter()
            .filter_map(|t| t.join().ok())
            .filter(|ok| *ok)
            .count();
        assert_eq!(count, 1);
        drop(j);
        fs::remove_dir_all(path).unwrap();
    }
}
