//! Typed deploy connector (slice 1 of the deploy-boundary proof).
//!
//! `deploy.apply` and `deploy.remove` carry typed fields: an immutable artifact
//! digest, exact target IDs, the expected prior state and the test-report
//! digest. They are not GitHub owner/repo/body fields, and the executor never
//! receives shell commands, paths or addresses from the caller.
//!
//! This slice covers request validation, the content-addressed artifact store
//! with byte re-verification at dispatch, the trusted target inventory and the
//! connector preflight/execute path. Slice 2b-2 wires the connector into the
//! production `/v1/deploy/invoke` route with the approval hold, durable
//! reservation and pre-dispatch recheck. Slice 3 ships the trusted executor:
//! [`HttpPolicyExecutor`] reaches `membrane-proof-target` fixtures over the
//! fixed HTTP protocol, validates the artifact again before any write,
//! compares the reviewed prior state, installs atomically and reads the
//! installed bytes back. Failures are classified: pre-write refusals close as
//! refused, anything after the write is sent is uncertain.

use std::{
    collections::BTreeSet,
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const TOOL_DEPLOY_APPLY: &str = "deploy.apply";
pub const TOOL_DEPLOY_REMOVE: &str = "deploy.remove";
pub const DEPLOY_SCHEMA_VERSION: u32 = 1;
/// One target per approval avoids partial fleet success in the first proof.
pub const MAX_TARGETS_PER_APPROVAL: usize = 1;
const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;

pub fn is_deploy_tool(tool_id: &str) -> bool {
    matches!(tool_id, TOOL_DEPLOY_APPLY | TOOL_DEPLOY_REMOVE)
}

#[derive(Debug, Error)]
pub enum DeployError {
    #[error("unsupported deploy tool: {0}")]
    UnsupportedTool(String),
    #[error("unsupported deploy schema version: {0}")]
    SchemaVersion(u32),
    #[error("invalid deploy request: {0}")]
    InvalidArgs(String),
    #[error("target not in trusted inventory: {0}")]
    TargetDenied(String),
    #[error("artifact not staged: {0}")]
    ArtifactMissing(String),
    #[error("artifact bytes do not match approved digest {0}")]
    ArtifactDigestMismatch(String),
    #[error("artifact store error: {0}")]
    Store(String),
    #[error("executor error: {0}")]
    Executor(String),
    #[error("target prior state does not match the reviewed digest: {0}")]
    PriorStateMismatch(String),
    #[error("target unavailable before any write: {0}")]
    TargetUnavailable(String),
    #[error("target rejected the policy artifact: {0}")]
    PolicyRejected(String),
    #[error("target state unknown after the write was sent: {0}")]
    PostWrite(String),
}

impl DeployError {
    /// True when the error proves the executor never changed target state, so
    /// the failure is a refusal, not an uncertainty. A timed-out or lost write
    /// is never pre-write: the target may have applied it.
    pub fn pre_write(&self) -> bool {
        match self {
            Self::UnsupportedTool(_)
            | Self::SchemaVersion(_)
            | Self::InvalidArgs(_)
            | Self::TargetDenied(_)
            | Self::ArtifactMissing(_)
            | Self::ArtifactDigestMismatch(_)
            | Self::Store(_)
            | Self::PriorStateMismatch(_)
            | Self::TargetUnavailable(_)
            | Self::PolicyRejected(_) => true,
            Self::Executor(_) | Self::PostWrite(_) => false,
        }
    }
}

/// The exact call an operator approves. Every field is part of the approval
/// hash (`approval::call_hash`); unknown fields are rejected, so a caller cannot
/// smuggle a URL, credential or command into the request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeployRequest {
    pub schema_version: u32,
    pub tool: String,
    pub operation_id: String,
    pub model: String,
    /// SHA-256 (lowercase hex) of the exact bytes the executor consumes. For
    /// `deploy.remove`, the digest of the installed artifact.
    pub artifact_sha256: String,
    /// Exact, sorted, unique inventory IDs.
    pub targets: Vec<String>,
    /// SHA-256 of the target state the operator reviewed before approval.
    pub expected_prior_state_sha256: String,
    pub test_report_sha256: String,
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn valid_operation_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

/// A plain inventory ID: lowercase letters, digits, `-` and `_`, starting with a
/// letter or digit. Aliases, selectors, wildcards and URLs never match.
pub fn is_valid_target_id(s: &str) -> bool {
    let mut bytes = s.bytes();
    match bytes.next() {
        Some(b) if b.is_ascii_lowercase() || b.is_ascii_digit() => {}
        _ => return false,
    }
    s.len() <= 64
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_".contains(&b))
}

impl DeployRequest {
    /// Shape checks only; the inventory and artifact checks live on the connector.
    pub fn validate(&self) -> Result<(), DeployError> {
        if self.schema_version != DEPLOY_SCHEMA_VERSION {
            return Err(DeployError::SchemaVersion(self.schema_version));
        }
        if !is_deploy_tool(&self.tool) {
            return Err(DeployError::UnsupportedTool(self.tool.clone()));
        }
        if !valid_operation_id(&self.operation_id) {
            return Err(DeployError::InvalidArgs("operation_id".into()));
        }
        if self.model.trim().is_empty() {
            return Err(DeployError::InvalidArgs("model".into()));
        }
        for (name, value) in [
            ("artifact_sha256", &self.artifact_sha256),
            (
                "expected_prior_state_sha256",
                &self.expected_prior_state_sha256,
            ),
            ("test_report_sha256", &self.test_report_sha256),
        ] {
            if !is_sha256_hex(value) {
                return Err(DeployError::InvalidArgs(format!(
                    "{name} must be 64 lowercase hex characters"
                )));
            }
        }
        if self.targets.is_empty() {
            return Err(DeployError::InvalidArgs("targets required".into()));
        }
        if self.targets.len() > MAX_TARGETS_PER_APPROVAL {
            return Err(DeployError::InvalidArgs(format!(
                "at most {MAX_TARGETS_PER_APPROVAL} target per approval"
            )));
        }
        // Sorted and unique, with no aliases, selectors, URLs or wildcards: only
        // plain inventory IDs pass `valid_target_id`.
        if !self.targets.windows(2).all(|w| w[0] < w[1]) {
            return Err(DeployError::InvalidArgs(
                "targets must be sorted and unique".into(),
            ));
        }
        if let Some(bad) = self.targets.iter().find(|t| !is_valid_target_id(t)) {
            return Err(DeployError::InvalidArgs(format!(
                "target is not a plain inventory ID: {bad}"
            )));
        }
        Ok(())
    }
}

/// Targets the operator configured. Callers name IDs; they never supply
/// addresses or credentials.
#[derive(Debug, Clone, Default)]
pub struct TargetInventory {
    ids: BTreeSet<String>,
}

impl TargetInventory {
    pub fn new<I: IntoIterator<Item = String>>(ids: I) -> Result<Self, DeployError> {
        let ids: BTreeSet<String> = ids.into_iter().collect();
        if let Some(bad) = ids.iter().find(|t| !is_valid_target_id(t)) {
            return Err(DeployError::InvalidArgs(format!(
                "inventory ID is not a plain ID: {bad}"
            )));
        }
        Ok(Self { ids })
    }

    pub fn contains(&self, id: &str) -> bool {
        self.ids.contains(id)
    }
}

/// Content-addressed store for immutable artifact bytes. The file name is the
/// SHA-256 of the contents; reads hash the bytes again, so replacing bytes
/// behind an approved digest is refused at dispatch.
#[derive(Debug, Clone)]
pub struct ArtifactStore {
    root: PathBuf,
}

impl ArtifactStore {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, DeployError> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(|e| DeployError::Store(e.to_string()))?;
        Ok(Self { root })
    }

    fn path_for(&self, digest: &str) -> Result<PathBuf, DeployError> {
        // Only a validated digest ever reaches the path join.
        if !is_sha256_hex(digest) {
            return Err(DeployError::InvalidArgs("artifact digest".into()));
        }
        Ok(self.root.join(digest))
    }

    /// Trusted staging step: store bytes under their own digest and return it.
    /// Existing content is never overwritten.
    pub fn stage(&self, bytes: &[u8]) -> Result<String, DeployError> {
        if bytes.len() as u64 > MAX_ARTIFACT_BYTES {
            return Err(DeployError::Store("artifact too large".into()));
        }
        let digest = hex::encode(Sha256::digest(bytes));
        let path = self.path_for(&digest)?;
        if path.exists() {
            return Ok(digest);
        }
        let tmp = self.root.join(format!(".{digest}.tmp"));
        {
            let mut f = fs::File::create(&tmp).map_err(|e| DeployError::Store(e.to_string()))?;
            f.write_all(bytes)
                .and_then(|_| f.sync_all())
                .map_err(|e| DeployError::Store(e.to_string()))?;
        }
        fs::rename(&tmp, &path).map_err(|e| DeployError::Store(e.to_string()))?;
        Ok(digest)
    }

    pub fn contains(&self, digest: &str) -> Result<bool, DeployError> {
        Ok(self.path_for(digest)?.is_file())
    }

    /// Read the bytes and prove they still hash to `digest`.
    pub fn read_verified(&self, digest: &str) -> Result<Vec<u8>, DeployError> {
        let path = self.path_for(digest)?;
        let meta = fs::metadata(&path).map_err(|_| DeployError::ArtifactMissing(digest.into()))?;
        if meta.len() > MAX_ARTIFACT_BYTES {
            return Err(DeployError::Store("artifact too large".into()));
        }
        let bytes = fs::read(&path).map_err(|_| DeployError::ArtifactMissing(digest.into()))?;
        if hex::encode(Sha256::digest(&bytes)) != digest {
            return Err(DeployError::ArtifactDigestMismatch(digest.into()));
        }
        Ok(bytes)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// What the trusted executor observed after the write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeployEffect {
    pub observed_state_sha256: String,
}

/// The only code that may touch a target. It receives validated, typed input
/// and byte-verified artifact content, never caller-provided commands, paths or
/// addresses.
#[async_trait::async_trait]
pub trait DeployExecutor: Send + Sync {
    async fn apply(
        &self,
        req: &DeployRequest,
        artifact: &[u8],
    ) -> Result<DeployEffect, DeployError>;
    async fn remove(&self, req: &DeployRequest) -> Result<DeployEffect, DeployError>;
}

/// Digest-only context for the receipt, with no artifact bytes or credentials.
#[derive(Debug, Clone, Serialize)]
pub struct DeployReceiptContext {
    pub tool: String,
    pub model: String,
    pub operation_id: String,
    pub artifact_sha256: String,
    pub targets: Vec<String>,
    pub expected_prior_state_sha256: String,
    pub test_report_sha256: String,
    pub effect: DeployEffect,
}

pub struct DeployConnector {
    inventory: TargetInventory,
    store: ArtifactStore,
    executor: Arc<dyn DeployExecutor>,
}

impl DeployConnector {
    pub fn new(
        inventory: TargetInventory,
        store: ArtifactStore,
        executor: Arc<dyn DeployExecutor>,
    ) -> Self {
        Self {
            inventory,
            store,
            executor,
        }
    }

    /// Everything that must hold before the executor is reachable: request
    /// shape, trusted inventory, and (for apply) the staged artifact.
    pub fn preflight(&self, req: &DeployRequest) -> Result<(), DeployError> {
        req.validate()?;
        if let Some(t) = req.targets.iter().find(|t| !self.inventory.contains(t)) {
            return Err(DeployError::TargetDenied(t.clone()));
        }
        if req.tool == TOOL_DEPLOY_APPLY && !self.store.contains(&req.artifact_sha256)? {
            return Err(DeployError::ArtifactMissing(req.artifact_sha256.clone()));
        }
        Ok(())
    }

    /// Pre-dispatch re-verification: everything `preflight` checks, plus
    /// hashing the staged artifact bytes again. The route runs this after the
    /// intent receipt is published, immediately before dispatch, so bytes
    /// swapped behind an approved digest refuse the call instead of deploying.
    pub fn reverify(&self, req: &DeployRequest) -> Result<(), DeployError> {
        self.preflight(req)?;
        if req.tool == TOOL_DEPLOY_APPLY {
            self.store.read_verified(&req.artifact_sha256)?;
        }
        Ok(())
    }

    /// Caller must already have passed gate authorization and an exact approval.
    /// Approval waives only the tool check: this still re-hashes the artifact.
    pub async fn execute(&self, req: &DeployRequest) -> Result<DeployReceiptContext, DeployError> {
        self.preflight(req)?;
        let effect = match req.tool.as_str() {
            TOOL_DEPLOY_APPLY => {
                let bytes = self.store.read_verified(&req.artifact_sha256)?;
                self.executor.apply(req, &bytes).await?
            }
            TOOL_DEPLOY_REMOVE => self.executor.remove(req).await?,
            other => return Err(DeployError::UnsupportedTool(other.into())),
        };
        Ok(DeployReceiptContext {
            tool: req.tool.clone(),
            model: req.model.clone(),
            operation_id: req.operation_id.clone(),
            artifact_sha256: req.artifact_sha256.clone(),
            targets: req.targets.clone(),
            expected_prior_state_sha256: req.expected_prior_state_sha256.clone(),
            test_report_sha256: req.test_report_sha256.clone(),
            effect,
        })
    }
}

/// The strict policy artifact the fixture consumes. The executor validates it
/// again before any write, so a byte-verified artifact that is not a valid
/// policy still never reaches the target.
#[derive(Debug, Clone, Copy, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyArtifact {
    pub schema_version: u32,
    pub max_count: u32,
}

pub const MAX_POLICY_BYTES: usize = 4096;
pub const MAX_COUNT_LIMIT: u32 = 100_000;
/// Pinned fixture image identifier, part of the target state digest.
pub const PROOF_TARGET_IMAGE: &str = "membrane-proof-target/v1";

pub fn parse_policy_artifact(bytes: &[u8]) -> Result<PolicyArtifact, DeployError> {
    if bytes.len() > MAX_POLICY_BYTES {
        return Err(DeployError::InvalidArgs("policy artifact too large".into()));
    }
    let policy: PolicyArtifact = serde_json::from_slice(bytes)
        .map_err(|e| DeployError::InvalidArgs(format!("invalid policy artifact: {e}")))?;
    if policy.schema_version != DEPLOY_SCHEMA_VERSION {
        return Err(DeployError::SchemaVersion(policy.schema_version));
    }
    if policy.max_count > MAX_COUNT_LIMIT {
        return Err(DeployError::InvalidArgs(format!(
            "max_count above limit {MAX_COUNT_LIMIT}"
        )));
    }
    Ok(policy)
}

/// Target state digest scheme, recomputed by the executor from read-back
/// bytes, never taken on the target's word.
pub fn target_state_digest(policy_sha256: &str, image: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"membrane-target-state/v1\0");
    h.update(policy_sha256.as_bytes());
    h.update(b"\0");
    h.update(image.as_bytes());
    hex::encode(h.finalize())
}

/// Trusted target address map from operator configuration. Callers name
/// inventory IDs; addresses never come from the request.
#[derive(Debug, Clone)]
pub struct TargetEndpoints {
    map: std::collections::BTreeMap<String, String>,
}

impl TargetEndpoints {
    /// Parse `id=url,id=url` from trusted config. Every ID is a plain
    /// inventory ID; every URL is http(s) with no userinfo, query or fragment.
    pub fn parse(spec: &str) -> Result<(TargetInventory, Self), DeployError> {
        let mut ids = Vec::new();
        let mut map = std::collections::BTreeMap::new();
        for pair in spec.split(',') {
            let (id, url) = pair
                .split_once('=')
                .ok_or_else(|| DeployError::InvalidArgs(format!("bad endpoint entry: {pair}")))?;
            let id = id.trim();
            let url = url.trim();
            if !is_valid_target_id(id) {
                return Err(DeployError::InvalidArgs(format!("bad target ID: {id}")));
            }
            let parsed = reqwest::Url::parse(url)
                .map_err(|_| DeployError::InvalidArgs(format!("bad target URL: {url}")))?;
            if !matches!(parsed.scheme(), "http" | "https")
                || !parsed.username().is_empty()
                || parsed.query().is_some()
                || parsed.fragment().is_some()
            {
                return Err(DeployError::InvalidArgs(format!(
                    "target URL not allowed: {url}"
                )));
            }
            if map
                .insert(id.to_string(), url.trim_end_matches('/').to_string())
                .is_some()
            {
                return Err(DeployError::InvalidArgs(format!(
                    "duplicate target ID: {id}"
                )));
            }
            ids.push(id.to_string());
        }
        if ids.is_empty() {
            return Err(DeployError::InvalidArgs(
                "no deploy targets configured".into(),
            ));
        }
        Ok((TargetInventory::new(ids)?, Self { map }))
    }

    pub fn base_url(&self, id: &str) -> Option<&str> {
        self.map.get(id).map(String::as_str)
    }
}

#[derive(Debug, serde::Deserialize)]
struct TargetState {
    policy_sha256: String,
    image: String,
}

/// The real executor for the proof fixture: it reaches targets over the fixed
/// HTTP protocol, validates the artifact itself, compares the reviewed prior
/// state before any write, then installs and reads back. It holds no signing
/// material and no credentials, and it never takes commands, paths or
/// addresses from the caller.
pub struct HttpPolicyExecutor {
    endpoints: TargetEndpoints,
    client: reqwest::Client,
}

impl HttpPolicyExecutor {
    pub fn new(endpoints: TargetEndpoints) -> Result<Self, DeployError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| DeployError::Executor(e.to_string()))?;
        Ok(Self { endpoints, client })
    }

    fn base(&self, req: &DeployRequest) -> Result<&str, DeployError> {
        let id = req
            .targets
            .first()
            .ok_or_else(|| DeployError::InvalidArgs("targets required".into()))?;
        self.endpoints
            .base_url(id)
            .ok_or_else(|| DeployError::TargetDenied(id.clone()))
    }

    async fn get_state(&self, base: &str) -> Result<TargetState, DeployError> {
        let response = self
            .client
            .get(format!("{base}/state"))
            .send()
            .await
            .map_err(|e| DeployError::TargetUnavailable(e.to_string()))?;
        if !response.status().is_success() {
            return Err(DeployError::TargetUnavailable(format!(
                "GET /state -> {}",
                response.status()
            )));
        }
        response
            .json::<TargetState>()
            .await
            .map_err(|e| DeployError::TargetUnavailable(e.to_string()))
    }

    fn check_prior(&self, req: &DeployRequest, before: &TargetState) -> Result<(), DeployError> {
        let reviewed = target_state_digest(&before.policy_sha256, &before.image);
        if reviewed != req.expected_prior_state_sha256 {
            return Err(DeployError::PriorStateMismatch(format!(
                "target is at {reviewed}, request expects {}",
                req.expected_prior_state_sha256
            )));
        }
        Ok(())
    }

    /// Read the installed policy bytes back and prove they are exactly the
    /// artifact, then return the locally recomputed state digest.
    async fn readback(&self, base: &str, expect: Option<&[u8]>) -> Result<String, DeployError> {
        let state = self
            .get_state(base)
            .await
            .map_err(|e| DeployError::PostWrite(e.to_string()))?;
        let response = self
            .client
            .get(format!("{base}/policy"))
            .send()
            .await
            .map_err(|e| DeployError::PostWrite(e.to_string()))?;
        let installed: Option<Vec<u8>> = match response.status() {
            reqwest::StatusCode::OK => Some(
                response
                    .bytes()
                    .await
                    .map_err(|e| DeployError::PostWrite(e.to_string()))?
                    .to_vec(),
            ),
            reqwest::StatusCode::NOT_FOUND => None,
            other => {
                return Err(DeployError::PostWrite(format!("GET /policy -> {other}")));
            }
        };
        let installed_sha = hex::encode(Sha256::digest(installed.as_deref().unwrap_or(&[])));
        let expect_sha = hex::encode(Sha256::digest(expect.unwrap_or(&[])));
        if installed_sha != expect_sha || installed_sha != state.policy_sha256 {
            return Err(DeployError::PostWrite(
                "read-back policy does not match the artifact".into(),
            ));
        }
        Ok(target_state_digest(&installed_sha, &state.image))
    }
}

#[async_trait::async_trait]
impl DeployExecutor for HttpPolicyExecutor {
    async fn apply(
        &self,
        req: &DeployRequest,
        artifact: &[u8],
    ) -> Result<DeployEffect, DeployError> {
        // Executor-side validation: byte-verified is not policy-valid.
        parse_policy_artifact(artifact)?;
        let base = self.base(req)?;
        let before = self.get_state(base).await?;
        self.check_prior(req, &before)?;
        // The write begins here. Anything that fails after the request is sent
        // is uncertain, never silently treated as refused.
        let response = self
            .client
            .put(format!("{base}/policy"))
            .body(artifact.to_vec())
            .send()
            .await
            .map_err(|e| DeployError::PostWrite(e.to_string()))?;
        match response.status() {
            reqwest::StatusCode::NO_CONTENT => {}
            reqwest::StatusCode::UNPROCESSABLE_ENTITY | reqwest::StatusCode::PAYLOAD_TOO_LARGE => {
                let reason = response.text().await.unwrap_or_default();
                return Err(DeployError::PolicyRejected(reason));
            }
            other => return Err(DeployError::PostWrite(format!("PUT /policy -> {other}"))),
        }
        let observed_state_sha256 = self.readback(base, Some(artifact)).await?;
        Ok(DeployEffect {
            observed_state_sha256,
        })
    }

    async fn remove(&self, req: &DeployRequest) -> Result<DeployEffect, DeployError> {
        let base = self.base(req)?;
        let before = self.get_state(base).await?;
        self.check_prior(req, &before)?;
        let response = self
            .client
            .delete(format!("{base}/policy"))
            .send()
            .await
            .map_err(|e| DeployError::PostWrite(e.to_string()))?;
        if response.status() != reqwest::StatusCode::NO_CONTENT {
            return Err(DeployError::PostWrite(format!(
                "DELETE /policy -> {}",
                response.status()
            )));
        }
        let observed_state_sha256 = self.readback(base, None).await?;
        Ok(DeployEffect {
            observed_state_sha256,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::call_hash;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Test stand-in only. It records calls so refusal tests can assert the
    /// executor was never reached; it writes nothing.
    #[derive(Default)]
    struct Recording {
        applies: AtomicUsize,
        removes: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl DeployExecutor for Recording {
        async fn apply(&self, _: &DeployRequest, _: &[u8]) -> Result<DeployEffect, DeployError> {
            self.applies.fetch_add(1, Ordering::SeqCst);
            Ok(DeployEffect {
                observed_state_sha256: "0".repeat(64),
            })
        }
        async fn remove(&self, _: &DeployRequest) -> Result<DeployEffect, DeployError> {
            self.removes.fetch_add(1, Ordering::SeqCst);
            Ok(DeployEffect {
                observed_state_sha256: "1".repeat(64),
            })
        }
    }

    struct Fixture {
        _dir: tempdir::Dir,
        connector: DeployConnector,
        exec: Arc<Recording>,
        store: ArtifactStore,
        digest: String,
    }

    /// Minimal temp dir so the crate needs no new dev-dependency.
    mod tempdir {
        use std::path::{Path, PathBuf};
        pub struct Dir(PathBuf);
        impl Dir {
            pub fn new(tag: &str) -> Self {
                let p = std::env::temp_dir().join(format!(
                    "membrane-deploy-{tag}-{}-{:?}",
                    std::process::id(),
                    std::thread::current().id()
                ));
                let _ = std::fs::remove_dir_all(&p);
                std::fs::create_dir_all(&p).unwrap();
                Self(p)
            }
            pub fn path(&self) -> &Path {
                &self.0
            }
        }
        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    fn fixture(tag: &str) -> Fixture {
        let dir = tempdir::Dir::new(tag);
        let store = ArtifactStore::open(dir.path().join("artifacts")).unwrap();
        let digest = store.stage(b"mitigation-v1").unwrap();
        let inventory =
            TargetInventory::new(["target-a".to_string(), "target-b".to_string()]).unwrap();
        let exec = Arc::new(Recording::default());
        let connector = DeployConnector::new(inventory, store.clone(), exec.clone());
        Fixture {
            _dir: dir,
            connector,
            exec,
            store,
            digest,
        }
    }

    fn request(digest: &str) -> DeployRequest {
        DeployRequest {
            schema_version: DEPLOY_SCHEMA_VERSION,
            tool: TOOL_DEPLOY_APPLY.into(),
            operation_id: "op-0001".into(),
            model: "client-1".into(),
            artifact_sha256: digest.into(),
            targets: vec!["target-a".into()],
            expected_prior_state_sha256: "a".repeat(64),
            test_report_sha256: "b".repeat(64),
        }
    }

    fn hash(r: &DeployRequest) -> String {
        call_hash("caller", "scope", "iac", "policy", r).unwrap()
    }

    fn calls(f: &Fixture) -> usize {
        f.exec.applies.load(Ordering::SeqCst) + f.exec.removes.load(Ordering::SeqCst)
    }

    #[tokio::test]
    async fn permitted_apply_reaches_executor_once() {
        let f = fixture("ok");
        let ctx = f.connector.execute(&request(&f.digest)).await.unwrap();
        assert_eq!(ctx.targets, vec!["target-a".to_string()]);
        assert_eq!(f.exec.applies.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn different_digest_is_refused_before_executor() {
        let f = fixture("digest");
        let other = hex::encode(Sha256::digest(b"other-bytes"));
        assert!(matches!(
            f.connector.execute(&request(&other)).await,
            Err(DeployError::ArtifactMissing(_))
        ));
        assert_eq!(calls(&f), 0);
    }

    #[tokio::test]
    async fn bytes_replaced_behind_approved_digest_are_refused() {
        let f = fixture("swap");
        fs::write(f.store.root().join(&f.digest), b"evil-bytes").unwrap();
        assert!(matches!(
            f.connector.execute(&request(&f.digest)).await,
            Err(DeployError::ArtifactDigestMismatch(_))
        ));
        assert_eq!(calls(&f), 0);
    }

    #[tokio::test]
    async fn expanded_or_malformed_targets_are_refused() {
        let f = fixture("targets");
        let cases: Vec<Vec<&str>> = vec![
            vec!["target-a", "target-b"],
            vec!["target-b", "target-a"],
            vec!["target-a", "target-a"],
            vec!["*"],
            vec!["target-a,target-b"],
            vec!["https://target-a.example"],
            vec!["env=prod"],
            vec!["Target-A"],
            vec!["../target-a"],
            vec![],
        ];
        for case in cases {
            let mut r = request(&f.digest);
            r.targets = case.iter().map(|s| s.to_string()).collect();
            assert!(f.connector.execute(&r).await.is_err(), "{case:?}");
        }
        let mut r = request(&f.digest);
        r.targets = vec!["target-z".into()];
        assert!(matches!(
            f.connector.execute(&r).await,
            Err(DeployError::TargetDenied(_))
        ));
        assert_eq!(calls(&f), 0);
    }

    #[test]
    fn substituted_target_changes_the_approval_hash() {
        let f = fixture("subst");
        let a = request(&f.digest);
        let mut b = a.clone();
        b.targets = vec!["target-b".into()];
        assert_ne!(hash(&a), hash(&b));
    }

    #[test]
    fn every_request_field_is_bound_by_the_approval_hash() {
        let base = request(&"c".repeat(64));
        let base_hash = hash(&base);
        let mut variants = Vec::new();
        let mut v = base.clone();
        v.operation_id = "op-0002".into();
        variants.push(v);
        let mut v = base.clone();
        v.model = "client-2".into();
        variants.push(v);
        let mut v = base.clone();
        v.artifact_sha256 = "d".repeat(64);
        variants.push(v);
        let mut v = base.clone();
        v.targets = vec!["target-b".into()];
        variants.push(v);
        let mut v = base.clone();
        v.expected_prior_state_sha256 = "e".repeat(64);
        variants.push(v);
        let mut v = base.clone();
        v.test_report_sha256 = "f".repeat(64);
        variants.push(v);
        let mut v = base.clone();
        v.tool = TOOL_DEPLOY_REMOVE.into();
        variants.push(v);
        for v in variants {
            assert_ne!(hash(&v), base_hash, "{v:?}");
        }
    }

    #[test]
    fn unknown_fields_such_as_credentials_or_urls_are_rejected() {
        let ok = serde_json::to_value(request(&"c".repeat(64))).unwrap();
        assert!(serde_json::from_value::<DeployRequest>(ok.clone()).is_ok());
        for extra in ["token", "url", "command", "path"] {
            let mut v = ok.clone();
            v[extra] = serde_json::json!("x");
            assert!(
                serde_json::from_value::<DeployRequest>(v).is_err(),
                "{extra}"
            );
        }
    }

    #[tokio::test]
    async fn malformed_digests_and_ids_are_refused() {
        let f = fixture("shape");
        for mutate in [
            |r: &mut DeployRequest| r.artifact_sha256 = "../etc/passwd".into(),
            |r: &mut DeployRequest| r.artifact_sha256 = "A".repeat(64),
            |r: &mut DeployRequest| r.expected_prior_state_sha256 = "short".into(),
            |r: &mut DeployRequest| r.test_report_sha256 = String::new(),
            |r: &mut DeployRequest| r.operation_id = "has space".into(),
            |r: &mut DeployRequest| r.operation_id = String::new(),
            |r: &mut DeployRequest| r.model = " ".into(),
            |r: &mut DeployRequest| r.schema_version = 2,
            |r: &mut DeployRequest| r.tool = "github.merge".into(),
        ] {
            let mut r = request(&f.digest);
            mutate(&mut r);
            assert!(f.connector.execute(&r).await.is_err());
        }
        assert_eq!(calls(&f), 0);
    }

    #[tokio::test]
    async fn remove_is_a_distinct_action_that_never_inherits_apply() {
        let f = fixture("remove");
        let mut r = request(&f.digest);
        r.tool = TOOL_DEPLOY_REMOVE.into();
        f.connector.execute(&r).await.unwrap();
        assert_eq!(f.exec.removes.load(Ordering::SeqCst), 1);
        assert_eq!(f.exec.applies.load(Ordering::SeqCst), 0);
        // The apply approval hash does not match the remove request.
        assert_ne!(hash(&r), hash(&request(&f.digest)));
    }

    #[test]
    fn reverify_hashes_bytes_without_touching_the_executor() {
        let f = fixture("reverify");
        f.connector.reverify(&request(&f.digest)).unwrap();
        assert_eq!(calls(&f), 0);
        fs::write(f.store.root().join(&f.digest), b"evil-bytes").unwrap();
        assert!(matches!(
            f.connector.reverify(&request(&f.digest)),
            Err(DeployError::ArtifactDigestMismatch(_))
        ));
        assert_eq!(calls(&f), 0);
        // remove has no staged bytes to re-hash; shape and inventory still apply.
        let mut r = request(&f.digest);
        r.tool = TOOL_DEPLOY_REMOVE.into();
        f.connector.reverify(&r).unwrap();
    }

    #[test]
    fn staging_is_content_addressed_and_never_overwrites() {
        let f = fixture("stage");
        let again = f.store.stage(b"mitigation-v1").unwrap();
        assert_eq!(again, f.digest);
        assert!(f.store.stage(b"mitigation-v2").unwrap() != f.digest);
        assert_eq!(f.store.read_verified(&f.digest).unwrap(), b"mitigation-v1");
        assert!(f.store.read_verified("not-a-digest").is_err());
    }

    #[test]
    fn inventory_rejects_non_plain_ids() {
        assert!(TargetInventory::new(["ok-1".to_string()]).is_ok());
        assert!(TargetInventory::new(["*".to_string()]).is_err());
        assert!(TargetInventory::new(["a/b".to_string()]).is_err());
    }

    #[test]
    fn policy_artifact_is_strictly_validated() {
        let ok = parse_policy_artifact(br#"{"schema_version":1,"max_count":100}"#).unwrap();
        assert_eq!(ok.max_count, 100);
        assert!(parse_policy_artifact(br#"{"schema_version":2,"max_count":100}"#).is_err());
        assert!(parse_policy_artifact(br#"{"schema_version":1}"#).is_err());
        assert!(
            parse_policy_artifact(br#"{"schema_version":1,"max_count":100,"url":"x"}"#).is_err()
        );
        assert!(parse_policy_artifact(br#"{"schema_version":1,"max_count":100001}"#).is_err());
        assert!(parse_policy_artifact(b"not json").is_err());
        let oversize = vec![b' '; MAX_POLICY_BYTES + 1];
        assert!(parse_policy_artifact(&oversize).is_err());
    }

    #[test]
    fn target_endpoints_parse_rejects_untrusted_shapes() {
        let (inventory, endpoints) =
            TargetEndpoints::parse("target-a=http://127.0.0.1:9301,target-b=https://t.example")
                .unwrap();
        assert_eq!(
            endpoints.base_url("target-a"),
            Some("http://127.0.0.1:9301")
        );
        assert!(inventory.contains("target-b"));
        for bad in [
            "",
            "target-a",
            "target-a=ftp://x",
            "a/b=http://x",
            "target-a=http://user@x",
            "target-a=http://x?y=1",
            "target-a=http://x,target-a=http://y",
        ] {
            assert!(TargetEndpoints::parse(bad).is_err(), "{bad:?}");
        }
    }

    /// The real executor against a live in-process fixture target: the whole
    /// slice-3 chain (policy validation, prior-state comparison, atomic
    /// install, byte read-back) with the seeded defect visible on /evaluate.
    struct HttpFixture {
        connector: DeployConnector,
        base_url: String,
        _dir: tempdir::Dir,
        _target: tokio::task::JoinHandle<()>,
        default_state: String,
        policy_digest: String,
    }

    async fn http_fixture() -> HttpFixture {
        let dir = tempdir::Dir::new("http");
        let store = ArtifactStore::open(dir.path().join("artifacts")).unwrap();
        let policy_bytes = br#"{"schema_version":1,"max_count":100}"#.to_vec();
        let policy_digest = store.stage(&policy_bytes).unwrap();
        let (base_url, target) = membrane_proof_target::spawn_ephemeral(None).await.unwrap();
        let (inventory, endpoints) =
            TargetEndpoints::parse(&format!("target-a={base_url}")).unwrap();
        let connector = DeployConnector::new(
            inventory,
            store,
            Arc::new(HttpPolicyExecutor::new(endpoints).unwrap()),
        );
        // Default (defective) state: policy digest of the empty bytes.
        let default_state =
            target_state_digest(&hex::encode(Sha256::digest([])), PROOF_TARGET_IMAGE);
        HttpFixture {
            connector,
            base_url,
            _dir: dir,
            _target: target,
            default_state,
            policy_digest,
        }
    }

    fn http_request(f: &HttpFixture) -> DeployRequest {
        let mut r = request(&f.policy_digest);
        r.expected_prior_state_sha256 = f.default_state.clone();
        r
    }

    #[tokio::test]
    async fn apply_installs_policy_and_the_behavior_changes() {
        let f = http_fixture().await;
        let base = f.base_url.clone();
        let client = reqwest::Client::new();
        // Defect before apply: count 101 is accepted.
        let accepted: serde_json::Value = client
            .post(format!("{base}/evaluate"))
            .json(&serde_json::json!({"count": 101}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(accepted["ok"], true);

        let ctx = f.connector.execute(&http_request(&f)).await.unwrap();
        assert_eq!(ctx.targets, vec!["target-a".to_string()]);
        // The receipt carries the executor-observed state, not the expected one.
        assert_eq!(
            ctx.effect.observed_state_sha256,
            target_state_digest(&f.policy_digest, PROOF_TARGET_IMAGE)
        );

        // Mitigation live: 101 refused, 1 still ok.
        let refused = client
            .post(format!("{base}/evaluate"))
            .json(&serde_json::json!({"count": 101}))
            .send()
            .await
            .unwrap();
        assert_eq!(refused.status(), 422);
        let ok: serde_json::Value = client
            .post(format!("{base}/evaluate"))
            .json(&serde_json::json!({"count": 1}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(ok["ok"], true);
    }

    #[tokio::test]
    async fn prior_state_mismatch_refuses_before_any_write() {
        let f = http_fixture().await;
        let mut r = http_request(&f);
        r.expected_prior_state_sha256 = "9".repeat(64);
        let err = f.connector.execute(&r).await.unwrap_err();
        assert!(matches!(err, DeployError::PriorStateMismatch(_)));
        assert!(err.pre_write());
        // Nothing was written: the defect is still live on the target.
        let base = f.base_url.clone();
        let state: serde_json::Value = reqwest::Client::new()
            .get(format!("{base}/state"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(state["policy_sha256"], hex::encode(Sha256::digest([])));
    }

    #[tokio::test]
    async fn invalid_artifact_never_reaches_the_target() {
        let f = http_fixture().await;
        let bad_digest = f.connector.store.stage(br#"{"schema_version":1}"#).unwrap();
        let mut r = http_request(&f);
        r.artifact_sha256 = bad_digest;
        let err = f.connector.execute(&r).await.unwrap_err();
        assert!(err.pre_write());
    }

    #[tokio::test]
    async fn remove_restores_the_default_state() {
        let f = http_fixture().await;
        f.connector.execute(&http_request(&f)).await.unwrap();
        let mut r = http_request(&f);
        r.tool = TOOL_DEPLOY_REMOVE.into();
        // After the apply, the reviewed prior state for the removal is the
        // policy-installed state.
        r.expected_prior_state_sha256 = target_state_digest(&f.policy_digest, PROOF_TARGET_IMAGE);
        f.connector.execute(&r).await.unwrap();
        let base = f.base_url.clone();
        let accepted: serde_json::Value = reqwest::Client::new()
            .post(format!("{base}/evaluate"))
            .json(&serde_json::json!({"count": 101}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(accepted["ok"], true);
    }
}
