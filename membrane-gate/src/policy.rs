//! Channel-registry policy as code: validate, diff and atomically install the
//! registry file the gate enforces.
//!
//! The gate re-reads its registry file on every authorization check, so
//! replacing that file atomically is a live policy update with no restart.
//! These functions close the rest of the loop: offline validation for CI, a
//! review diff for pull requests, and an install step that refuses to put an
//! invalid registry in place. A registry that cannot be loaded at all fails
//! closed: every authorization check errors until a valid file is restored.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::identity::{parse_duration_secs, IdentityGrant, SpendGrant};
use crate::ChannelRegistry;

/// Top-level keys [`ChannelRegistry`] accepts, including legacy aliases for
/// `model_api_url`. The runtime parser ignores unknown keys, so validation
/// rejects them instead: in a policy file an unknown key is almost always a
/// typo that silently disables the intended setting.
const KNOWN_TOP_LEVEL_KEYS: &[&str] = &[
    "identities",
    "permitted_channels",
    "forbidden_exports",
    "model_allowlist",
    "delta_t_secs",
    "model_api_url",
    "llama_cpp_url",
    "ollama_url",
    "github_repo_allowlist",
    "approval",
    "revision",
];

/// Outcome of validating one registry. Errors are conditions the gate refuses
/// or that make config unusable; warnings are legal configurations an operator
/// should confirm are deliberate.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct ValidationReport {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl ValidationReport {
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }

    fn error(&mut self, msg: impl Into<String>) {
        self.errors.push(msg.into());
    }

    fn warn(&mut self, msg: impl Into<String>) {
        self.warnings.push(msg.into());
    }
}

/// Parse registry text and validate it. A parse failure is reported as an
/// error and yields no registry; semantic errors still yield the parsed
/// registry so callers can inspect or diff it.
pub fn validate_registry_text(text: &str) -> (Option<ChannelRegistry>, ValidationReport) {
    let mut report = ValidationReport::default();
    if let Ok(serde_yaml::Value::Mapping(map)) = serde_yaml::from_str::<serde_yaml::Value>(text) {
        for key in map.keys() {
            match key.as_str() {
                Some(name) if !KNOWN_TOP_LEVEL_KEYS.contains(&name) => {
                    report.error(format!("unknown top-level key `{name}`"));
                }
                _ => {}
            }
        }
    }
    match serde_yaml::from_str::<ChannelRegistry>(text) {
        Ok(registry) => {
            let mut semantic = validate_registry(&registry);
            report.errors.append(&mut semantic.errors);
            report.warnings.append(&mut semantic.warnings);
            (Some(registry), report)
        }
        Err(e) => {
            report.error(format!("registry does not parse: {e}"));
            (None, report)
        }
    }
}

/// Semantic checks on a parsed registry, mirroring the conditions the gate
/// enforces at authorization time.
pub fn validate_registry(registry: &ChannelRegistry) -> ValidationReport {
    let mut report = ValidationReport::default();

    if registry.delta_t_secs == 0 {
        report.error("delta_t_secs must be greater than zero");
    }
    warn_duplicates(
        &mut report,
        "permitted_channels",
        &registry.permitted_channels,
    );
    warn_duplicates(
        &mut report,
        "forbidden_exports",
        &registry.forbidden_exports,
    );
    warn_duplicates(&mut report, "model_allowlist", &registry.model_allowlist);
    warn_duplicates(
        &mut report,
        "github_repo_allowlist",
        &registry.github_repo_allowlist,
    );

    if registry.model_allowlist.is_empty() {
        report.warn("model_allowlist is empty: the gate refuses every model call");
    }
    if registry.identities.is_empty() {
        report.warn("identities is empty: the gate refuses every production caller");
    }
    match &registry.model_api_url {
        Some(url) if !(url.starts_with("http://") || url.starts_with("https://")) => {
            report.error(format!(
                "model_api_url `{url}` must be an http:// or https:// URL"
            ));
        }
        None => report.warn("model_api_url is not set: model calls need a dev mock model"),
        _ => {}
    }
    for repo in &registry.github_repo_allowlist {
        if !is_repo_slug(repo) {
            report.error(format!(
                "github_repo_allowlist entry `{repo}` is not an `owner/name` slug"
            ));
        }
    }
    if let Some(approval) = &registry.approval {
        if let Err(e) = approval.validate() {
            report.error(format!("approval policy: {e}"));
        }
    }

    let now = now_unix();
    for (key, grant) in &registry.identities {
        validate_identity(&mut report, registry, key, grant, now);
    }

    // Grants that share a budget must state the same cap; when they disagree
    // the gate denies spending until they agree.
    let mut budgets: BTreeMap<&str, BTreeSet<u64>> = BTreeMap::new();
    for grant in registry.identities.values() {
        if let Some(spend) = &grant.spend {
            if !spend.budget.trim().is_empty() {
                budgets
                    .entry(spend.budget.as_str())
                    .or_default()
                    .insert(spend.budget_cap_msat);
            }
        }
    }
    for (budget, caps) in &budgets {
        if caps.len() > 1 {
            report.error(format!(
                "budget `{budget}` has conflicting caps {caps:?} across grants; spending is denied until they agree"
            ));
        }
    }

    report
}

fn validate_identity(
    report: &mut ValidationReport,
    registry: &ChannelRegistry,
    key: &str,
    grant: &IdentityGrant,
    now: i64,
) {
    let id = short_key(key);
    if !is_caller_pubkey(key) {
        report.error(format!(
            "identity `{id}` is not a 64-character lowercase hex public key"
        ));
    }

    if grant.valid_for.is_some() && grant.expires_at.is_some() {
        report.error(format!(
            "identity `{id}` sets both valid_for and expires_at; the grant window is contradictory and denies every request"
        ));
    }
    if grant.valid_for.is_some() && grant.not_before.is_none() {
        report.error(format!(
            "identity `{id}` sets valid_for without not_before; the grant window is invalid and denies every request"
        ));
    }
    if let Some(raw) = &grant.valid_for {
        if let Err(e) = parse_duration_secs(raw) {
            report.error(format!(
                "identity `{id}` has an invalid valid_for `{raw}`: {e}"
            ));
        }
    }
    if let (Some(from), Some(until)) = (grant.not_before, grant.expires_at) {
        if until <= from {
            report.error(format!(
                "identity `{id}` expires_at is not after not_before; the grant window denies every request"
            ));
        }
    }
    if let Some(until) = grant.expires_at {
        if now >= until {
            report.warn(format!(
                "identity `{id}` expired at {}; the grant already denies every request",
                render_time(Some(until))
            ));
        }
    }

    for model in &grant.model_allowlist {
        if !registry.model_allowlist.contains(model) {
            report.error(format!(
                "identity `{id}` allows model `{model}`, which is not in the registry model_allowlist; the gate refuses it"
            ));
        }
    }
    for channel in &grant.permitted_channels {
        if !registry.permitted_channels.contains(channel) {
            report.warn(format!(
                "identity `{id}` grants channel `{channel}`, which is not in the registry permitted_channels"
            ));
        }
    }
    for repo in &grant.github_repo_allowlist {
        if !is_repo_slug(repo) {
            report.error(format!(
                "identity `{id}` github_repo_allowlist entry `{repo}` is not an `owner/name` slug"
            ));
        } else if !registry.github_repo_allowlist.contains(repo) {
            report.error(format!(
                "identity `{id}` allows repo `{repo}`, which is not in the registry github_repo_allowlist; the gate refuses it"
            ));
        }
    }

    if let Some(spend) = &grant.spend {
        if spend.budget.trim().is_empty() {
            report.error(format!(
                "identity `{id}` spend grant has an empty budget name"
            ));
        }
        if spend.budget_cap_msat == 0 {
            report.error(format!(
                "identity `{id}` spend grant has a zero budget_cap_msat"
            ));
        }
        if spend.per_call_ceiling_msat == 0 || spend.per_call_ceiling_msat > spend.budget_cap_msat {
            report.error(format!(
                "identity `{id}` spend grant per_call_ceiling_msat ({}) must be between 1 and budget_cap_msat ({})",
                spend.per_call_ceiling_msat, spend.budget_cap_msat
            ));
        }
    }

    warn_duplicates_grant(report, &id, "scopes", &grant.scopes);
    warn_duplicates_grant(report, &id, "permitted_channels", &grant.permitted_channels);
    warn_duplicates_grant(report, &id, "model_allowlist", &grant.model_allowlist);
    warn_duplicates_grant(report, &id, "tool_allowlist", &grant.tool_allowlist);
    warn_duplicates_grant(
        report,
        &id,
        "github_repo_allowlist",
        &grant.github_repo_allowlist,
    );
}

/// A field-level change between two registries or two grants, rendered for
/// review.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FieldChange {
    pub field: String,
    pub change: String,
}

/// The difference between two registries, in a form a reviewer can read in a
/// pull request.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct RegistryDiff {
    pub identity_added: Vec<String>,
    pub identity_removed: Vec<String>,
    pub identity_changed: BTreeMap<String, Vec<FieldChange>>,
    pub registry_changed: Vec<FieldChange>,
}

impl RegistryDiff {
    pub fn is_empty(&self) -> bool {
        self.identity_added.is_empty()
            && self.identity_removed.is_empty()
            && self.identity_changed.is_empty()
            && self.registry_changed.is_empty()
    }

    pub fn render_text(&self) -> String {
        if self.is_empty() {
            return "no changes".to_string();
        }
        let mut out = String::new();
        for key in &self.identity_added {
            out.push_str(&format!("identity added: {key}\n"));
        }
        for key in &self.identity_removed {
            out.push_str(&format!("identity removed: {key}\n"));
        }
        for (key, changes) in &self.identity_changed {
            out.push_str(&format!("identity changed: {key}\n"));
            for change in changes {
                out.push_str(&format!("  {}: {}\n", change.field, change.change));
            }
        }
        for change in &self.registry_changed {
            out.push_str(&format!("{}: {}\n", change.field, change.change));
        }
        out.trim_end().to_string()
    }
}

/// Compute the review diff between the registry currently in force and a
/// candidate.
pub fn diff_registries(old: &ChannelRegistry, new: &ChannelRegistry) -> RegistryDiff {
    let mut diff = RegistryDiff::default();

    push_list_change(
        &mut diff.registry_changed,
        "permitted_channels",
        &old.permitted_channels,
        &new.permitted_channels,
    );
    push_list_change(
        &mut diff.registry_changed,
        "forbidden_exports",
        &old.forbidden_exports,
        &new.forbidden_exports,
    );
    push_list_change(
        &mut diff.registry_changed,
        "model_allowlist",
        &old.model_allowlist,
        &new.model_allowlist,
    );
    push_list_change(
        &mut diff.registry_changed,
        "github_repo_allowlist",
        &old.github_repo_allowlist,
        &new.github_repo_allowlist,
    );
    push_scalar_change(
        &mut diff.registry_changed,
        "delta_t_secs",
        old.delta_t_secs,
        new.delta_t_secs,
    );
    push_opt_str_change(
        &mut diff.registry_changed,
        "model_api_url",
        &old.model_api_url,
        &new.model_api_url,
    );
    match (&old.approval, &new.approval) {
        (None, None) => {}
        (None, Some(_)) => diff.registry_changed.push(FieldChange {
            field: "approval".to_string(),
            change: "added".to_string(),
        }),
        (Some(_), None) => diff.registry_changed.push(FieldChange {
            field: "approval".to_string(),
            change: "removed".to_string(),
        }),
        (Some(before), Some(after)) => {
            push_list_change(
                &mut diff.registry_changed,
                "approval.holdable_tools",
                &before.holdable_tools,
                &after.holdable_tools,
            );
            push_scalar_change(
                &mut diff.registry_changed,
                "approval.ttl_secs",
                before.ttl_secs,
                after.ttl_secs,
            );
        }
    }

    for key in new.identities.keys() {
        if !old.identities.contains_key(key) {
            diff.identity_added.push(key.clone());
        }
    }
    for key in old.identities.keys() {
        if !new.identities.contains_key(key) {
            diff.identity_removed.push(key.clone());
        }
    }
    for (key, grant) in &new.identities {
        if let Some(prev) = old.identities.get(key) {
            let changes = diff_grant(prev, grant);
            if !changes.is_empty() {
                diff.identity_changed.insert(key.clone(), changes);
            }
        }
    }
    diff
}

fn diff_grant(old: &IdentityGrant, new: &IdentityGrant) -> Vec<FieldChange> {
    let mut changes = Vec::new();
    push_scalar_change(&mut changes, "revoked", old.revoked, new.revoked);
    push_list_change(&mut changes, "scopes", &old.scopes, &new.scopes);
    push_list_change(
        &mut changes,
        "permitted_channels",
        &old.permitted_channels,
        &new.permitted_channels,
    );
    push_list_change(
        &mut changes,
        "model_allowlist",
        &old.model_allowlist,
        &new.model_allowlist,
    );
    push_list_change(
        &mut changes,
        "tool_allowlist",
        &old.tool_allowlist,
        &new.tool_allowlist,
    );
    push_list_change(
        &mut changes,
        "github_repo_allowlist",
        &old.github_repo_allowlist,
        &new.github_repo_allowlist,
    );
    if old.not_before != new.not_before {
        changes.push(FieldChange {
            field: "not_before".to_string(),
            change: format!(
                "{} -> {}",
                render_time(old.not_before),
                render_time(new.not_before)
            ),
        });
    }
    if old.expires_at != new.expires_at {
        changes.push(FieldChange {
            field: "expires_at".to_string(),
            change: format!(
                "{} -> {}",
                render_time(old.expires_at),
                render_time(new.expires_at)
            ),
        });
    }
    push_opt_str_change(&mut changes, "valid_for", &old.valid_for, &new.valid_for);
    if old.spend != new.spend {
        changes.push(FieldChange {
            field: "spend".to_string(),
            change: format!(
                "{} -> {}",
                render_spend(&old.spend),
                render_spend(&new.spend)
            ),
        });
    }
    changes
}

/// Where the generation record for a live registry file is kept: a sibling
/// named `<file>.revision-state.json`. The installer writes it at install
/// commit time; the gate only reads it.
pub fn revision_state_path_for(live: &Path) -> PathBuf {
    live.with_file_name(format!(
        "{}.revision-state.json",
        live.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "registry".into())
    ))
}

/// The generation the installer last committed: the registry revision and the
/// sha256 of the exact installed bytes. The gate refuses any live registry
/// that does not match this record, so policy can only change through the
/// registered update path.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AcceptedGeneration {
    /// Random per-registration token, bound into every policy digest. A fresh
    /// epoch is generated only by an explicit trust reset (first install or
    /// `migrate`); ordinary installs carry it forward unchanged. Re-creating
    /// a deleted record therefore produces digests that never match approvals
    /// granted before the reset, even for byte-identical policy content.
    pub epoch: String,
    pub revision: u64,
    pub content_sha256: String,
}

/// A fresh policy epoch: 256 bits of cryptographic randomness, hex-encoded.
/// Never derived from content, so deleting the record cannot recreate a
/// previous epoch.
pub fn fresh_epoch() -> String {
    nostr::Keys::generate().public_key().to_hex()
}

/// An epoch is only ever produced by `fresh_epoch`; anything else means the
/// record was hand-written or corrupt, and is treated as corrupt.
fn is_valid_epoch(epoch: &str) -> bool {
    epoch.len() == 64 && epoch.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Parse a generation record, rejecting malformed epochs. Callers map the
/// error to their own fail-closed path.
fn parse_record(text: &str) -> anyhow::Result<AcceptedGeneration> {
    let record: AcceptedGeneration = serde_json::from_str(text)?;
    if !is_valid_epoch(&record.epoch) {
        anyhow::bail!("invalid epoch");
    }
    Ok(record)
}

/// The install lock serializing applies and migrates for one record: held
/// across the whole read-live/commit sequence so two writers cannot race.
fn acquire_install_lock(state_path: &Path) -> anyhow::Result<std::fs::File> {
    let lock_path = state_path.with_extension("lock");
    if let Some(dir) = lock_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let lock_file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)?;
    lock_file
        .try_lock()
        .map_err(|_| anyhow::anyhow!("another registry install is in progress"))?;
    Ok(lock_file)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(bytes))
}

/// Atomically record the accepted generation (tmp file, sync, rename, then
/// sync the directory), the same durability pattern as the registry install.
pub fn write_accepted_generation(
    state_path: &Path,
    epoch: &str,
    revision: u64,
    content: &[u8],
) -> anyhow::Result<()> {
    let record = AcceptedGeneration {
        epoch: epoch.to_string(),
        revision,
        content_sha256: sha256_hex(content),
    };
    let bytes = serde_json::to_vec(&record)?;
    let dir = state_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir)?;
    let tmp = state_path.with_extension("tmp");
    std::fs::write(&tmp, &bytes)?;
    std::fs::File::open(&tmp).and_then(|f| f.sync_all())?;
    std::fs::rename(&tmp, state_path)?;
    if let Ok(dir_handle) = std::fs::File::open(dir) {
        let _ = dir_handle.sync_all();
    }
    Ok(())
}

/// Register the registry file currently at `live` as the accepted generation
/// without changing its content. Used by tests and to complete an install
/// that was interrupted between the registry write and the state write. The
/// epoch carries forward from the existing record; with no record a fresh
/// epoch is generated, which is a trust reset (see `migrate_registry`).
pub fn register_current_generation(live: &Path) -> anyhow::Result<AcceptedGeneration> {
    let state_path = revision_state_path_for(live);
    register_generation_at(live, &state_path)
}

fn register_generation_at(live: &Path, state_path: &Path) -> anyhow::Result<AcceptedGeneration> {
    let bytes = std::fs::read(live).map_err(|e| anyhow::anyhow!("read {}: {e}", live.display()))?;
    let registry: ChannelRegistry = serde_yaml::from_slice(&bytes)
        .map_err(|e| anyhow::anyhow!("parse {}: {e}", live.display()))?;
    // Same monotonicity rule as the installer: registering must never move
    // the durable accepted generation backwards or sideways.
    let mut epoch = None;
    match std::fs::read_to_string(state_path) {
        Ok(text) => {
            let record = parse_record(&text).map_err(|e| {
                anyhow::anyhow!(
                    "accepted-generation state {} is unreadable ({e}). Restore the correct current record if you have it - a repair that invalidates nothing; otherwise remove the record deliberately and re-run `membrane registry migrate`, a trust reset whose fresh epoch invalidates every outstanding approval",
                    state_path.display()
                )
            })?;
            let content_sha256 = sha256_hex(&bytes);
            if record.revision == registry.revision && record.content_sha256 == content_sha256 {
                return Ok(record);
            }
            if registry.revision <= record.revision {
                anyhow::bail!(
                    "refusing to register revision {} over accepted generation {}",
                    registry.revision,
                    record.revision
                );
            }
            epoch = Some(record.epoch);
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(anyhow::anyhow!("read {}: {e}", state_path.display())),
    }
    let epoch = epoch.unwrap_or_else(fresh_epoch);
    write_accepted_generation(state_path, &epoch, registry.revision, &bytes)?;
    Ok(AcceptedGeneration {
        epoch,
        revision: registry.revision,
        content_sha256: sha256_hex(&bytes),
    })
}

/// Explicit trust reset and upgrade bootstrap: record the registry currently
/// at `live` as the accepted generation under a FRESH policy epoch. The new
/// epoch is bound into every policy digest, so approvals granted before the
/// reset can never match again, even under byte-identical policy content -
/// no approval-store surgery is needed to void them.
///
/// Refuses when a valid record already exists: resetting a live deployment
/// first requires deliberately removing the record, which is itself the
/// trust-reset decision.
pub fn migrate_registry(live: &Path, state_path: &Path) -> anyhow::Result<AcceptedGeneration> {
    // Same lock as applies: a migrate must never race an in-flight install.
    let _install_lock = acquire_install_lock(state_path)?;
    match std::fs::read_to_string(state_path) {
        Ok(text) => {
            if let Ok(record) = parse_record(&text) {
                anyhow::bail!(
                    "generation {} is already recorded at {}; a trust reset requires deliberately removing the record first, which invalidates every outstanding approval",
                    record.revision,
                    state_path.display()
                );
            }
            // A corrupt record (including a malformed epoch) is replaced by
            // the fresh epoch below.
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(anyhow::anyhow!("read {}: {e}", state_path.display())),
    }
    let text = std::fs::read_to_string(live)
        .map_err(|e| anyhow::anyhow!("read {}: {e}", live.display()))?;
    // Migrate records exactly what the gate would enforce, so the live
    // registry must pass the same validation an apply would.
    let (_, report) = validate_registry_text(&text);
    if !report.is_valid() {
        anyhow::bail!(
            "live registry at {} is invalid ({} error(s)); fix it or install a valid candidate first",
            live.display(),
            report.errors.len()
        );
    }
    let revision = serde_yaml::from_str::<serde_yaml::Value>(&text)
        .ok()
        .and_then(|value| value.get("revision").and_then(|v| v.as_u64()))
        .unwrap_or(0);
    let epoch = fresh_epoch();
    write_accepted_generation(state_path, &epoch, revision, text.as_bytes())?;
    Ok(AcceptedGeneration {
        epoch,
        revision,
        content_sha256: sha256_hex(text.as_bytes()),
    })
}

/// Validate `candidate` and atomically move it over the live registry at
/// `live`, then record the new generation so the gate accepts it.
///
/// The candidate's bytes are installed unchanged, comments included. When the
/// report contains errors nothing is written; the write is a temp file, sync
/// and rename in the live file's directory, so readers never see a partial
/// registry. Two commit rules make policy history append-only:
///
/// - the candidate's revision must advance the live registry's, so restoring
///   an earlier registry installs only as a new, higher generation;
/// - the generation record advances at install commit time, under an install
///   lock that serializes concurrent installers, so a gate that never reads
///   while an old policy is being replaced still never sees the old
///   generation accepted again.
///
/// Commit order is registry file first, generation record second. A crash
/// between the two leaves the gate refusing the live registry (its content
/// does not match the record); re-applying the same candidate completes the
/// commit without another revision bump.
pub fn install_registry(candidate: &Path, live: &Path) -> anyhow::Result<ValidationReport> {
    let state_path = revision_state_path_for(live);
    install_registry_with_state_path(candidate, live, &state_path)
}

/// `install_registry` with an explicit generation-record path. The installer
/// and the gate must agree on the record location; a deployment that points
/// the gate at an override must pass the same path here, or applies would
/// write a record the gate never reads.
pub fn install_registry_with_state_path(
    candidate: &Path,
    live: &Path,
    state_path: &Path,
) -> anyhow::Result<ValidationReport> {
    let text = std::fs::read_to_string(candidate)
        .map_err(|e| anyhow::anyhow!("read {}: {e}", candidate.display()))?;
    let (parsed, mut report) = validate_registry_text(&text);
    if !report.is_valid() {
        return Ok(report);
    }
    let candidate_revision = parsed.as_ref().map(|r| r.revision).unwrap_or(0);

    // Serialize installers for the whole read-live/commit sequence; without
    // this two applies could read the same live revision and race to commit.
    let _install_lock = acquire_install_lock(state_path)?;

    let live_bytes = match std::fs::read(live) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(anyhow::anyhow!("read {}: {e}", live.display())),
    };
    // The durable accepted high-water is the record, not the mutable live
    // file: lowering the live file and re-applying it must never move the
    // accepted generation backwards.
    let record = match std::fs::read_to_string(state_path) {
        Ok(text) => Some(parse_record(&text).map_err(|e| {
            anyhow::anyhow!(
                "accepted-generation state {} is unreadable ({e}). Restore the correct current record if you have it - a repair that invalidates nothing; otherwise remove the record deliberately and re-run `membrane registry migrate`, a trust reset whose fresh epoch invalidates every outstanding approval",
                state_path.display()
            )
        })?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            return Err(anyhow::anyhow!(
                "read {}: {e}",
                state_path.display()
            ))
        }
    };
    // Only the live revision number gates the install; a live file with other
    // problems does not block replacing it. An unreadable revision reads as
    // legacy 0.
    let live_revision = live_bytes.as_ref().and_then(|bytes| {
        serde_yaml::from_slice::<serde_yaml::Value>(bytes)
            .ok()
            .and_then(|value| value.get("revision").and_then(|v| v.as_u64()))
    });
    if record.is_none() && live_bytes.is_some() {
        // A live registry with no recorded generation is never silently
        // adopted: bootstrapping it is a trust reset that must invalidate
        // outstanding approvals, so it requires the explicit migrate path
        // (fresh epoch), not an ordinary apply.
        report.error(format!(
            "no accepted policy generation is recorded for {}; recording one is a trust reset: run `membrane registry migrate --to {}` - the fresh policy epoch invalidates every outstanding approval. This is also the recovery path for an interrupted first install: the check cannot distinguish that crash from a deleted record, so it always takes the explicit path",
            live.display(),
            live.display()
        ));
        return Ok(report);
    }
    if let Some(live_bytes) = &live_bytes {
        let live_revision = live_revision.unwrap_or(0);
        let live_sha = sha256_hex(live_bytes);
        if *live_bytes == text.as_bytes()
            && record
                .as_ref()
                .is_some_and(|r| r.revision == live_revision && r.content_sha256 == live_sha)
        {
            // Already installed and recorded: a no-op, not a change.
            return Ok(report);
        }
        if let Some(record) = &record {
            if candidate_revision <= record.revision {
                report.error(format!(
                    "candidate revision {candidate_revision} does not advance accepted generation {}; bump revision to at least {}",
                    record.revision,
                    record.revision + 1
                ));
                return Ok(report);
            }
            // Surface divergence between the live file and the recorded
            // generation (a direct edit) instead of silently legitimizing it.
            if record.revision != live_revision || record.content_sha256 != live_sha {
                report.warnings.push(format!(
                    "live registry diverges from accepted generation {}; the install records a new generation",
                    record.revision
                ));
            }
        }
        if *live_bytes == text.as_bytes() {
            // Same bytes, but not the recorded generation: completing an
            // interrupted commit (live advanced past the record). Carries the
            // record's epoch forward; the registry itself is unchanged.
            let epoch = &record.as_ref().expect("live file implies record").epoch;
            write_accepted_generation(state_path, epoch, candidate_revision, live_bytes)?;
            return Ok(report);
        }
        if candidate_revision <= live_revision {
            report.error(format!(
                "candidate revision {candidate_revision} does not advance live revision {}; bump revision to at least {}",
                live_revision,
                live_revision + 1
            ));
            return Ok(report);
        }
    } else if let Some(record) = &record {
        // No live file: a new install still cannot recreate a generation at
        // or below the durable high-water.
        if candidate_revision <= record.revision {
            report.error(format!(
                "candidate revision {candidate_revision} does not advance accepted generation {}; bump revision to at least {}",
                record.revision,
                record.revision + 1
            ));
            return Ok(report);
        }
    }
    let dir = live
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = live
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("{} has no file name", live.display()))?;
    let tmp = dir.join(format!(
        ".{}.tmp-{}",
        name.to_string_lossy(),
        std::process::id()
    ));
    let result = (|| -> anyhow::Result<()> {
        std::fs::write(&tmp, &text).map_err(|e| anyhow::anyhow!("write {}: {e}", tmp.display()))?;
        std::fs::File::open(&tmp)
            .and_then(|f| f.sync_all())
            .map_err(|e| anyhow::anyhow!("sync {}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, live)
            .map_err(|e| anyhow::anyhow!("replace {}: {e}", live.display()))?;
        if let Ok(dir_handle) = std::fs::File::open(dir) {
            let _ = dir_handle.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result?;
    // The registry is live; committing the generation record is what lets the
    // gate accept it. If this fails the gate refuses the new registry until
    // the same candidate is re-applied. The epoch carries forward from the
    // existing record; only a fresh deployment (no live file, no record)
    // mints one here.
    let epoch = record
        .as_ref()
        .map(|r| r.epoch.clone())
        .unwrap_or_else(fresh_epoch);
    write_accepted_generation(state_path, &epoch, candidate_revision, text.as_bytes())?;
    Ok(report)
}

fn push_list_change(changes: &mut Vec<FieldChange>, field: &str, old: &[String], new: &[String]) {
    let added: Vec<&str> = new
        .iter()
        .filter(|item| !old.contains(item))
        .map(String::as_str)
        .collect();
    let removed: Vec<&str> = old
        .iter()
        .filter(|item| !new.contains(item))
        .map(String::as_str)
        .collect();
    if added.is_empty() && removed.is_empty() {
        return;
    }
    let mut parts: Vec<String> = added.iter().map(|item| format!("+ {item}")).collect();
    parts.extend(removed.iter().map(|item| format!("- {item}")));
    changes.push(FieldChange {
        field: field.to_string(),
        change: parts.join(", "),
    });
}

fn push_scalar_change<T>(changes: &mut Vec<FieldChange>, field: &str, old: T, new: T)
where
    T: PartialEq + std::fmt::Display,
{
    if old != new {
        changes.push(FieldChange {
            field: field.to_string(),
            change: format!("{old} -> {new}"),
        });
    }
}

fn push_opt_str_change(
    changes: &mut Vec<FieldChange>,
    field: &str,
    old: &Option<String>,
    new: &Option<String>,
) {
    if old != new {
        changes.push(FieldChange {
            field: field.to_string(),
            change: format!(
                "{} -> {}",
                old.as_deref().unwrap_or("unset"),
                new.as_deref().unwrap_or("unset")
            ),
        });
    }
}

fn render_spend(spend: &Option<SpendGrant>) -> String {
    match spend {
        Some(grant) => format!(
            "budget={} cap={}msat ceiling={}msat",
            grant.budget, grant.budget_cap_msat, grant.per_call_ceiling_msat
        ),
        None => "none".to_string(),
    }
}

fn render_time(value: Option<i64>) -> String {
    match value {
        Some(secs) => match chrono::DateTime::from_timestamp(secs, 0) {
            Some(dt) => format!("{} ({secs})", dt.format("%Y-%m-%dT%H:%M:%SZ")),
            None => secs.to_string(),
        },
        None => "unset".to_string(),
    }
}

fn warn_duplicates(report: &mut ValidationReport, what: &str, items: &[String]) {
    let mut seen = BTreeSet::new();
    for item in items {
        if !seen.insert(item) {
            report.warn(format!("{what} lists `{item}` more than once"));
        }
    }
}

fn warn_duplicates_grant(report: &mut ValidationReport, id: &str, what: &str, items: &[String]) {
    warn_duplicates(report, &format!("identity `{id}` {what}"), items);
}

fn is_caller_pubkey(key: &str) -> bool {
    key.len() == 64
        && key
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn is_repo_slug(value: &str) -> bool {
    let mut parts = value.split('/');
    let valid = matches!(
        (parts.next(), parts.next(), parts.next()),
        (Some(owner), Some(name), None) if !owner.is_empty() && !name.is_empty()
    );
    valid && !value.chars().any(char::is_whitespace)
}

fn short_key(key: &str) -> String {
    if key.len() > 12 {
        format!("{}...", &key[..12])
    } else {
        key.to_string()
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::ApprovalPolicy;

    const CALLER_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const CALLER_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn base_registry_yaml() -> String {
        format!(
            r#"
permitted_channels:
  - local-llm
forbidden_exports:
  - cloud-telemetry
model_allowlist:
  - sha256:demo-model
delta_t_secs: 300
model_api_url: http://127.0.0.1:8080
github_repo_allowlist:
  - example-org/pilot
identities:
  {CALLER_A}:
    scopes: [pilot-scope]
    permitted_channels: [local-llm]
    model_allowlist: [sha256:demo-model]
    tool_allowlist: [github.comment]
    github_repo_allowlist: [example-org/pilot]
"#
        )
    }

    fn valid_registry() -> ChannelRegistry {
        let (registry, report) = validate_registry_text(&base_registry_yaml());
        assert!(report.is_valid(), "unexpected errors: {:?}", report.errors);
        registry.expect("base registry parses")
    }

    #[test]
    fn valid_registry_passes() {
        let registry = valid_registry();
        let report = validate_registry(&registry);
        assert_eq!(report.errors, Vec::<String>::new());
        assert_eq!(report.warnings, Vec::<String>::new());
    }

    #[test]
    fn unknown_top_level_key_is_an_error() {
        let text = base_registry_yaml() + "modle_allowlist: []\n";
        let (_, report) = validate_registry_text(&text);
        assert!(report
            .errors
            .iter()
            .any(|e| e.contains("unknown top-level key `modle_allowlist`")));
    }

    #[test]
    fn unparseable_registry_is_an_error() {
        let (_, report) = validate_registry_text("identities: [not, a, map]");
        assert!(!report.is_valid());
        assert!(report.errors.iter().any(|e| e.contains("does not parse")));
    }

    #[test]
    fn malformed_identity_key_is_an_error() {
        let text = base_registry_yaml().replace(CALLER_A, "not-a-key");
        let (_, report) = validate_registry_text(&text);
        assert!(report
            .errors
            .iter()
            .any(|e| e.contains("64-character lowercase hex public key")));
    }

    #[test]
    fn grant_model_outside_registry_allowlist_is_an_error() {
        let text = base_registry_yaml().replace(
            "model_allowlist: [sha256:demo-model]\n    tool_allowlist",
            "model_allowlist: [sha256:other-model]\n    tool_allowlist",
        );
        let (_, report) = validate_registry_text(&text);
        assert!(report
            .errors
            .iter()
            .any(|e| e.contains("sha256:other-model") && e.contains("registry model_allowlist")));
    }

    #[test]
    fn grant_repo_outside_registry_allowlist_is_an_error() {
        let text = base_registry_yaml().replace(
            "github_repo_allowlist: [example-org/pilot]\n",
            "github_repo_allowlist: [other-org/repo]\n",
        );
        let (_, report) = validate_registry_text(&text);
        assert!(report
            .errors
            .iter()
            .any(|e| e.contains("other-org/repo") && e.contains("registry github_repo_allowlist")));
    }

    #[test]
    fn malformed_repo_slug_is_an_error() {
        let text = base_registry_yaml().replace("- example-org/pilot", "- just-a-name");
        let (_, report) = validate_registry_text(&text);
        assert!(report
            .errors
            .iter()
            .any(|e| e.contains("`just-a-name` is not an `owner/name` slug")));
    }

    #[test]
    fn contradictory_windows_are_errors() {
        let both = "    not_before: 1767225600\n    expires_at: 1767225600\n    valid_for: 24h\n";
        let text = base_registry_yaml().replace(
            "    github_repo_allowlist: [example-org/pilot]\n",
            &format!("    github_repo_allowlist: [example-org/pilot]\n{both}"),
        );
        let (_, report) = validate_registry_text(&text);
        assert!(report
            .errors
            .iter()
            .any(|e| e.contains("both valid_for and expires_at")));
        assert!(report
            .errors
            .iter()
            .any(|e| e.contains("expires_at is not after not_before")));

        let without_not_before = "    valid_for: 24h\n";
        let text = base_registry_yaml().replace(
            "    github_repo_allowlist: [example-org/pilot]\n",
            &format!("    github_repo_allowlist: [example-org/pilot]\n{without_not_before}"),
        );
        let (_, report) = validate_registry_text(&text);
        assert!(report
            .errors
            .iter()
            .any(|e| e.contains("valid_for without not_before")));

        let bad_duration = "    not_before: 1767225600\n    valid_for: 12w\n";
        let text = base_registry_yaml().replace(
            "    github_repo_allowlist: [example-org/pilot]\n",
            &format!("    github_repo_allowlist: [example-org/pilot]\n{bad_duration}"),
        );
        let (_, report) = validate_registry_text(&text);
        assert!(report
            .errors
            .iter()
            .any(|e| e.contains("invalid valid_for `12w`")));
    }

    #[test]
    fn expired_grant_is_a_warning() {
        let text = base_registry_yaml().replace(
            "    github_repo_allowlist: [example-org/pilot]\n",
            "    github_repo_allowlist: [example-org/pilot]\n    expires_at: 946684800\n",
        );
        let (_, report) = validate_registry_text(&text);
        assert!(report.is_valid(), "errors: {:?}", report.errors);
        assert!(report.warnings.iter().any(|w| w.contains("expired")));
    }

    #[test]
    fn invalid_spend_grants_are_errors() {
        let spend = "    spend:\n      budget: inference\n      budget_cap_msat: 1000\n      per_call_ceiling_msat: 5000\n";
        let text = base_registry_yaml().replace(
            "    github_repo_allowlist: [example-org/pilot]\n",
            &format!("    github_repo_allowlist: [example-org/pilot]\n{spend}"),
        );
        let (_, report) = validate_registry_text(&text);
        assert!(report.errors.iter().any(|e| e.contains(
            "per_call_ceiling_msat (5000) must be between 1 and budget_cap_msat (1000)"
        )));
    }

    #[test]
    fn conflicting_budget_caps_are_an_error() {
        let grant_b = format!(
            "  {CALLER_B}:\n    scopes: [pilot-scope]\n    spend:\n      budget: inference\n      budget_cap_msat: 2000\n      per_call_ceiling_msat: 100\n"
        );
        let spend_a = "    spend:\n      budget: inference\n      budget_cap_msat: 1000\n      per_call_ceiling_msat: 100\n";
        let text = base_registry_yaml().replace(
            "    github_repo_allowlist: [example-org/pilot]\n",
            &format!("    github_repo_allowlist: [example-org/pilot]\n{spend_a}"),
        ) + &grant_b;
        let (_, report) = validate_registry_text(&text);
        assert!(report
            .errors
            .iter()
            .any(|e| e.contains("budget `inference` has conflicting caps")));
    }

    #[test]
    fn invalid_approval_policy_is_an_error() {
        let mut registry = valid_registry();
        registry.approval = Some(ApprovalPolicy {
            holdable_tools: vec!["github.comment".into()],
            ttl_secs: 0,
        });
        let report = validate_registry(&registry);
        assert!(report.errors.iter().any(|e| e.contains("approval policy")));
    }

    #[test]
    fn empty_registry_warns_but_passes() {
        let text = "permitted_channels: []\nforbidden_exports: []\nmodel_allowlist: []\ndelta_t_secs: 300\ngithub_repo_allowlist: []\nidentities: {}\n";
        let (_, report) = validate_registry_text(text);
        assert!(report.is_valid(), "errors: {:?}", report.errors);
        assert!(report
            .warnings
            .iter()
            .any(|w| w.contains("model_allowlist is empty")));
        assert!(report
            .warnings
            .iter()
            .any(|w| w.contains("identities is empty")));
    }

    #[test]
    fn diff_reports_identity_and_list_changes() {
        let old = valid_registry();
        let new_text = base_registry_yaml()
            .replace(
                "- sha256:demo-model\n",
                "- sha256:demo-model\n  - sha256:new-model\n",
            )
            .replace("delta_t_secs: 300", "delta_t_secs: 600")
            + &format!("  {CALLER_B}:\n    scopes: [pilot-scope]\n");
        let (new, report) = validate_registry_text(&new_text);
        assert!(report.is_valid(), "errors: {:?}", report.errors);
        let diff = diff_registries(&old, &new.unwrap());
        assert_eq!(diff.identity_added, vec![CALLER_B.to_string()]);
        assert!(diff.identity_removed.is_empty());
        assert!(diff
            .registry_changed
            .iter()
            .any(|c| c.field == "model_allowlist" && c.change == "+ sha256:new-model"));
        assert!(diff
            .registry_changed
            .iter()
            .any(|c| c.field == "delta_t_secs" && c.change == "300 -> 600"));

        let text = diff.render_text();
        assert!(text.contains("identity added: bbbb"));
        assert!(text.contains("model_allowlist: + sha256:new-model"));
    }

    #[test]
    fn diff_reports_grant_field_changes() {
        let old = valid_registry();
        let new_text = base_registry_yaml().replace(
            "    github_repo_allowlist: [example-org/pilot]\n",
            "    github_repo_allowlist: [example-org/pilot]\n    expires_at: 1767225600\n",
        );
        let (new, report) = validate_registry_text(&new_text);
        assert!(report.is_valid(), "errors: {:?}", report.errors);
        let diff = diff_registries(&old, &new.unwrap());
        let changes = diff
            .identity_changed
            .get(CALLER_A)
            .expect("grant change recorded");
        assert!(
            changes
                .iter()
                .any(|c| c.field == "expires_at"
                    && c.change.contains("unset -> 2026-01-01T00:00:00Z"))
        );
    }

    #[test]
    fn identical_registries_have_no_changes() {
        let registry = valid_registry();
        assert!(diff_registries(&registry, &registry).is_empty());
        assert_eq!(
            diff_registries(&registry, &registry).render_text(),
            "no changes"
        );
    }

    #[test]
    fn install_refuses_invalid_candidate() {
        let dir = std::env::temp_dir().join(format!("membrane-policy-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let live = dir.join("registry.yaml");
        let candidate = dir.join("candidate.yaml");
        std::fs::write(&live, base_registry_yaml()).unwrap();
        std::fs::write(&candidate, "modle_allowlist: []\n").unwrap();
        let report = install_registry(&candidate, &live).unwrap();
        assert!(!report.is_valid());
        assert_eq!(
            std::fs::read_to_string(&live).unwrap(),
            base_registry_yaml()
        );
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn install_writes_valid_candidate_unchanged() {
        let dir =
            std::env::temp_dir().join(format!("membrane-policy-test-ok-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let live = dir.join("registry.yaml");
        let candidate = dir.join("candidate.yaml");
        std::fs::write(&live, base_registry_yaml()).unwrap();
        // The live file is a legacy revision-0 registry: bootstrap the
        // generation record first (the upgrade trust reset), then the
        // candidate bumps it.
        migrate_registry(&live, &revision_state_path_for(&live)).unwrap();
        let text = format!("revision: 1\n{}", base_registry_yaml());
        std::fs::write(&candidate, &text).unwrap();
        let report = install_registry(&candidate, &live).unwrap();
        assert!(report.is_valid(), "errors: {:?}", report.errors);
        assert_eq!(std::fs::read_to_string(&live).unwrap(), text);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn install_refuses_a_candidate_that_does_not_advance_revision() {
        let dir =
            std::env::temp_dir().join(format!("membrane-policy-test-rev-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let live = dir.join("registry.yaml");
        let candidate = dir.join("candidate.yaml");
        std::fs::write(&live, base_registry_yaml()).unwrap();
        // A live registry with no recorded generation is never silently
        // adopted: apply refuses and names the explicit trust-reset path.
        std::fs::write(&candidate, base_registry_yaml()).unwrap();
        let report = install_registry(&candidate, &live).unwrap();
        assert!(!report.is_valid());
        assert!(report
            .errors
            .iter()
            .any(|e| e.contains("trust reset") && e.contains("migrate")));
        // The explicit bootstrap records the live registry under a fresh
        // epoch.
        let state_path = revision_state_path_for(&live);
        let record = migrate_registry(&live, &state_path).unwrap();
        assert_eq!(record.revision, 0);
        // A second migrate refuses while a valid record exists.
        assert!(migrate_registry(&live, &state_path).is_err());
        // Identical bytes now install as a no-op re-apply: the content is
        // already live and recorded.
        let report = install_registry(&candidate, &live).unwrap();
        assert!(report.is_valid(), "errors: {:?}", report.errors);
        assert_eq!(
            std::fs::read_to_string(&live).unwrap(),
            base_registry_yaml()
        );
        // Different content at the same revision is a same-generation
        // mutation: refused, and the live file is untouched.
        let mutated = base_registry_yaml().replace("local-llm", "other-llm");
        std::fs::write(&candidate, &mutated).unwrap();
        let report = install_registry(&candidate, &live).unwrap();
        assert!(!report.is_valid());
        assert!(report.errors.iter().any(|e| e.contains("revision")));
        assert_eq!(
            std::fs::read_to_string(&live).unwrap(),
            base_registry_yaml()
        );
        // Bumping the revision installs, even with identical policy fields:
        // a restore of earlier content is a new generation, not the old one.
        let bumped = format!("revision: 2\n{}", base_registry_yaml());
        std::fs::write(&candidate, &bumped).unwrap();
        let report = install_registry(&candidate, &live).unwrap();
        assert!(report.is_valid(), "errors: {:?}", report.errors);
        assert_eq!(std::fs::read_to_string(&live).unwrap(), bumped);
        // Re-applying the same candidate is idempotent.
        let report = install_registry(&candidate, &live).unwrap();
        assert!(report.is_valid(), "errors: {:?}", report.errors);
        // A candidate that no longer advances the revision is refused.
        let stale = format!("revision: 1\n{}", base_registry_yaml());
        std::fs::write(&candidate, &stale).unwrap();
        let report = install_registry(&candidate, &live).unwrap();
        assert!(!report.is_valid());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn install_cannot_lower_the_accepted_generation() {
        let dir =
            std::env::temp_dir().join(format!("membrane-policy-test-hw-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let live = dir.join("registry.yaml");
        let candidate = dir.join("candidate.yaml");
        // Install A at revision 1, then B at revision 2.
        let policy_a = format!("revision: 1\n{}", base_registry_yaml());
        std::fs::write(&candidate, &policy_a).unwrap();
        assert!(install_registry(&candidate, &live).unwrap().is_valid());
        let policy_b = format!(
            "revision: 2\n{}",
            base_registry_yaml().replace("local-llm", "other-llm")
        );
        std::fs::write(&candidate, &policy_b).unwrap();
        assert!(install_registry(&candidate, &live).unwrap().is_valid());
        // Directly restore A over the live file (bypassing apply).
        std::fs::write(&live, &policy_a).unwrap();
        // Re-applying the identical bytes must not rewrite the record back to
        // generation 1: the durable high-water is 2.
        std::fs::write(&candidate, &policy_a).unwrap();
        let report = install_registry(&candidate, &live).unwrap();
        assert!(!report.is_valid());
        assert!(report
            .errors
            .iter()
            .any(|e| e.contains("accepted generation 2")));
        let record: AcceptedGeneration =
            serde_json::from_str(&std::fs::read_to_string(revision_state_path_for(&live)).unwrap())
                .unwrap();
        assert_eq!(record.revision, 2);
        // A's content at revision 2 is not a reinstall either: 2 does not
        // advance the accepted generation.
        let lowered = format!("revision: 2\n{}", base_registry_yaml());
        std::fs::write(&candidate, &lowered).unwrap();
        let report = install_registry(&candidate, &live).unwrap();
        assert!(!report.is_valid());
        // A's content installs only as generation 3: a new generation, never
        // the one approvals were bound to.
        let restored = format!("revision: 3\n{}", base_registry_yaml());
        std::fs::write(&candidate, &restored).unwrap();
        let report = install_registry(&candidate, &live).unwrap();
        assert!(report.is_valid(), "errors: {:?}", report.errors);
        assert!(report
            .warnings
            .iter()
            .any(|w| w.contains("diverges from accepted generation")));
        let record: AcceptedGeneration =
            serde_json::from_str(&std::fs::read_to_string(revision_state_path_for(&live)).unwrap())
                .unwrap();
        assert_eq!(record.revision, 3);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ordinary_installs_carry_the_epoch_forward() {
        let dir =
            std::env::temp_dir().join(format!("membrane-policy-test-epoch-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let live = dir.join("registry.yaml");
        let candidate = dir.join("candidate.yaml");
        // Fresh deployment: no live file, no record. The first install mints
        // the epoch.
        let policy_a = format!("revision: 1\n{}", base_registry_yaml());
        std::fs::write(&candidate, &policy_a).unwrap();
        assert!(install_registry(&candidate, &live).unwrap().is_valid());
        let record_a: AcceptedGeneration =
            serde_json::from_str(&std::fs::read_to_string(revision_state_path_for(&live)).unwrap())
                .unwrap();
        assert_eq!(record_a.epoch.len(), 64);
        // An ordinary install carries the epoch forward unchanged.
        let policy_b = format!(
            "revision: 2\n{}",
            base_registry_yaml().replace("local-llm", "other-llm")
        );
        std::fs::write(&candidate, &policy_b).unwrap();
        assert!(install_registry(&candidate, &live).unwrap().is_valid());
        let record_b: AcceptedGeneration =
            serde_json::from_str(&std::fs::read_to_string(revision_state_path_for(&live)).unwrap())
                .unwrap();
        assert_eq!(record_a.epoch, record_b.epoch);
        assert_eq!(record_b.revision, 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn migrate_takes_the_install_lock() {
        let dir =
            std::env::temp_dir().join(format!("membrane-policy-test-mlock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let live = dir.join("registry.yaml");
        std::fs::write(&live, base_registry_yaml()).unwrap();
        let state_path = revision_state_path_for(&live);
        // While an apply holds the install lock, migrate refuses instead of
        // racing the record write.
        let lock = acquire_install_lock(&state_path).unwrap();
        let err = migrate_registry(&live, &state_path).unwrap_err();
        assert!(err.to_string().contains("in progress"), "{err}");
        drop(lock);
        migrate_registry(&live, &state_path).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn migrate_validates_the_live_registry() {
        let dir =
            std::env::temp_dir().join(format!("membrane-policy-test-mval-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let live = dir.join("registry.yaml");
        let state_path = revision_state_path_for(&live);
        // An invalid live registry is never recorded as the accepted
        // generation: migrate validates like an apply would.
        std::fs::write(&live, "modle_allowlist: []\n").unwrap();
        let err = migrate_registry(&live, &state_path).unwrap_err();
        assert!(err.to_string().contains("invalid"), "{err}");
        assert!(!state_path.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_malformed_epoch_is_treated_as_corrupt() {
        let dir = std::env::temp_dir().join(format!(
            "membrane-policy-test-epochshape-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let live = dir.join("registry.yaml");
        std::fs::write(&live, base_registry_yaml()).unwrap();
        let state_path = revision_state_path_for(&live);
        migrate_registry(&live, &state_path).unwrap();
        // A hand-written short or empty epoch is not a valid record: the
        // installer fails closed and migrate offers only the explicit reset.
        std::fs::write(
            &state_path,
            r#"{"epoch":"abc","revision":0,"content_sha256":"x"}"#,
        )
        .unwrap();
        let candidate = dir.join("candidate.yaml");
        std::fs::write(&candidate, format!("revision: 1\n{}", base_registry_yaml())).unwrap();
        assert!(install_registry(&candidate, &live).is_err());
        migrate_registry(&live, &state_path).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn install_fails_closed_on_a_corrupt_generation_record() {
        let dir = std::env::temp_dir().join(format!(
            "membrane-policy-test-corrupt-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let live = dir.join("registry.yaml");
        let candidate = dir.join("candidate.yaml");
        let policy_a = format!("revision: 1\n{}", base_registry_yaml());
        std::fs::write(&candidate, &policy_a).unwrap();
        assert!(install_registry(&candidate, &live).unwrap().is_valid());
        // A corrupt record is not a silent re-baseline: installs refuse until
        // the operator restores or deliberately removes the record.
        std::fs::write(revision_state_path_for(&live), b"not json").unwrap();
        let policy_b = format!(
            "revision: 2\n{}",
            base_registry_yaml().replace("local-llm", "other-llm")
        );
        std::fs::write(&candidate, &policy_b).unwrap();
        let err = install_registry(&candidate, &live).unwrap_err();
        assert!(err.to_string().contains("trust reset"), "{err}");
        assert_eq!(std::fs::read_to_string(&live).unwrap(), policy_a);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
