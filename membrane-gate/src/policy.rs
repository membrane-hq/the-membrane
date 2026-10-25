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
use std::path::Path;

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

/// Validate `candidate` and atomically move it over the live registry at
/// `live`. The candidate's bytes are installed unchanged, comments included.
/// When the report contains errors nothing is written; the write is a temp
/// file, sync and rename in the live file's directory, so readers never see a
/// partial registry.
pub fn install_registry(candidate: &Path, live: &Path) -> anyhow::Result<ValidationReport> {
    let text = std::fs::read_to_string(candidate)
        .map_err(|e| anyhow::anyhow!("read {}: {e}", candidate.display()))?;
    let (_, report) = validate_registry_text(&text);
    if !report.is_valid() {
        return Ok(report);
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
        std::fs::write(&live, "permitted_channels: []\n").unwrap();
        let text = base_registry_yaml();
        std::fs::write(&candidate, &text).unwrap();
        let report = install_registry(&candidate, &live).unwrap();
        assert!(report.is_valid(), "errors: {:?}", report.errors);
        assert_eq!(std::fs::read_to_string(&live).unwrap(), text);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
