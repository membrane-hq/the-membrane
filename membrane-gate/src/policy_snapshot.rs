//! One consistent read of the policy that authorizes a request, and the digest
//! that binds that exact state into evidence.
//!
//! Without this, two policy sources could drift apart inside one request: the
//! gate keeps the startup registry in memory while identity grants are re-read
//! from the registry file on every check, and a signed receipt named neither.
//! A snapshot is one read of the live registry (or the startup registry when no
//! identity registry file is configured). Every check for the request runs
//! against it, its digest is recorded in the signed receipt, and dispatch
//! refuses the call when the live policy no longer matches the receipt.

use crate::approval::ApprovalPolicy;
use crate::identity::IdentityGrant;
use crate::{ChannelRegistry, Gate, GateError};
use serde_json::json;
use sha2::{Digest, Sha256};

/// The policy state that judged one request: one read of the live registry,
/// the caller's grant inside it, and a digest over everything the gate
/// enforced for that caller.
#[derive(Debug, Clone)]
pub struct PolicySnapshot {
    /// The registry identity checks run against: the live registry file parsed
    /// once, or the startup registry when no identity registry file is set.
    pub live: ChannelRegistry,
    /// The caller's grant inside `live`.
    pub grant: IdentityGrant,
    /// sha256 over the canonical effective policy (accepted generation,
    /// startup globals, live globals and this grant). Changes when any
    /// enforced field changes and on every accepted registry write.
    pub digest: String,
    /// The accepted registry generation this snapshot was taken from.
    pub revision: u64,
}

/// Verify the live registry matches the generation the installer last
/// committed through the registered update path. Anything else - a direct
/// file edit (with or without a revision bump), a rollback, a half-finished
/// install, a missing or corrupt record - fails closed: policy can only
/// change through `membrane registry apply`, which advances the generation
/// record durably at install commit time, whether or not the gate observes
/// the change.
///
/// Threat bound: the record and the registry live in the operator's storage;
/// rolling both back together (or forging the record) is outside the model,
/// the same trust domain as the approval store.
pub fn verify_accepted_generation(
    state_path: &std::path::Path,
    live_text: &str,
    live_revision: u64,
) -> Result<crate::policy::AcceptedGeneration, GateError> {
    let text = std::fs::read_to_string(state_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            GateError::PolicyRevision(format!(
                "no accepted policy generation recorded at {}; install the registry with `membrane registry apply`",
                state_path.display()
            ))
        } else {
            GateError::PolicyRevision(format!(
                "accepted-generation state {} cannot be read: {e}",
                state_path.display()
            ))
        }
    })?;
    let record = serde_json::from_str::<crate::policy::AcceptedGeneration>(&text)
        .ok()
        .filter(|r| r.epoch.len() == 64 && r.epoch.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| {
            GateError::PolicyRevision(format!(
                "accepted-generation state {} is unreadable or malformed; restore the correct current record, or remove it and re-run `membrane registry migrate` (a trust reset whose fresh epoch invalidates every outstanding approval)",
                state_path.display()
            ))
        })?;
    let content_sha256 = crate::policy::sha256_hex(live_text.as_bytes());
    if record.revision != live_revision || record.content_sha256 != content_sha256 {
        return Err(GateError::PolicyRevision(format!(
            "live registry does not match accepted generation {}; direct edits are rejected - install policy with `membrane registry apply`",
            record.revision
        )));
    }
    Ok(record)
}

fn sorted(list: &[String]) -> Vec<String> {
    let mut out = list.to_vec();
    out.sort();
    out
}

fn globals_view(registry: &ChannelRegistry) -> serde_json::Value {
    json!({
        "permitted_channels": sorted(&registry.permitted_channels),
        "forbidden_exports": sorted(&registry.forbidden_exports),
        "model_allowlist": sorted(&registry.model_allowlist),
        "github_repo_allowlist": sorted(&registry.github_repo_allowlist),
        "delta_t_secs": registry.delta_t_secs,
        "approval": registry.approval.as_ref().map(|policy: &ApprovalPolicy| json!({
            "holdable_tools": sorted(&policy.holdable_tools),
            "ttl_secs": policy.ttl_secs,
        })),
    })
}

fn grant_view(grant: &IdentityGrant) -> serde_json::Value {
    json!({
        "revoked": grant.revoked,
        "scopes": sorted(&grant.scopes),
        "permitted_channels": sorted(&grant.permitted_channels),
        "model_allowlist": sorted(&grant.model_allowlist),
        "tool_allowlist": sorted(&grant.tool_allowlist),
        "github_repo_allowlist": sorted(&grant.github_repo_allowlist),
        "not_before": grant.not_before,
        "expires_at": grant.expires_at,
        "valid_for": grant.valid_for,
        "spend": grant.spend,
    })
}

/// sha256 over the canonical effective policy for one caller: the accepted
/// registry generation, the gate's startup globals (what the session and
/// liveness checks enforce), the live registry's globals (what the identity
/// checks enforce) and the caller's grant. Set-like lists are sorted first,
/// so reordering one does not change the digest; any real change to an
/// enforced field does. Grants for other identities are not covered, so an
/// unrelated identity's fields never invalidate this caller's in-flight
/// calls - but every accepted registry write advances the generation, and the
/// generation is global: any install invalidates all outstanding approvals.
pub fn effective_policy_digest(
    startup: &ChannelRegistry,
    live: &ChannelRegistry,
    grant: &IdentityGrant,
    epoch: Option<&str>,
) -> Result<String, GateError> {
    let view = json!({
        "format": "membrane-policy-v3",
        "epoch": epoch,
        "revision": live.revision,
        "startup_globals": globals_view(startup),
        "live_globals": globals_view(live),
        "grant": grant_view(grant),
    });
    let bytes = membrane_core::canonical::canonical_json_bytes(&view)
        .map_err(|e| GateError::Registry(e.to_string()))?;
    let mut h = Sha256::new();
    h.update(b"membrane-policy-v3\0");
    h.update(&bytes);
    Ok(hex::encode(h.finalize()))
}

impl Gate {
    /// Read the live registry once and bind the exact policy state enforced for
    /// this caller. An unknown identity or an unreadable registry fails closed,
    /// same as authorization.
    pub fn policy_snapshot(&self, identity: &str) -> Result<PolicySnapshot, GateError> {
        let (live, epoch) = match &self.identity_registry_path {
            Some(path) => {
                let text = std::fs::read_to_string(path)
                    .map_err(|e| GateError::IdentityGrant(format!("registry unavailable: {e}")))?;
                let live: ChannelRegistry = serde_yaml::from_str(&text)
                    .map_err(|e| GateError::IdentityGrant(format!("registry unavailable: {e}")))?;
                // The live registry must be exactly the generation the
                // installer last committed; direct edits fail closed.
                let state_path = self
                    .revision_state_path
                    .clone()
                    .unwrap_or_else(|| crate::policy::revision_state_path_for(path));
                let record = verify_accepted_generation(&state_path, &text, live.revision)?;
                (live, Some(record.epoch))
            }
            None => (self.registry.clone(), None),
        };
        let grant = live
            .identities
            .get(identity)
            .cloned()
            .ok_or_else(|| GateError::IdentityGrant("unknown identity".into()))?;
        let digest = effective_policy_digest(&self.registry, &live, &grant, epoch.as_deref())?;
        Ok(PolicySnapshot {
            revision: live.revision,
            live,
            grant,
            digest,
        })
    }

    /// The policy state that may dispatch: the live policy now, which must be
    /// the state the intent receipt named. Any change refuses the call; the
    /// caller retries under a fresh snapshot.
    pub fn dispatch_snapshot(
        &self,
        receipt_snapshot: &PolicySnapshot,
        identity: &str,
    ) -> Result<PolicySnapshot, GateError> {
        let fresh = self.policy_snapshot(identity)?;
        if fresh.digest != receipt_snapshot.digest {
            return Err(GateError::PolicyChanged(format!(
                "receipt names policy {} but the live policy is {}",
                receipt_snapshot.digest, fresh.digest
            )));
        }
        Ok(fresh)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::SpendGrant;

    fn grant() -> IdentityGrant {
        IdentityGrant {
            revoked: false,
            scopes: vec!["s".into()],
            permitted_channels: vec!["local-llm".into()],
            model_allowlist: vec!["m".into()],
            tool_allowlist: vec!["github.comment".into()],
            github_repo_allowlist: vec!["a/b".into()],
            not_before: None,
            expires_at: None,
            valid_for: None,
            spend: Some(SpendGrant {
                budget: "ops".into(),
                budget_cap_msat: 1_000,
                per_call_ceiling_msat: 100,
            }),
        }
    }

    fn mk_registry(identities: Vec<(&str, IdentityGrant)>) -> ChannelRegistry {
        ChannelRegistry {
            approval: Some(ApprovalPolicy {
                holdable_tools: vec!["github.merge".into()],
                ttl_secs: 900,
            }),
            identities: identities
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
            permitted_channels: vec!["local-llm".into()],
            forbidden_exports: vec!["training-retention".into()],
            model_allowlist: vec!["m".into()],
            delta_t_secs: 300,
            model_api_url: None,
            github_repo_allowlist: vec!["a/b".into()],
            revision: 0,
        }
    }

    #[test]
    fn list_reordering_does_not_change_the_digest() {
        let registry = mk_registry(vec![("id", grant())]);
        let base = effective_policy_digest(&registry, &registry, &grant(), None).unwrap();
        let mut reordered = mk_registry(vec![("id", grant())]);
        reordered.permitted_channels.reverse();
        reordered.forbidden_exports.reverse();
        reordered.model_allowlist.reverse();
        reordered.github_repo_allowlist.reverse();
        reordered
            .approval
            .as_mut()
            .unwrap()
            .holdable_tools
            .reverse();
        let mut grant = grant();
        grant.scopes.reverse();
        grant.permitted_channels.reverse();
        grant.model_allowlist.reverse();
        grant.tool_allowlist.reverse();
        grant.github_repo_allowlist.reverse();
        assert_eq!(
            base,
            effective_policy_digest(&reordered, &reordered, &grant, None).unwrap()
        );
    }

    #[test]
    fn every_enforced_change_changes_the_digest() {
        let registry = mk_registry(vec![("id", grant())]);
        let base = effective_policy_digest(&registry, &registry, &grant(), None).unwrap();

        let mut revoked = grant();
        revoked.revoked = true;
        assert_ne!(
            base,
            effective_policy_digest(&registry, &registry, &revoked, None).unwrap()
        );

        let mut narrowed = grant();
        narrowed.tool_allowlist.clear();
        assert_ne!(
            base,
            effective_policy_digest(&registry, &registry, &narrowed, None).unwrap()
        );

        let mut windowed = grant();
        windowed.expires_at = Some(2_000);
        assert_ne!(
            base,
            effective_policy_digest(&registry, &registry, &windowed, None).unwrap()
        );

        let mut no_spend = grant();
        no_spend.spend = None;
        assert_ne!(
            base,
            effective_policy_digest(&registry, &registry, &no_spend, None).unwrap()
        );

        let mut globals = mk_registry(vec![("id", grant())]);
        globals.model_allowlist.push("other".into());
        assert_ne!(
            base,
            effective_policy_digest(&globals, &registry, &grant(), None).unwrap()
        );
        assert_ne!(
            base,
            effective_policy_digest(&registry, &globals, &grant(), None).unwrap()
        );

        let mut ttl = mk_registry(vec![("id", grant())]);
        ttl.approval.as_mut().unwrap().ttl_secs = 60;
        assert_ne!(
            base,
            effective_policy_digest(&ttl, &ttl, &grant(), None).unwrap()
        );

        let mut delta = mk_registry(vec![("id", grant())]);
        delta.delta_t_secs = 60;
        assert_ne!(
            base,
            effective_policy_digest(&delta, &delta, &grant(), None).unwrap()
        );
    }

    fn gate_with_registry_file(
        tag: &str,
    ) -> (
        Gate,
        std::path::PathBuf,
        ChannelRegistry,
        membrane_core::iac::IntentAuthorizationCredential,
        String,
    ) {
        let operator = nostr::Keys::generate();
        let caller = nostr::Keys::generate();
        let identity = caller.public_key().to_hex();
        let mut iac = membrane_core::iac::IntentAuthorizationCredential::new_session_with_tools(
            "s",
            "m",
            "0".repeat(64),
            4_102_444_800,
            vec!["local-llm".into()],
            vec![],
            vec!["github.comment".into()],
        );
        iac.caller_pubkey = Some(identity.clone());
        iac.sign(&operator).unwrap();
        let registry = mk_registry(vec![(&identity, grant())]);
        let dir = std::env::temp_dir().join(format!(
            "membrane-snapshot-{}-{tag}",
            nostr::Keys::generate().public_key().to_hex()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("registry.yaml");
        std::fs::write(&path, serde_yaml::to_string(&registry).unwrap()).unwrap();
        crate::policy::register_current_generation(&path).unwrap();
        let gate = Gate::new(
            registry.clone(),
            membrane_core::BusPublisher::new(membrane_core::BusPublisherConfig {
                relay_url: "memory://snapshot".into(),
                keys: operator,
            }),
        )
        .with_identity_registry_path(path.clone());
        (gate, path, registry, iac, identity)
    }

    #[test]
    fn dispatch_refuses_a_policy_that_changed_since_the_receipt() {
        let (gate, path, registry, iac, identity) = gate_with_registry_file("stale");
        let snapshot = gate.policy_snapshot(&identity).unwrap();
        gate.dispatch_snapshot(&snapshot, &identity).unwrap();

        // A registry install between the receipt and dispatch changes the digest.
        let mut changed = registry.clone();
        changed.revision += 1;
        changed.identities.get_mut(&identity).unwrap().revoked = true;
        std::fs::write(&path, serde_yaml::to_string(&changed).unwrap()).unwrap();
        crate::policy::register_current_generation(&path).unwrap();
        let err = gate.dispatch_snapshot(&snapshot, &identity).unwrap_err();
        assert!(matches!(err, GateError::PolicyChanged(_)), "{err}");
        // The fresh state denies on its own merits too.
        let fresh = gate.policy_snapshot(&identity).unwrap();
        assert_ne!(fresh.digest, snapshot.digest);
        assert!(matches!(
            gate.authorize_with_snapshot(&fresh, &iac, "m", None, 1_700_000_000, false),
            Err(GateError::IdentityGrant(_))
        ));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn spend_authorization_comes_from_one_consistent_read() {
        let (gate, path, registry, iac, identity) = gate_with_registry_file("spend");
        let spend = gate.authorize_spend(&identity, &iac, "m").unwrap();
        assert_eq!(spend.budget, "ops");

        let mut changed = registry.clone();
        changed.revision += 1;
        changed.identities.get_mut(&identity).unwrap().spend = None;
        std::fs::write(&path, serde_yaml::to_string(&changed).unwrap()).unwrap();
        crate::policy::register_current_generation(&path).unwrap();
        assert!(matches!(
            gate.authorize_spend(&identity, &iac, "m"),
            Err(GateError::Spend(_))
        ));

        let mut changed = registry.clone();
        changed.revision += 2;
        changed.identities.get_mut(&identity).unwrap().revoked = true;
        std::fs::write(&path, serde_yaml::to_string(&changed).unwrap()).unwrap();
        crate::policy::register_current_generation(&path).unwrap();
        assert!(matches!(
            gate.authorize_spend(&identity, &iac, "m"),
            Err(GateError::IdentityGrant(_))
        ));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn the_digest_names_what_the_gate_enforces() {
        let (gate, path, registry, _, identity) = gate_with_registry_file("globals");
        let base = gate.policy_snapshot(&identity).unwrap();
        // Startup globals are part of the digest: a gate restarted with a
        // different registry would name a different policy for the same file.
        let mut other_startup = registry.clone();
        other_startup.delta_t_secs = 60;
        let other = effective_policy_digest(
            &other_startup,
            &registry,
            mk_registry(vec![(identity.as_str(), grant())])
                .identities
                .values()
                .next()
                .unwrap(),
            None,
        )
        .unwrap();
        assert_ne!(base.digest, other);
        // The live registry file is read once per snapshot; a missing file
        // fails closed.
        std::fs::remove_file(&path).unwrap();
        assert!(gate.policy_snapshot(&identity).is_err());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn unknown_identity_fails_closed() {
        let (gate, _, _, _, _) = gate_with_registry_file("unknown");
        assert!(matches!(
            gate.policy_snapshot("nobody"),
            Err(GateError::IdentityGrant(_))
        ));
    }

    #[test]
    fn an_unrelated_identity_does_not_change_the_digest() {
        let registry = mk_registry(vec![("id", grant())]);
        let base = effective_policy_digest(&registry, &registry, &grant(), None).unwrap();
        let wider = mk_registry(vec![("id", grant()), ("other", grant())]);
        assert_eq!(
            base,
            effective_policy_digest(&wider, &wider, &grant(), None).unwrap()
        );
    }

    #[test]
    fn every_accepted_write_is_a_new_generation() {
        // Identical enforced fields under two accepted revisions name two
        // different policies: a restore never reopens what a change closed.
        let one = mk_registry(vec![("id", grant())]);
        let mut three = one.clone();
        three.revision = 3;
        assert_ne!(
            effective_policy_digest(&one, &one, &grant(), None).unwrap(),
            effective_policy_digest(&three, &three, &grant(), None).unwrap()
        );
    }

    #[test]
    fn a_restored_registry_is_rejected_and_a_bumped_restore_is_a_new_generation() {
        let (gate, path, registry, _, identity) = gate_with_registry_file("rollback");
        let gen_a = gate.policy_snapshot(&identity).unwrap();

        // Install B through the registered update path: accepted as a new
        // generation.
        let mut policy_b = registry.clone();
        policy_b.revision += 1;
        policy_b.model_allowlist.push("other".into());
        std::fs::write(&path, serde_yaml::to_string(&policy_b).unwrap()).unwrap();
        crate::policy::register_current_generation(&path).unwrap();
        let gen_b = gate.policy_snapshot(&identity).unwrap();
        assert_ne!(gen_a.digest, gen_b.digest);

        // Restoring the original file bytes directly is refused, even though
        // the content is exactly a policy the gate once enforced.
        std::fs::write(&path, serde_yaml::to_string(&registry).unwrap()).unwrap();
        let err = gate.policy_snapshot(&identity).unwrap_err();
        assert!(matches!(err, GateError::PolicyRevision(_)), "{err}");

        // A direct edit that bumps the revision is refused too: a bumped
        // revision never self-registers, only the installer records a
        // generation.
        let mut bumped_edit = registry.clone();
        bumped_edit.revision = policy_b.revision + 1;
        std::fs::write(&path, serde_yaml::to_string(&bumped_edit).unwrap()).unwrap();
        let err = gate.policy_snapshot(&identity).unwrap_err();
        assert!(matches!(err, GateError::PolicyRevision(_)), "{err}");

        // The same restore THROUGH the update path is accepted as generation
        // 2: its digest differs from generation 0's, so nothing bound to
        // generation 0 matches it.
        crate::policy::register_current_generation(&path).unwrap();
        let gen_c = gate.policy_snapshot(&identity).unwrap();
        assert_eq!(gen_c.revision, bumped_edit.revision);
        assert_ne!(gen_c.digest, gen_a.digest);
        assert_ne!(gen_c.digest, gen_b.digest);

        // A direct edit that keeps the revision but changes content is a
        // silent same-generation mutation: refused.
        let mut silent = bumped_edit.clone();
        silent.model_allowlist.push("sneaky".into());
        std::fs::write(&path, serde_yaml::to_string(&silent).unwrap()).unwrap();
        let err = gate.policy_snapshot(&identity).unwrap_err();
        assert!(matches!(err, GateError::PolicyRevision(_)), "{err}");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn an_interrupted_install_is_refused_until_reapplied() {
        let (gate, path, registry, _, identity) = gate_with_registry_file("half");
        // Crash window: the registry file moved but the generation record
        // never committed. The gate refuses the half-installed policy.
        let mut policy_b = registry.clone();
        policy_b.revision += 1;
        policy_b.model_allowlist.push("other".into());
        std::fs::write(&path, serde_yaml::to_string(&policy_b).unwrap()).unwrap();
        let err = gate.policy_snapshot(&identity).unwrap_err();
        assert!(matches!(err, GateError::PolicyRevision(_)), "{err}");
        // Re-applying the same candidate completes the commit.
        let candidate = path.parent().unwrap().join("candidate.yaml");
        std::fs::write(&candidate, serde_yaml::to_string(&policy_b).unwrap()).unwrap();
        let report = crate::policy::install_registry(&candidate, &path).unwrap();
        assert!(report.is_valid(), "errors: {:?}", report.errors);
        gate.policy_snapshot(&identity).unwrap();
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn acceptance_survives_a_restart() {
        let (gate, path, registry, _, identity) = gate_with_registry_file("restart");
        let before = gate.policy_snapshot(&identity).unwrap();
        // "Restart": a new gate over the same registry and record accepts the
        // unchanged registry at the same generation.
        let gate = Gate::new(
            registry.clone(),
            membrane_core::BusPublisher::new(membrane_core::BusPublisherConfig {
                relay_url: "memory://snapshot-restart".into(),
                keys: nostr::Keys::generate(),
            }),
        )
        .with_identity_registry_path(path.clone());
        let after = gate.policy_snapshot(&identity).unwrap();
        assert_eq!(before.digest, after.digest);
        // A registered update after the restart is accepted; a direct
        // rollback to the original bytes is still refused.
        let mut policy_b = registry.clone();
        policy_b.revision = before.revision + 1;
        policy_b.model_allowlist.push("newer".into());
        std::fs::write(&path, serde_yaml::to_string(&policy_b).unwrap()).unwrap();
        crate::policy::register_current_generation(&path).unwrap();
        gate.policy_snapshot(&identity).unwrap();
        std::fs::write(&path, serde_yaml::to_string(&registry).unwrap()).unwrap();
        let err = gate.policy_snapshot(&identity).unwrap_err();
        assert!(matches!(err, GateError::PolicyRevision(_)), "{err}");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_registry_without_a_recorded_generation_is_refused() {
        let (gate, path, registry, _, identity) = gate_with_registry_file("nowrite");
        // State path where no generation was ever recorded: the gate fails
        // closed instead of accepting an unregistered registry.
        let state_path = path
            .parent()
            .unwrap()
            .join("missing-dir")
            .join("revision-state.json");
        let gate = gate.with_revision_state_path(state_path);
        let err = gate.policy_snapshot(&identity).unwrap_err();
        assert!(matches!(err, GateError::PolicyRevision(_)), "{err}");
        let _ = registry;
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_malformed_epoch_fails_closed() {
        let (gate, path, _, _, identity) = gate_with_registry_file("bad-epoch");
        let state_path = path.parent().unwrap().join("revision-state.json");
        std::fs::write(
            &state_path,
            r#"{"epoch":"","revision":0,"content_sha256":"x"}"#,
        )
        .unwrap();
        let gate = gate.with_revision_state_path(state_path);
        let err = gate.policy_snapshot(&identity).unwrap_err();
        assert!(matches!(err, GateError::PolicyRevision(_)), "{err}");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn corrupt_acceptance_state_fails_closed() {
        let (gate, path, _, _, identity) = gate_with_registry_file("corrupt");
        let state_path = path.parent().unwrap().join("revision-state.json");
        std::fs::write(&state_path, b"not json").unwrap();
        let gate = gate.with_revision_state_path(state_path);
        let err = gate.policy_snapshot(&identity).unwrap_err();
        assert!(matches!(err, GateError::PolicyRevision(_)), "{err}");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_record_at_an_overridden_state_path_is_the_one_verified() {
        let (gate, path, registry, _, identity) = gate_with_registry_file("override");
        // The helper recorded at the default sibling; a gate pointed at a
        // different state path must verify against that path instead.
        let state_path = path.parent().unwrap().join("custom-state.json");
        let mk_gate = || {
            Gate::new(
                registry.clone(),
                membrane_core::BusPublisher::new(membrane_core::BusPublisherConfig {
                    relay_url: "memory://snapshot-override".into(),
                    keys: gate.publisher().keys().clone(),
                }),
            )
            .with_identity_registry_path(path.clone())
            .with_revision_state_path(state_path.clone())
        };
        let err = mk_gate().policy_snapshot(&identity).unwrap_err();
        assert!(matches!(err, GateError::PolicyRevision(_)), "{err}");
        std::fs::copy(crate::policy::revision_state_path_for(&path), &state_path).unwrap();
        mk_gate().policy_snapshot(&identity).unwrap();
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn startup_globals_stay_part_of_the_digest_across_restart() {
        let (gate, path, registry, _, identity) = gate_with_registry_file("globals-restart");
        let before = gate.policy_snapshot(&identity).unwrap();
        // Same live file, same record, different startup registry: the
        // registry is still accepted, but the digest names the new startup
        // globals, so approvals bound to the old digest cannot match.
        let mut other_startup = registry.clone();
        other_startup.delta_t_secs = 60;
        let restarted = Gate::new(
            other_startup,
            membrane_core::BusPublisher::new(membrane_core::BusPublisherConfig {
                relay_url: "memory://snapshot-globals".into(),
                keys: nostr::Keys::generate(),
            }),
        )
        .with_identity_registry_path(path.clone());
        let after = restarted.policy_snapshot(&identity).unwrap();
        assert_eq!(before.revision, after.revision);
        assert_ne!(before.digest, after.digest);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn cli_path_restarts_cannot_revive_a_prior_generation() {
        // The enforced production path: `membrane gate` loads its startup
        // registry from the same registered file the gate verifies, so every
        // restart re-derives startup globals from the recorded generation.
        // Simulate boot = load(live file) + verify against the record.
        let (gate, path, registry, _, identity) = gate_with_registry_file("cli-restart");
        let gen_a = gate.policy_snapshot(&identity).unwrap();
        let boot_gate = || {
            let startup: crate::ChannelRegistry =
                serde_yaml::from_str(&std::fs::read_to_string(path.clone()).unwrap()).unwrap();
            Gate::new(
                startup,
                membrane_core::BusPublisher::new(membrane_core::BusPublisherConfig {
                    relay_url: "memory://cli-restart".into(),
                    keys: nostr::Keys::generate(),
                }),
            )
            .with_identity_registry_path(path.clone())
        };
        // Boot 2 over unchanged files: same generation, same digest.
        assert_eq!(
            boot_gate().policy_snapshot(&identity).unwrap().digest,
            gen_a.digest
        );

        // Apply B through the registered path, then boot again: a new
        // generation, and startup globals come from B.
        let mut policy_b = registry.clone();
        policy_b.revision += 1;
        policy_b.model_allowlist.push("other".into());
        let candidate = path.parent().unwrap().join("candidate.yaml");
        std::fs::write(&candidate, serde_yaml::to_string(&policy_b).unwrap()).unwrap();
        assert!(crate::policy::install_registry(&candidate, &path)
            .unwrap()
            .is_valid());
        let gen_b = boot_gate().policy_snapshot(&identity).unwrap();
        assert_ne!(gen_a.digest, gen_b.digest);

        // Directly restore A's bytes: every boot now refuses - startup
        // globals and live policy both come from a file the record rejects.
        std::fs::write(&path, serde_yaml::to_string(&registry).unwrap()).unwrap();
        let err = boot_gate().policy_snapshot(&identity).unwrap_err();
        assert!(matches!(err, GateError::PolicyRevision(_)), "{err}");

        // A's content returns only as a new generation; its digest still
        // never matches generation A's.
        let mut restored = registry.clone();
        restored.revision = policy_b.revision + 1;
        std::fs::write(&candidate, serde_yaml::to_string(&restored).unwrap()).unwrap();
        assert!(crate::policy::install_registry(&candidate, &path)
            .unwrap()
            .is_valid());
        let gen_c = boot_gate().policy_snapshot(&identity).unwrap();
        assert_ne!(gen_c.digest, gen_a.digest);
        assert_ne!(gen_c.digest, gen_b.digest);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_recreated_record_never_recreates_an_old_digest() {
        // The supported reset pathway: delete the record, re-baseline with
        // migrate. The fresh epoch means the re-accepted registry - even
        // byte-identical content at the original revision - names a different
        // policy than the one approvals were bound to.
        let (gate, path, registry, _, identity) = gate_with_registry_file("epoch-reset");
        let gen_a = gate.policy_snapshot(&identity).unwrap();

        // Install B through the registered path; epoch carries forward.
        let mut policy_b = registry.clone();
        policy_b.revision += 1;
        policy_b.model_allowlist.push("other".into());
        let candidate = path.parent().unwrap().join("candidate.yaml");
        std::fs::write(&candidate, serde_yaml::to_string(&policy_b).unwrap()).unwrap();
        assert!(crate::policy::install_registry(&candidate, &path)
            .unwrap()
            .is_valid());
        let gen_b = gate.policy_snapshot(&identity).unwrap();
        assert_ne!(gen_a.digest, gen_b.digest);

        // Attack: restore A's bytes directly, delete the record, and
        // re-baseline through the supported migrate command.
        let epoch_before = serde_json::from_str::<crate::policy::AcceptedGeneration>(
            &std::fs::read_to_string(crate::policy::revision_state_path_for(&path)).unwrap(),
        )
        .unwrap()
        .epoch;
        std::fs::write(&path, serde_yaml::to_string(&registry).unwrap()).unwrap();
        let err = gate.policy_snapshot(&identity).unwrap_err();
        assert!(matches!(err, GateError::PolicyRevision(_)), "{err}");
        std::fs::remove_file(crate::policy::revision_state_path_for(&path)).unwrap();
        // An ordinary apply refuses to adopt the unrecorded live file...
        std::fs::write(&candidate, serde_yaml::to_string(&registry).unwrap()).unwrap();
        let report = crate::policy::install_registry(&candidate, &path).unwrap();
        assert!(!report.is_valid());
        // ...but the explicit trust reset records it under a NEW epoch.
        let record =
            crate::policy::migrate_registry(&path, &crate::policy::revision_state_path_for(&path))
                .unwrap();
        assert_ne!(record.epoch, epoch_before);
        let gen_a2 = gate.policy_snapshot(&identity).unwrap();
        // Same content, same revision, same startup globals - and still not
        // the policy the original approval was bound to.
        assert_eq!(gen_a2.revision, gen_a.revision);
        assert_ne!(gen_a2.digest, gen_a.digest);
        assert_ne!(gen_a2.digest, gen_b.digest);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn concurrent_same_revision_installs_cannot_both_be_accepted() {
        let (gate, path, registry, _, identity) = gate_with_registry_file("race");
        gate.policy_snapshot(&identity).unwrap();
        // Two installers both advance 0 -> 1 with different content. The
        // install lock and the monotonic revision rule mean exactly one
        // commits; the loser must re-install at revision 2.
        let mut first = registry.clone();
        first.revision = 1;
        first.model_allowlist.push("first".into());
        let mut second = registry.clone();
        second.revision = 1;
        second.model_allowlist.push("second".into());
        let candidate_a = path.parent().unwrap().join("candidate-a.yaml");
        let candidate_b = path.parent().unwrap().join("candidate-b.yaml");
        std::fs::write(&candidate_a, serde_yaml::to_string(&first).unwrap()).unwrap();
        std::fs::write(&candidate_b, serde_yaml::to_string(&second).unwrap()).unwrap();
        let live = path.clone();
        let (a, b) = (candidate_a.clone(), candidate_b.clone());
        let run = move |candidate: std::path::PathBuf, live: std::path::PathBuf| {
            crate::policy::install_registry(&candidate, &live)
                .map(|report| report.is_valid())
                .unwrap_or(false)
        };
        let live_b = live.clone();
        let handle = std::thread::spawn(move || run(b, live_b));
        let first_won = run(a, live.clone());
        let second_won = handle.join().unwrap();
        assert_ne!(first_won, second_won, "exactly one installer commits");
        // The gate accepts exactly the generation that committed.
        let snapshot = gate.policy_snapshot(&identity).unwrap();
        assert_eq!(snapshot.revision, 1);
        // The loser re-installs at revision 2 and the gate accepts it.
        let mut retry = if second_won { first } else { second };
        retry.revision = 2;
        std::fs::write(&candidate_a, serde_yaml::to_string(&retry).unwrap()).unwrap();
        let report = crate::policy::install_registry(&candidate_a, &live).unwrap();
        assert!(report.is_valid(), "errors: {:?}", report.errors);
        let snapshot = gate.policy_snapshot(&identity).unwrap();
        assert_eq!(snapshot.revision, 2);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
