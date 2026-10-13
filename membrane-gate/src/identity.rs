//! Production-only identity enforcement. Demo credentials never bypass this path.
use crate::{ChannelRegistry, Gate, GateError};
use membrane_core::{caller::CallerProof, iac::IntentAuthorizationCredential};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityGrant {
    #[serde(default)]
    pub revoked: bool,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub permitted_channels: Vec<String>,
    #[serde(default)]
    pub model_allowlist: Vec<String>,
    #[serde(default)]
    pub tool_allowlist: Vec<String>,
    #[serde(default)]
    pub github_repo_allowlist: Vec<String>,
    /// Unix seconds. The grant is not usable before this time. Absent means no lower bound.
    #[serde(default)]
    pub not_before: Option<i64>,
    /// Unix seconds. The grant stops working at this time (exclusive). Absent means a
    /// standing grant with no expiry.
    #[serde(default)]
    pub expires_at: Option<i64>,
    /// Length of the window, counted from `not_before`: a number followed by `s`, `m`, `h` or
    /// `d` (for example `90m`, `24h`, `7d`). Requires `not_before` and excludes `expires_at`, so
    /// a registry file means the same thing whenever it is read.
    #[serde(default)]
    pub valid_for: Option<String>,
    /// Spend authority on the Routstr rail. Absent means this identity cannot spend.
    #[serde(default)]
    pub spend: Option<SpendGrant>,
}

/// Operator-granted spend scope: which shared budget this identity draws on and the
/// most one call may cost. Budgets are not resized in place: two grants naming the
/// same budget must state the same cap, or spending is denied until they agree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpendGrant {
    pub budget: String,
    pub budget_cap_msat: u64,
    pub per_call_ceiling_msat: u64,
}

/// Parse `valid_for` into seconds. Zero, unknown units and overflow are errors.
pub fn parse_duration_secs(raw: &str) -> Result<i64, String> {
    let raw = raw.trim();
    let split = raw.len().saturating_sub(1);
    if !raw.is_char_boundary(split) || split == 0 {
        return Err("expected a number followed by s, m, h or d".into());
    }
    let (num, unit) = raw.split_at(split);
    let unit_secs: i64 = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3_600,
        "d" => 86_400,
        _ => return Err("unit must be s, m, h or d".into()),
    };
    if !num.bytes().all(|b| b.is_ascii_digit()) {
        return Err("expected a whole number".into());
    }
    let n: i64 = num.parse().map_err(|_| "number out of range".to_string())?;
    let secs = n.checked_mul(unit_secs).ok_or("duration out of range")?;
    if secs <= 0 {
        return Err("duration must be positive".into());
    }
    Ok(secs)
}

impl IdentityGrant {
    /// The end of the window: `expires_at`, or `not_before + valid_for`. `None` means no expiry.
    /// Contradictory or malformed settings are an error, which callers treat as a denial.
    pub fn effective_expiry(&self) -> Result<Option<i64>, GateError> {
        let Some(raw) = self.valid_for.as_deref() else {
            return Ok(self.expires_at);
        };
        if self.expires_at.is_some() {
            return Err(GateError::GrantWindow(
                "invalid window: set expires_at or valid_for, not both".into(),
            ));
        }
        let from = self.not_before.ok_or_else(|| {
            GateError::GrantWindow("invalid window: valid_for requires not_before".into())
        })?;
        let secs = parse_duration_secs(raw)
            .map_err(|e| GateError::GrantWindow(format!("invalid valid_for: {e}")))?;
        from.checked_add(secs)
            .map(Some)
            .ok_or_else(|| GateError::GrantWindow("invalid window: out of range".into()))
    }
}
impl IdentityGrant {
    /// Fail-closed time box. Expired, not yet valid and contradictory windows all deny.
    pub fn check_window(&self, now: i64) -> Result<(), GateError> {
        let expiry = self.effective_expiry()?;
        if let (Some(from), Some(until)) = (self.not_before, expiry) {
            if until <= from {
                return Err(GateError::GrantWindow(
                    "invalid window: expires_at is not after not_before".into(),
                ));
            }
        }
        if self.not_before.is_some_and(|from| now < from) {
            return Err(GateError::GrantWindow("grant not yet valid".into()));
        }
        if expiry.is_some_and(|until| now >= until) {
            return Err(GateError::GrantWindow("grant expired".into()));
        }
        Ok(())
    }
}
impl Gate {
    /// Public, per-process challenge binds a proof to this gate lifetime.
    pub fn caller_audience(&self) -> String {
        format!("{}:{}", self.publisher_pubkey_hex(), self.caller_challenge)
    }

    pub fn authenticate_caller<T: Serialize>(
        &self,
        iac: &IntentAuthorizationCredential,
        proof: &CallerProof,
        path: &str,
        body: &T,
        now: i64,
    ) -> Result<String, GateError> {
        // Verify operator authority before trusting the bound caller key.
        self.validate_iac(Some(iac), now)?;
        if proof.timestamp > now
            || now.saturating_sub(proof.timestamp) > 60
            || proof.nonce.len() != 64
            || !proof.nonce.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(GateError::IdentityAuthentication(
                "expired, future or malformed proof".into(),
            ));
        }
        let identity = proof
            .verify(&self.caller_audience(), path, body, iac)
            .map_err(|e| GateError::IdentityAuthentication(e.to_string()))?;
        let mut replay = self
            .replay
            .lock()
            .map_err(|_| GateError::IdentityAuthentication("replay cache unavailable".into()))?;
        replay.retain(|_, issued| now.saturating_sub(*issued) <= 60);
        let key = format!("{identity}:{}", proof.nonce.to_ascii_lowercase());
        if replay.contains_key(&key) || replay.len() >= 10_000 {
            return Err(GateError::IdentityAuthentication(
                "replay or replay capacity exceeded".into(),
            ));
        }
        replay.insert(key, proof.timestamp);
        Ok(identity)
    }
    /// Expiry times of grants that are not revoked and have a window, read the same way
    /// authorization reads them. A grant with a malformed window is left out: it already
    /// denies every request.
    pub fn grant_expiries(&self) -> Result<Vec<(String, i64)>, GateError> {
        let live;
        let registry = if let Some(path) = &self.identity_registry_path {
            live = ChannelRegistry::load(path)
                .map_err(|e| GateError::IdentityGrant(format!("registry unavailable: {e}")))?;
            &live
        } else {
            &self.registry
        };
        Ok(registry
            .identities
            .iter()
            .filter(|(_, g)| !g.revoked)
            .filter_map(|(id, g)| match g.effective_expiry() {
                Ok(Some(until)) => Some((id.clone(), until)),
                _ => None,
            })
            .collect())
    }
    pub fn authorize_identity(
        &self,
        identity: &str,
        iac: &IntentAuthorizationCredential,
        model: &str,
        tool_repo: Option<(&str, &str)>,
    ) -> Result<(), GateError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            // A clock before 1970 cannot prove a grant is inside its window.
            .map_err(|_| GateError::GrantWindow("system clock unavailable".into()))?;
        self.authorize_identity_at(identity, iac, model, tool_repo, now)
    }
    /// Everything `authorize_identity` checks, plus a spend grant. Returns it so the
    /// caller never trusts a budget or limit supplied by the request.
    pub fn authorize_spend(
        &self,
        identity: &str,
        iac: &IntentAuthorizationCredential,
        model: &str,
    ) -> Result<SpendGrant, GateError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .map_err(|_| GateError::GrantWindow("system clock unavailable".into()))?;
        self.authorize_identity_at(identity, iac, model, None, now)?;
        let live;
        let registry = if let Some(path) = &self.identity_registry_path {
            live = ChannelRegistry::load(path)
                .map_err(|e| GateError::IdentityGrant(format!("registry unavailable: {e}")))?;
            &live
        } else {
            &self.registry
        };
        registry
            .identities
            .get(identity)
            .and_then(|g| g.spend.clone())
            .filter(|s| s.per_call_ceiling_msat > 0 && s.per_call_ceiling_msat <= s.budget_cap_msat)
            .ok_or_else(|| GateError::Spend("no valid spend grant for identity".into()))
    }
    pub fn authorize_identity_at(
        &self,
        identity: &str,
        iac: &IntentAuthorizationCredential,
        model: &str,
        tool_repo: Option<(&str, &str)>,
        now: i64,
    ) -> Result<(), GateError> {
        let live;
        let registry = if let Some(path) = &self.identity_registry_path {
            live = ChannelRegistry::load(path)
                .map_err(|e| GateError::IdentityGrant(format!("registry unavailable: {e}")))?;
            &live
        } else {
            &self.registry
        };
        let grant = registry
            .identities
            .get(identity)
            .ok_or_else(|| GateError::IdentityGrant("unknown identity".into()))?;
        if grant.revoked {
            return Err(GateError::IdentityGrant("revoked identity".into()));
        }
        grant.check_window(now)?;
        if !grant.scopes.contains(&iac.scope_id)
            || iac
                .permitted_channels
                .iter()
                .any(|c| !grant.permitted_channels.contains(c))
        {
            return Err(GateError::IdentityGrant(
                "scope or channel not granted".into(),
            ));
        }
        if !iac.model_allowed(model)
            || !registry.model_allowlist.iter().any(|m| m == model)
            || !grant.model_allowlist.iter().any(|m| m == model)
        {
            return Err(GateError::ModelDenied(model.into()));
        }
        if let Some((tool, repo)) = tool_repo {
            if !iac.tool_allowed(tool) || !grant.tool_allowlist.iter().any(|t| t == tool) {
                return Err(GateError::ToolDenied(tool.into()));
            }
            if !registry.github_repo_allowlist.iter().any(|r| r == repo)
                || !grant.github_repo_allowlist.iter().any(|r| r == repo)
            {
                return Err(GateError::RepoDenied(repo.into()));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use membrane_core::{BusPublisher, BusPublisherConfig};
    use nostr::Keys;
    fn fixture() -> (Gate, Keys, IntentAuthorizationCredential) {
        let operator = Keys::generate();
        let caller = Keys::generate();
        let mut iac = IntentAuthorizationCredential::new_session_with_tools(
            "s",
            "m",
            "0".repeat(64),
            500,
            vec!["local-llm".into()],
            vec![],
            vec!["github.comment".into()],
        );
        iac.caller_pubkey = Some(caller.public_key().to_hex());
        iac.sign(&operator).unwrap();
        let grant = IdentityGrant {
            revoked: false,
            scopes: vec!["s".into()],
            permitted_channels: vec!["local-llm".into()],
            model_allowlist: vec!["m".into()],
            tool_allowlist: vec!["github.comment".into()],
            github_repo_allowlist: vec!["a/b".into()],
            not_before: None,
            expires_at: None,
            valid_for: None,
            spend: None,
        };
        let registry = ChannelRegistry {
            identities: [(caller.public_key().to_hex(), grant)].into(),
            permitted_channels: vec!["local-llm".into()],
            forbidden_exports: vec![],
            model_allowlist: vec!["m".into()],
            delta_t_secs: 300,
            model_api_url: None,
            github_repo_allowlist: vec!["a/b".into()],
        };
        (
            Gate::new(
                registry,
                BusPublisher::new(BusPublisherConfig {
                    relay_url: "memory://identity".into(),
                    keys: operator,
                }),
            ),
            caller,
            iac,
        )
    }
    fn proof(gate: &Gate, caller: &Keys, iac: &IntentAuthorizationCredential) -> CallerProof {
        CallerProof::sign(
            caller,
            &gate.caller_audience(),
            "/v1/tools/invoke",
            &serde_json::json!({"tool":"github.comment"}),
            iac,
            100,
            Keys::generate().public_key().to_hex(),
        )
        .unwrap()
    }
    fn auth(
        g: &Gate,
        i: &IntentAuthorizationCredential,
        p: &CallerProof,
        now: i64,
    ) -> Result<String, GateError> {
        g.authenticate_caller(
            i,
            p,
            "/v1/tools/invoke",
            &serde_json::json!({"tool":"github.comment"}),
            now,
        )
    }
    #[test]
    fn valid_distinct_caller_and_operator_then_replay_denied() {
        let (g, c, i) = fixture();
        let p = proof(&g, &c, &i);
        let id = auth(&g, &i, &p, 100).unwrap();
        assert_ne!(id, g.publisher_pubkey_hex());
        g.authorize_identity(&id, &i, "m", Some(("github.comment", "a/b")))
            .unwrap();
        assert!(auth(&g, &i, &p, 100).is_err());
    }
    #[test]
    fn wrong_key_tampered_iac_body_path_and_audience_denied() {
        let (g, c, i) = fixture();
        let body = serde_json::json!({"tool":"github.comment"});
        assert!(auth(&g, &i, &proof(&g, &Keys::generate(), &i), 100).is_err());
        let mut forged = i.clone();
        forged.caller_pubkey = Some(Keys::generate().public_key().to_hex());
        assert!(auth(&g, &forged, &proof(&g, &c, &i), 100).is_err());
        let p = proof(&g, &c, &i);
        assert!(g
            .authenticate_caller(&i, &p, "/v1/chat/completions", &body, 100)
            .is_err());
        assert!(g
            .authenticate_caller(
                &i,
                &p,
                "/v1/tools/invoke",
                &serde_json::json!({"tool":"github.merge"}),
                100
            )
            .is_err());
        let foreign = CallerProof::sign(
            &c,
            "wrong-gate",
            "/v1/tools/invoke",
            &body,
            &i,
            100,
            "a".repeat(64),
        )
        .unwrap();
        assert!(auth(&g, &i, &foreign, 100).is_err());
    }
    #[test]
    fn stale_future_unbound_and_cache_failure_denied() {
        let (g, c, mut i) = fixture();
        let p = proof(&g, &c, &i);
        assert!(auth(&g, &i, &p, 161).is_err());
        assert!(auth(&g, &i, &p, 99).is_err());
        i.caller_pubkey = None;
        i.sign(g.publisher().keys()).unwrap();
        assert!(auth(&g, &i, &p, 100).is_err());
    }
    #[test]
    fn unknown_revoked_and_intersection_denied() {
        let (mut g, c, i) = fixture();
        let id = c.public_key().to_hex();
        assert!(g
            .authorize_identity(&Keys::generate().public_key().to_hex(), &i, "m", None)
            .is_err());
        assert!(g.authorize_identity(&id, &i, "other", None).is_err());
        assert!(g
            .authorize_identity(&id, &i, "m", Some(("github.merge", "a/b")))
            .is_err());
        assert!(g
            .authorize_identity(&id, &i, "m", Some(("github.comment", "a/c")))
            .is_err());
        let mut other_scope = i.clone();
        other_scope.scope_id = "other".into();
        assert!(g.authorize_identity(&id, &other_scope, "m", None).is_err());
        g.registry.identities.get_mut(&id).unwrap().revoked = true;
        assert!(g.authorize_identity(&id, &i, "m", None).is_err());
    }
    #[test]
    fn live_registry_revocation_and_broken_registry_fail_closed() {
        let (g, c, i) = fixture();
        let id = c.public_key().to_hex();
        let path = std::env::temp_dir().join(format!("membrane-{}.yaml", id));
        std::fs::write(&path, serde_yaml::to_string(g.registry()).unwrap()).unwrap();
        let g = g.with_identity_registry_path(path.clone());
        g.authorize_identity(&id, &i, "m", None).unwrap();
        let mut r = g.registry().clone();
        r.identities.get_mut(&id).unwrap().revoked = true;
        std::fs::write(&path, serde_yaml::to_string(&r).unwrap()).unwrap();
        assert!(g.authorize_identity(&id, &i, "m", None).is_err());
        std::fs::write(&path, "not: [valid").unwrap();
        assert!(g.authorize_identity(&id, &i, "m", None).is_err());
        std::fs::remove_file(path).unwrap();
        assert!(g.authorize_identity(&id, &i, "m", None).is_err());
    }
    #[test]
    fn old_gate_challenge_cannot_replay_after_restart() {
        let (g, c, i) = fixture();
        let p = proof(&g, &c, &i);
        let restarted = Gate::new(
            g.registry().clone(),
            BusPublisher::new(BusPublisherConfig {
                relay_url: "memory://restart".into(),
                keys: g.publisher().keys().clone(),
            }),
        );
        assert_ne!(g.caller_audience(), restarted.caller_audience());
        assert!(auth(&restarted, &i, &p, 100).is_err());
    }
    #[test]
    fn replay_capacity_and_poisoned_lock_fail_closed() {
        let (g, c, i) = fixture();
        g.replay
            .lock()
            .unwrap()
            .extend((0..10_000).map(|n| (format!("occupied-{n}"), 100)));
        assert!(auth(&g, &i, &proof(&g, &c, &i), 100).is_err());
        let g = std::sync::Arc::new(g);
        let other = g.clone();
        let _ = std::thread::spawn(move || {
            let _lock = other.replay.lock().unwrap();
            panic!("poison replay cache");
        })
        .join();
        assert!(auth(&g, &i, &proof(&g, &c, &i), 100).is_err());
    }
    #[test]
    fn simultaneous_replay_has_exactly_one_winner() {
        let (g, c, i) = fixture();
        let p = proof(&g, &c, &i);
        let g = std::sync::Arc::new(g);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let jobs: Vec<_> = (0..8)
            .map(|_| {
                let g = g.clone();
                let i = i.clone();
                let p = p.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    auth(&g, &i, &p, 100).is_ok()
                })
            })
            .collect();
        assert_eq!(
            jobs.into_iter()
                .filter(|j| j.thread().id() != std::thread::current().id())
                .map(|j| j.join().unwrap() as usize)
                .sum::<usize>(),
            1
        );
    }
    #[test]
    fn grant_window_is_enforced_and_fails_closed() {
        let (mut g, c, i) = fixture();
        let id = c.public_key().to_hex();
        let ok = |g: &Gate, now| g.authorize_identity_at(&id, &i, "m", None, now);
        // No window: a standing grant keeps working.
        ok(&g, 1_000_000).unwrap();
        g.registry.identities.get_mut(&id).unwrap().not_before = Some(1_000);
        g.registry.identities.get_mut(&id).unwrap().expires_at = Some(2_000);
        assert!(matches!(ok(&g, 999), Err(GateError::GrantWindow(_))));
        ok(&g, 1_000).unwrap();
        ok(&g, 1_999).unwrap();
        assert!(matches!(ok(&g, 2_000), Err(GateError::GrantWindow(_))));
        assert!(matches!(ok(&g, 9_999_999), Err(GateError::GrantWindow(_))));
        // Contradictory windows deny at every time.
        g.registry.identities.get_mut(&id).unwrap().not_before = Some(2_000);
        assert!(matches!(ok(&g, 1_500), Err(GateError::GrantWindow(_))));
        assert!(matches!(ok(&g, 2_500), Err(GateError::GrantWindow(_))));
    }
    #[test]
    fn expiry_cannot_widen_what_the_grant_allows() {
        let (mut g, c, i) = fixture();
        let id = c.public_key().to_hex();
        g.registry.identities.get_mut(&id).unwrap().expires_at = Some(2_000);
        // Inside the window the usual intersection still applies.
        assert!(matches!(
            g.authorize_identity_at(&id, &i, "other-model", None, 1_000),
            Err(GateError::ModelDenied(_))
        ));
    }
    #[test]
    fn registry_windows_parse_from_yaml_and_unknown_fields_still_fail() {
        let ok: IdentityGrant =
            serde_yaml::from_str("scopes: [s]\nnot_before: 10\nexpires_at: 20\n").unwrap();
        assert_eq!((ok.not_before, ok.expires_at), (Some(10), Some(20)));
        assert!(serde_yaml::from_str::<IdentityGrant>("expires: 20\n").is_err());
        assert!(serde_yaml::from_str::<IdentityGrant>("expires_at: soon\n").is_err());
    }
    fn grant_mut<'a>(g: &'a mut Gate, id: &str) -> &'a mut IdentityGrant {
        g.registry.identities.get_mut(id).unwrap()
    }
    #[test]
    fn duration_strings_parse_strictly() {
        assert_eq!(parse_duration_secs("90s"), Ok(90));
        assert_eq!(parse_duration_secs("90m"), Ok(5_400));
        assert_eq!(parse_duration_secs(" 24h "), Ok(86_400));
        assert_eq!(parse_duration_secs("7d"), Ok(604_800));
        for bad in [
            "",
            "h",
            "1",
            "0h",
            "-1h",
            "1.5h",
            "1w",
            "1 h",
            "h1",
            "+1h",
            "99999999999999999999d",
            "9223372036854775807d",
            "é",
        ] {
            assert!(parse_duration_secs(bad).is_err(), "{bad:?} should fail");
        }
    }
    #[test]
    fn relative_window_counts_from_not_before_and_fails_closed() {
        let (mut g, c, i) = fixture();
        let id = c.public_key().to_hex();
        grant_mut(&mut g, &id).not_before = Some(1_000);
        grant_mut(&mut g, &id).valid_for = Some("1h".into());
        let ok = |g: &Gate, now| g.authorize_identity_at(&id, &i, "m", None, now);
        assert!(matches!(ok(&g, 999), Err(GateError::GrantWindow(_))));
        ok(&g, 1_000).unwrap();
        ok(&g, 4_599).unwrap();
        assert!(matches!(ok(&g, 4_600), Err(GateError::GrantWindow(_))));
        // Both forms, a missing start, or a bad value deny at every time.
        grant_mut(&mut g, &id).expires_at = Some(9_000);
        assert!(matches!(ok(&g, 2_000), Err(GateError::GrantWindow(_))));
        grant_mut(&mut g, &id).expires_at = None;
        grant_mut(&mut g, &id).not_before = None;
        assert!(matches!(ok(&g, 2_000), Err(GateError::GrantWindow(_))));
        grant_mut(&mut g, &id).not_before = Some(1_000);
        grant_mut(&mut g, &id).valid_for = Some("soon".into());
        assert!(matches!(ok(&g, 2_000), Err(GateError::GrantWindow(_))));
        grant_mut(&mut g, &id).valid_for = Some("1d".into());
        grant_mut(&mut g, &id).not_before = Some(i64::MAX - 10);
        assert!(matches!(ok(&g, i64::MAX), Err(GateError::GrantWindow(_))));
    }
    #[test]
    fn grant_expiries_lists_windowed_unrevoked_grants_only() {
        let (mut g, c, _) = fixture();
        let id = c.public_key().to_hex();
        assert!(g.grant_expiries().unwrap().is_empty());
        g.registry.identities.get_mut(&id).unwrap().not_before = Some(100);
        g.registry.identities.get_mut(&id).unwrap().valid_for = Some("1h".into());
        assert_eq!(g.grant_expiries().unwrap(), vec![(id.clone(), 3_700)]);
        g.registry.identities.get_mut(&id).unwrap().revoked = true;
        assert!(g.grant_expiries().unwrap().is_empty());
    }
    #[test]
    fn valid_for_parses_from_yaml() {
        let g: IdentityGrant =
            serde_yaml::from_str("scopes: [s]\nnot_before: 10\nvalid_for: 2h\n").unwrap();
        assert_eq!(g.effective_expiry().unwrap(), Some(7_210));
    }
}
