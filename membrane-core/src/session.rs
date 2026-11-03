//! Router session chain state (RFA-lite) for §4.2.2.

use std::collections::BTreeMap;

use crate::event::{EventType, MembraneEvent, MembranePayload};
use crate::rollup::{cp_hash_hex, is_cp_event, GENESIS_CP_HASH};

/// Reasons carried in `membrane.alert.degraded` generic payloads.
pub const ALERT_REASON_SUBJECT_SEVER: &str = "subject_sever";
pub const ALERT_REASON_DELTA_T_EXCEEDED: &str = "delta_t_exceeded";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionChainState {
    pub last_cp_hash: String,
    pub last_event_id: Option<String>,
    pub session_nonce: u64,
    pub active_scope_id: Option<String>,
    /// Timestamp of the most recent `membrane.cp.router` for this subject.
    pub last_router_cp_at: Option<i64>,
    /// Scope blocked by sever or Δt staleness until a fresh IAC + new scope.
    pub degraded_scope_id: Option<String>,
    pub degraded_at: Option<i64>,
    pub degraded_reason: Option<String>,
    /// Scope-local counters and liveness; CP hashes remain one serialized operator chain.
    pub scopes: BTreeMap<String, (u64, Option<i64>)>,
    /// Never forget a severed scope when another scope is degraded.
    pub degraded_scopes: BTreeMap<String, (String, i64)>,
}

impl SessionChainState {
    pub fn genesis() -> Self {
        Self {
            last_cp_hash: GENESIS_CP_HASH.to_string(),
            last_event_id: None,
            session_nonce: 0,
            active_scope_id: None,
            last_router_cp_at: None,
            degraded_scope_id: None,
            degraded_at: None,
            degraded_reason: None,
            scopes: BTreeMap::new(),
            degraded_scopes: BTreeMap::new(),
        }
    }

    pub fn from_bus_events(events: &[MembraneEvent], subject_pubkey: &str) -> Self {
        let mut state = Self::genesis();
        let mut last_router_nonce = 0u64;

        for event in events {
            if event.subject_pubkey != subject_pubkey {
                continue;
            }
            if is_cp_event(event.event_type) {
                if let Ok(hash) = cp_hash_hex(event) {
                    state.last_cp_hash = hash;
                }
            }
            if event.event_type == EventType::CpRouter {
                state.last_router_cp_at = Some(event.timestamp);
                if let MembranePayload::Router(payload) = &event.payload {
                    last_router_nonce = payload.session_nonce;
                    if let Some(scope) = &payload.scope_id {
                        state.scopes.insert(
                            scope.clone(),
                            (payload.session_nonce, Some(event.timestamp)),
                        );
                        state.active_scope_id = Some(scope.clone());
                    }
                }
            }
            if event.event_type == EventType::AlertDegraded {
                let (reason, scope_id) = alert_degraded_fields(&event.payload);
                if let Some(scope) = &scope_id {
                    state.degraded_scopes.insert(
                        scope.clone(),
                        (
                            reason.clone().unwrap_or_else(|| "degraded".into()),
                            event.timestamp,
                        ),
                    );
                }
                state.degraded_scope_id = scope_id;
                state.degraded_at = Some(event.timestamp);
                state.degraded_reason = reason;
            }
        }

        state.session_nonce = last_router_nonce;
        state
    }

    pub fn begin_scope(&mut self, scope_id: &str) -> bool {
        if self.active_scope_id.as_deref() == Some(scope_id) {
            return false;
        }
        self.active_scope_id = Some(scope_id.to_string());
        let (nonce, at) = self.scopes.get(scope_id).copied().unwrap_or((0, None));
        self.session_nonce = nonce;
        self.last_router_cp_at = at;
        true
    }

    pub fn next_parent_cp_hash(&self, iac_parent_cp_hash: &str) -> String {
        if self.last_cp_hash == GENESIS_CP_HASH {
            iac_parent_cp_hash.to_string()
        } else {
            self.last_cp_hash.clone()
        }
    }

    pub fn next_session_nonce(&mut self) -> u64 {
        self.session_nonce += 1;
        self.session_nonce
    }

    pub fn record_cp(&mut self, cp_hash: String, bus_event_id: Option<String>, at: i64) {
        self.last_cp_hash = cp_hash;
        self.last_event_id = bus_event_id;
        self.last_router_cp_at = Some(at);
        if let Some(scope) = &self.active_scope_id {
            self.scopes
                .insert(scope.clone(), (self.session_nonce, Some(at)));
        }
    }

    pub fn mark_degraded(&mut self, scope_id: &str, reason: &str, at: i64) {
        self.degraded_scopes
            .insert(scope_id.to_string(), (reason.to_string(), at));
        self.degraded_scope_id = Some(scope_id.to_string());
        self.degraded_at = Some(at);
        self.degraded_reason = Some(reason.to_string());
    }

    pub fn clear_degraded_for_scope(&mut self, scope_id: &str) {
        self.degraded_scopes.remove(scope_id);
        if self.degraded_scope_id.as_deref() == Some(scope_id) {
            self.degraded_scope_id = None;
            self.degraded_at = None;
            self.degraded_reason = None;
        }
    }

    pub fn last_router_cp_age_secs(&self, now: i64) -> Option<i64> {
        self.last_router_cp_at.map(|ts| now.saturating_sub(ts))
    }

    pub fn is_scope_degraded(&self, scope_id: &str) -> bool {
        self.degraded_scopes.contains_key(scope_id)
            || self.degraded_scope_id.as_deref() == Some(scope_id)
    }

    pub fn scope_router_cp_age_secs(&self, scope_id: &str, now: i64) -> Option<i64> {
        if self.active_scope_id.as_deref() == Some(scope_id) {
            self.last_router_cp_age_secs(now)
        } else {
            self.scopes
                .get(scope_id)
                .and_then(|(_, at)| *at)
                .map(|at| now.saturating_sub(at))
        }
    }

    /// True when an active router CP chain exists and the last CP is older than Δt.
    pub fn is_router_stale(&self, now: i64, delta_t_secs: u64) -> bool {
        let Some(last) = self.last_router_cp_at else {
            return false;
        };
        now.saturating_sub(last) > delta_t_secs as i64
    }

    pub fn validate_iac_anchor(
        &self,
        iac_parent_cp_hash: &str,
        new_scope: bool,
    ) -> Result<(), String> {
        if !new_scope {
            return Ok(());
        }
        if iac_parent_cp_hash == GENESIS_CP_HASH {
            if self.last_cp_hash != GENESIS_CP_HASH {
                return Err(
                    "session IAC must set parent_cp_hash to current chain head (use `iac issue`)"
                        .into(),
                );
            }
            return Ok(());
        }
        if iac_parent_cp_hash != self.last_cp_hash {
            return Err(format!(
                "IAC parent_cp_hash does not match chain head (expected {})",
                self.last_cp_hash
            ));
        }
        Ok(())
    }
}

impl Default for SessionChainState {
    fn default() -> Self {
        Self::genesis()
    }
}

pub fn alert_degraded_fields(payload: &MembranePayload) -> (Option<String>, Option<String>) {
    let MembranePayload::Generic(value) = payload else {
        return (None, None);
    };
    let reason = value
        .get("reason")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let scope_id = value
        .get("scope_id")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    (reason, scope_id)
}

pub fn alert_degraded_payload(
    reason: &str,
    scope_id: &str,
    last_cp_age_secs: Option<i64>,
    delta_t_secs: u64,
) -> MembranePayload {
    MembranePayload::Generic(serde_json::json!({
        "reason": reason,
        "scope_id": scope_id,
        "last_cp_age_secs": last_cp_age_secs,
        "delta_t_secs": delta_t_secs,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{EventType, MembranePayload, RouterSessionPayload};

    fn router_event(ts: i64, nonce: u64, subject: &str) -> MembraneEvent {
        MembraneEvent::new(
            EventType::CpRouter,
            subject,
            GENESIS_CP_HASH,
            ts,
            MembranePayload::Router(RouterSessionPayload {
                model_id: "demo".into(),
                context_merkle_root: "bb".repeat(32),
                session_nonce: nonce,
                parent_cp_hash: GENESIS_CP_HASH.into(),
                iac_hash: "dd".repeat(32),
                scope_id: None,
                tool_id: None,
                policy_digest: None,
                policy_revision: None,
            }),
        )
    }

    fn degraded_event(ts: i64, subject: &str, scope: &str, reason: &str) -> MembraneEvent {
        MembraneEvent::new(
            EventType::AlertDegraded,
            subject,
            GENESIS_CP_HASH,
            ts,
            alert_degraded_payload(reason, scope, Some(400), 300),
        )
    }

    #[test]
    fn interleaved_scopes_keep_nonce_age_and_all_severs() {
        let mut state = SessionChainState::genesis();
        state.begin_scope("a");
        state.next_session_nonce();
        state.record_cp("aa".repeat(32), None, 100);
        state.begin_scope("b");
        assert_eq!(state.last_router_cp_at, None);
        state.next_session_nonce();
        state.record_cp("bb".repeat(32), None, 500);
        assert_eq!(state.scope_router_cp_age_secs("a", 600), Some(500));
        state.begin_scope("a");
        assert_eq!(state.next_session_nonce(), 2);
        assert_eq!(state.last_router_cp_at, Some(100));
        state.mark_degraded("a", ALERT_REASON_SUBJECT_SEVER, 601);
        state.mark_degraded("b", ALERT_REASON_SUBJECT_SEVER, 602);
        assert!(state.is_scope_degraded("a"));
        assert!(state.is_scope_degraded("b"));
    }

    #[test]
    fn restart_restores_active_scope_and_all_severs() {
        let subject = "aa".repeat(32);
        let mut cp = router_event(100, 5, &subject);
        if let MembranePayload::Router(payload) = &mut cp.payload {
            payload.scope_id = Some("a".into());
        }
        let events = vec![
            cp,
            degraded_event(110, &subject, "a", ALERT_REASON_SUBJECT_SEVER),
            degraded_event(120, &subject, "b", ALERT_REASON_SUBJECT_SEVER),
        ];
        let state = SessionChainState::from_bus_events(&events, &subject);
        assert_eq!(state.active_scope_id.as_deref(), Some("a"));
        assert_eq!(state.scopes["a"].0, 5);
        assert!(state.is_scope_degraded("a"));
        assert!(state.is_scope_degraded("b"));
    }
    #[test]
    fn chains_parent_cp_hash_after_first_turn() {
        let mut state = SessionChainState::genesis();
        assert_eq!(state.next_parent_cp_hash(GENESIS_CP_HASH), GENESIS_CP_HASH);

        state.record_cp("aa".repeat(32), Some("event1".into()), 100);
        assert_eq!(state.next_parent_cp_hash(GENESIS_CP_HASH), "aa".repeat(32));
    }

    #[test]
    fn scope_change_resets_nonce() {
        let mut state = SessionChainState::genesis();
        state.session_nonce = 5;
        state.active_scope_id = Some("old".into());
        assert!(state.begin_scope("new"));
        assert_eq!(state.session_nonce, 0);
        assert!(!state.begin_scope("new"));
    }

    #[test]
    fn bootstrap_from_bus_events() {
        let subject = "aa".repeat(32);
        let events = vec![
            router_event(100, 1, &subject),
            router_event(101, 2, &subject),
        ];
        let state = SessionChainState::from_bus_events(&events, &subject);
        assert_ne!(state.last_cp_hash, GENESIS_CP_HASH);
        assert_eq!(state.session_nonce, 2);
        assert_eq!(state.last_router_cp_at, Some(101));
    }

    #[test]
    fn bootstrap_picks_up_degraded_alert() {
        let subject = "aa".repeat(32);
        let events = vec![
            router_event(100, 1, &subject),
            degraded_event(200, &subject, "scope-a", ALERT_REASON_SUBJECT_SEVER),
        ];
        let state = SessionChainState::from_bus_events(&events, &subject);
        assert!(state.is_scope_degraded("scope-a"));
        assert_eq!(
            state.degraded_reason.as_deref(),
            Some(ALERT_REASON_SUBJECT_SEVER)
        );
    }

    #[test]
    fn router_stale_after_delta_t() {
        let mut state = SessionChainState::genesis();
        state.last_router_cp_at = Some(1_000);
        assert!(!state.is_router_stale(1_200, 300));
        assert!(state.is_router_stale(1_301, 300));
    }

    #[test]
    fn no_router_cp_is_not_stale() {
        let state = SessionChainState::genesis();
        assert!(!state.is_router_stale(9_999, 300));
    }

    #[test]
    fn fresh_scope_clears_degraded() {
        let mut state = SessionChainState::genesis();
        state.mark_degraded("old-scope", ALERT_REASON_SUBJECT_SEVER, 100);
        state.clear_degraded_for_scope("old-scope");
        assert!(!state.is_scope_degraded("old-scope"));
    }
}
