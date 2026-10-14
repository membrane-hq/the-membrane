use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IacVerifyError {
    #[error("IAC missing signature")]
    MissingSignature,
    #[error("invalid signature hex: {0}")]
    InvalidSignatureHex(String),
    #[error("signature verification failed")]
    InvalidSignature,
    #[error("canonical JSON error: {0}")]
    Canonical(#[from] crate::canonical::CanonicalError),
    #[error("invalid signer pubkey: {0}")]
    InvalidSignerPubkey(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentAuthorizationCredential {
    pub version: String,
    pub scope_id: String,
    /// Operator-signed caller key. None remains parseable but cannot enter production.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_pubkey: Option<String>,
    pub permitted_channels: Vec<String>,
    pub model_allowlist: Vec<String>,
    /// Tools this credential authorizes (e.g. `jira.comment`). Empty = no tools.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_allowlist: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoder_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stimulation_policy: Option<String>,
    pub context_merkle_bound: String,
    pub forbidden_exports: Vec<String>,
    pub valid_until: i64,
    pub parent_cp_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignableIac {
    pub version: String,
    pub scope_id: String,
    /// Operator-signed caller key. None remains parseable but cannot enter production.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_pubkey: Option<String>,
    pub permitted_channels: Vec<String>,
    pub model_allowlist: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_allowlist: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoder_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stimulation_policy: Option<String>,
    pub context_merkle_bound: String,
    pub forbidden_exports: Vec<String>,
    pub valid_until: i64,
    pub parent_cp_hash: String,
}

impl IntentAuthorizationCredential {
    pub const SCHEMA_VERSION: &str = "0.9.14";

    pub fn signable_view(&self) -> SignableIac {
        SignableIac {
            version: self.version.clone(),
            scope_id: self.scope_id.clone(),
            caller_pubkey: self.caller_pubkey.clone(),
            permitted_channels: self.permitted_channels.clone(),
            model_allowlist: self.model_allowlist.clone(),
            tool_allowlist: self.tool_allowlist.clone(),
            decoder_version: self.decoder_version.clone(),
            stimulation_policy: self.stimulation_policy.clone(),
            context_merkle_bound: self.context_merkle_bound.clone(),
            forbidden_exports: self.forbidden_exports.clone(),
            valid_until: self.valid_until,
            parent_cp_hash: self.parent_cp_hash.clone(),
        }
    }

    pub fn hash_hex(&self) -> Result<String, crate::canonical::CanonicalError> {
        let bytes = crate::canonical::canonical_json_bytes(&self.signable_view())?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }

    pub fn is_valid_at(&self, now: i64) -> bool {
        self.valid_until >= now
    }

    pub fn permits_channel(&self, channel: &str) -> bool {
        self.permitted_channels.iter().any(|c| c == channel)
    }

    pub fn model_allowed(&self, model_id: &str) -> bool {
        self.model_allowlist.iter().any(|m| m == model_id)
    }

    pub fn tool_allowed(&self, tool_id: &str) -> bool {
        self.tool_allowlist.iter().any(|t| t == tool_id)
    }

    /// Build an unsigned session-scoped IAC (caller signs with `sign()`).
    pub fn new_session(
        scope_id: impl Into<String>,
        model_id: impl Into<String>,
        parent_cp_hash: impl Into<String>,
        valid_until: i64,
        permitted_channels: Vec<String>,
        forbidden_exports: Vec<String>,
    ) -> Self {
        Self::new_session_with_tools(
            scope_id,
            model_id,
            parent_cp_hash,
            valid_until,
            permitted_channels,
            forbidden_exports,
            Vec::new(),
        )
    }

    /// Session IAC with an explicit tool allowlist (agent tool scopes).
    pub fn new_session_with_tools(
        scope_id: impl Into<String>,
        model_id: impl Into<String>,
        parent_cp_hash: impl Into<String>,
        valid_until: i64,
        permitted_channels: Vec<String>,
        forbidden_exports: Vec<String>,
        tool_allowlist: Vec<String>,
    ) -> Self {
        Self {
            version: Self::SCHEMA_VERSION.to_string(),
            scope_id: scope_id.into(),
            caller_pubkey: None,
            permitted_channels,
            model_allowlist: vec![model_id.into()],
            tool_allowlist,
            decoder_version: None,
            stimulation_policy: None,
            context_merkle_bound: "f".repeat(64),
            forbidden_exports,
            valid_until,
            parent_cp_hash: parent_cp_hash.into(),
            signature: None,
        }
    }

    /// Sign the IAC with the subject's Nostr key (same digest binding as MembraneEvent).
    pub fn sign(&mut self, keys: &nostr::Keys) -> Result<(), IacVerifyError> {
        let bytes = crate::canonical::canonical_json_bytes(&self.signable_view())?;
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        let message = nostr::secp256k1::Message::from_digest(digest);
        let sig = keys.sign_schnorr(&message);
        self.signature = Some(hex::encode(sig.serialize()));
        Ok(())
    }

    /// Verify Schnorr signature over canonical signable fields.
    pub fn verify_signature(&self, expected_signer_pubkey_hex: &str) -> Result<(), IacVerifyError> {
        let sig_hex = self
            .signature
            .as_ref()
            .ok_or(IacVerifyError::MissingSignature)?;
        let sig_bytes =
            hex::decode(sig_hex).map_err(|e| IacVerifyError::InvalidSignatureHex(e.to_string()))?;
        if sig_bytes.len() != 64 {
            return Err(IacVerifyError::InvalidSignatureHex(format!(
                "expected 64 bytes, got {}",
                sig_bytes.len()
            )));
        }

        let pubkey = nostr::PublicKey::from_hex(expected_signer_pubkey_hex)
            .map_err(|e| IacVerifyError::InvalidSignerPubkey(e.to_string()))?;

        let bytes = crate::canonical::canonical_json_bytes(&self.signable_view())?;
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        let message = nostr::secp256k1::Message::from_digest(digest);
        let sig = nostr::secp256k1::schnorr::Signature::from_slice(&sig_bytes)
            .map_err(|e| IacVerifyError::InvalidSignatureHex(e.to_string()))?;

        let secp = nostr::secp256k1::Secp256k1::verification_only();
        let xonly = pubkey
            .xonly()
            .map_err(|e| IacVerifyError::InvalidSignerPubkey(e.to_string()))?;
        secp.verify_schnorr(&sig, &message, &xonly)
            .map_err(|_| IacVerifyError::InvalidSignature)
    }
}

/// Longest lifetime a re-issued IAC may be given.
pub const MAX_REISSUE_TTL_SECS: i64 = 7 * 24 * 3600;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ReissueError {
    #[error("previous IAC is not signed by the operator key: {0}")]
    PreviousNotOperatorSigned(String),
    #[error("ttl must be between 1 and {MAX_REISSUE_TTL_SECS} seconds")]
    BadTtl,
    #[error(
        "`{0}` is not a plain identifier; wildcards, spaces and control characters are refused"
    )]
    UnsafeIdentifier(String),
    #[error("caller key mismatch: the previous IAC is bound to a different caller")]
    CallerMismatch,
    #[error("a caller public key is required; an unbound IAC cannot enter production")]
    CallerRequired,
}

/// Explicit operator input for a re-issue. Anything not listed is copied
/// unchanged from the previous IAC. Additions are narrow and named; there is no
/// way to remove a forbidden export or to widen by pattern.
#[derive(Debug, Clone, Default)]
pub struct ReissueRequest {
    pub now: i64,
    pub ttl_secs: i64,
    pub parent_cp_hash: String,
    /// Required when the previous IAC has no caller binding; must match when it has one.
    pub caller_pubkey: Option<String>,
    pub add_models: Vec<String>,
    pub add_tools: Vec<String>,
    pub add_channels: Vec<String>,
}

/// One difference between the previous and the re-issued IAC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReissueChange {
    pub field: &'static str,
    pub from: String,
    pub to: String,
}

fn plain_identifier(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 128
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':' | '/'))
        && !v.contains("..")
}

impl IntentAuthorizationCredential {
    /// Build an unsigned successor of `self`. The previous IAC must verify against
    /// `operator_pubkey_hex` (a foreign or tampered credential is never carried
    /// forward), even if it has expired. Scope, models, tools, channels, export
    /// restrictions and context bound are copied; only `valid_until`,
    /// `parent_cp_hash` and explicitly named additions differ. The caller signs
    /// the result: re-issue is always an operator act, never automatic.
    pub fn reissue(
        &self,
        operator_pubkey_hex: &str,
        req: &ReissueRequest,
    ) -> Result<(Self, Vec<ReissueChange>), ReissueError> {
        self.verify_signature(operator_pubkey_hex)
            .map_err(|e| ReissueError::PreviousNotOperatorSigned(e.to_string()))?;
        if req.ttl_secs < 1 || req.ttl_secs > MAX_REISSUE_TTL_SECS {
            return Err(ReissueError::BadTtl);
        }
        for v in req
            .add_models
            .iter()
            .chain(&req.add_tools)
            .chain(&req.add_channels)
        {
            if !plain_identifier(v) {
                return Err(ReissueError::UnsafeIdentifier(v.chars().take(40).collect()));
            }
        }
        let caller = match (&self.caller_pubkey, &req.caller_pubkey) {
            (Some(old), Some(new)) if !old.eq_ignore_ascii_case(new) => {
                return Err(ReissueError::CallerMismatch)
            }
            (Some(old), _) => old.clone(),
            (None, Some(new)) => new.to_ascii_lowercase(),
            (None, None) => return Err(ReissueError::CallerRequired),
        };

        let mut next = self.clone();
        next.signature = None;
        next.caller_pubkey = Some(caller);
        next.valid_until = req.now + req.ttl_secs;
        next.parent_cp_hash = req.parent_cp_hash.clone();

        let mut changes = Vec::new();
        if self.caller_pubkey.is_none() {
            changes.push(ReissueChange {
                field: "caller_pubkey",
                from: "(none)".into(),
                to: next.caller_pubkey.clone().unwrap_or_default(),
            });
        }
        changes.push(ReissueChange {
            field: "valid_until",
            from: self.valid_until.to_string(),
            to: next.valid_until.to_string(),
        });
        if self.parent_cp_hash != next.parent_cp_hash {
            changes.push(ReissueChange {
                field: "parent_cp_hash",
                from: self.parent_cp_hash.clone(),
                to: next.parent_cp_hash.clone(),
            });
        }
        let mut add = |field: &'static str, list: &mut Vec<String>, extra: &[String]| {
            for v in extra {
                if !list.contains(v) {
                    list.push(v.clone());
                    changes.push(ReissueChange {
                        field,
                        from: "(absent)".into(),
                        to: v.clone(),
                    });
                }
            }
        };
        add(
            "model_allowlist",
            &mut next.model_allowlist,
            &req.add_models,
        );
        add("tool_allowlist", &mut next.tool_allowlist, &req.add_tools);
        add(
            "permitted_channels",
            &mut next.permitted_channels,
            &req.add_channels,
        );
        Ok((next, changes))
    }
}

#[cfg(feature = "ots")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollupBundle {
    pub version: String,
    pub subject_pubkey: String,
    pub period_start: i64,
    pub period_end: i64,
    pub cp_chain_root: String,
    pub last_bus_root: String,
    pub last_cp_hash: String,
}

#[cfg(feature = "ots")]
impl RollupBundle {
    pub const SCHEMA_VERSION: &str = "0.9.14";
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::Keys;

    fn sample_iac() -> IntentAuthorizationCredential {
        IntentAuthorizationCredential {
            version: IntentAuthorizationCredential::SCHEMA_VERSION.to_string(),
            caller_pubkey: None,
            scope_id: "test-scope".into(),
            permitted_channels: vec!["local-llm".into()],
            model_allowlist: vec!["demo".into()],
            tool_allowlist: vec!["jira.comment".into()],
            decoder_version: None,
            stimulation_policy: None,
            context_merkle_bound: "f".repeat(64),
            forbidden_exports: vec!["cloud-telemetry".into()],
            valid_until: 4_102_444_800,
            parent_cp_hash: "0".repeat(64),
            signature: None,
        }
    }

    #[test]
    fn tool_allowlist_bound_in_signature() {
        let keys = Keys::generate();
        let mut iac = sample_iac();
        iac.sign(&keys).unwrap();
        iac.tool_allowlist.push("github.merge".into());
        assert!(iac.verify_signature(&keys.public_key().to_hex()).is_err());
    }

    #[test]
    fn iac_sign_and_verify_roundtrip() {
        let keys = Keys::generate();
        let mut iac = sample_iac();
        iac.sign(&keys).unwrap();
        iac.verify_signature(&keys.public_key().to_hex()).unwrap();
    }

    #[test]
    fn iac_rejects_tampered_payload() {
        let keys = Keys::generate();
        let mut iac = sample_iac();
        iac.sign(&keys).unwrap();
        iac.scope_id = "tampered".into();
        assert!(iac.verify_signature(&keys.public_key().to_hex()).is_err());
    }

    #[test]
    fn iac_rejects_missing_signature() {
        let iac = sample_iac();
        assert!(matches!(
            iac.verify_signature(&Keys::generate().public_key().to_hex()),
            Err(IacVerifyError::MissingSignature)
        ));
    }

    fn signed_with_caller(keys: &Keys) -> IntentAuthorizationCredential {
        let mut iac = sample_iac();
        iac.caller_pubkey = Some("a".repeat(64));
        iac.valid_until = 100;
        iac.sign(keys).unwrap();
        iac
    }

    fn req() -> ReissueRequest {
        ReissueRequest {
            now: 1_000,
            ttl_secs: 3600,
            parent_cp_hash: "1".repeat(64),
            ..Default::default()
        }
    }

    #[test]
    fn reissue_changes_only_expiry_and_chain_head() {
        let keys = Keys::generate();
        let old = signed_with_caller(&keys);
        let (mut next, changes) = old.reissue(&keys.public_key().to_hex(), &req()).unwrap();
        assert!(next.signature.is_none());
        assert_eq!(next.valid_until, 4_600);
        assert_eq!(next.model_allowlist, old.model_allowlist);
        assert_eq!(next.tool_allowlist, old.tool_allowlist);
        assert_eq!(next.permitted_channels, old.permitted_channels);
        assert_eq!(next.forbidden_exports, old.forbidden_exports);
        assert_eq!(next.caller_pubkey, old.caller_pubkey);
        let fields: Vec<_> = changes.iter().map(|c| c.field).collect();
        assert_eq!(fields, vec!["valid_until", "parent_cp_hash"]);
        next.sign(&keys).unwrap();
        next.verify_signature(&keys.public_key().to_hex()).unwrap();
    }

    #[test]
    fn reissue_refuses_foreign_or_unsigned_previous() {
        let keys = Keys::generate();
        let old = signed_with_caller(&keys);
        let other = Keys::generate().public_key().to_hex();
        assert!(matches!(
            old.reissue(&other, &req()),
            Err(ReissueError::PreviousNotOperatorSigned(_))
        ));
        let mut unsigned = old.clone();
        unsigned.signature = None;
        assert!(unsigned
            .reissue(&keys.public_key().to_hex(), &req())
            .is_err());
        let mut tampered = old;
        tampered.tool_allowlist.push("github.merge".into());
        assert!(tampered
            .reissue(&keys.public_key().to_hex(), &req())
            .is_err());
    }

    #[test]
    fn reissue_additions_are_explicit_and_recorded() {
        let keys = Keys::generate();
        let old = signed_with_caller(&keys);
        let mut r = req();
        r.add_tools = vec!["github.comment".into(), "jira.comment".into()];
        let (next, changes) = old.reissue(&keys.public_key().to_hex(), &r).unwrap();
        assert_eq!(next.tool_allowlist, vec!["jira.comment", "github.comment"]);
        let added: Vec<_> = changes
            .iter()
            .filter(|c| c.field == "tool_allowlist")
            .collect();
        assert_eq!(added.len(), 1);
        assert_eq!(added[0].to, "github.comment");
    }

    #[test]
    fn reissue_refuses_wildcards_bad_ttl_and_caller_problems() {
        let keys = Keys::generate();
        let pk = keys.public_key().to_hex();
        let old = signed_with_caller(&keys);
        for bad in ["*", "github.*x y", "", "a/../b", "tool\nx"] {
            let mut r = req();
            r.add_tools = vec![bad.into()];
            assert!(matches!(
                old.reissue(&pk, &r),
                Err(ReissueError::UnsafeIdentifier(_))
            ));
        }
        for ttl in [0, -5, MAX_REISSUE_TTL_SECS + 1] {
            let mut r = req();
            r.ttl_secs = ttl;
            assert_eq!(old.reissue(&pk, &r).unwrap_err(), ReissueError::BadTtl);
        }
        let mut r = req();
        r.caller_pubkey = Some("b".repeat(64));
        assert_eq!(
            old.reissue(&pk, &r).unwrap_err(),
            ReissueError::CallerMismatch
        );

        let mut unbound = sample_iac();
        unbound.sign(&keys).unwrap();
        assert_eq!(
            unbound.reissue(&pk, &req()).unwrap_err(),
            ReissueError::CallerRequired
        );
        let mut r = req();
        r.caller_pubkey = Some("C".repeat(64));
        let (next, _) = unbound.reissue(&pk, &r).unwrap();
        assert_eq!(next.caller_pubkey, Some("c".repeat(64)));
    }

    #[test]
    fn reissue_works_on_expired_previous() {
        let keys = Keys::generate();
        let old = signed_with_caller(&keys);
        assert!(!old.is_valid_at(1_000));
        let (next, _) = old.reissue(&keys.public_key().to_hex(), &req()).unwrap();
        assert!(next.is_valid_at(1_000));
    }
}
