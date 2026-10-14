//! Proof of possession for an operator-signed IAC. Not a second authorization credential.
use crate::{
    canonical::canonical_json_bytes,
    iac::{IacVerifyError, IntentAuthorizationCredential},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallerProof {
    pub timestamp: i64,
    pub nonce: String,
    pub signature: String,
}
impl CallerProof {
    fn digest<T: Serialize>(
        &self,
        audience: &str,
        path: &str,
        body: &T,
        iac: &IntentAuthorizationCredential,
    ) -> Result<[u8; 32], IacVerifyError> {
        let payload = serde_json::json!({
            "domain": "membrane/caller-proof/v1", "audience": audience,
            "method": "POST", "path": path, "body": body,
            "iac_hash": iac.hash_hex()?, "timestamp": self.timestamp, "nonce": self.nonce,
        });
        Ok(Sha256::digest(canonical_json_bytes(&payload)?).into())
    }
    pub fn sign<T: Serialize>(
        keys: &nostr::Keys,
        audience: &str,
        path: &str,
        body: &T,
        iac: &IntentAuthorizationCredential,
        timestamp: i64,
        nonce: String,
    ) -> Result<Self, IacVerifyError> {
        let mut proof = Self {
            timestamp,
            nonce,
            signature: String::new(),
        };
        let msg = nostr::secp256k1::Message::from_digest(proof.digest(audience, path, body, iac)?);
        proof.signature = hex::encode(keys.sign_schnorr(&msg).serialize());
        Ok(proof)
    }
    pub fn verify<T: Serialize>(
        &self,
        audience: &str,
        path: &str,
        body: &T,
        iac: &IntentAuthorizationCredential,
    ) -> Result<String, IacVerifyError> {
        let key = iac
            .caller_pubkey
            .as_deref()
            .ok_or(IacVerifyError::InvalidSignerPubkey(
                "missing caller binding".into(),
            ))?;
        // Canonical lowercase hex is the registry identity, not a caller-selected alias.
        if key.len() != 64
            || !key
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(IacVerifyError::InvalidSignerPubkey(
                "noncanonical caller key".into(),
            ));
        }
        let public = nostr::PublicKey::from_hex(key)
            .map_err(|e| IacVerifyError::InvalidSignerPubkey(e.to_string()))?;
        let bytes = hex::decode(&self.signature)
            .map_err(|e| IacVerifyError::InvalidSignatureHex(e.to_string()))?;
        let signature = nostr::secp256k1::schnorr::Signature::from_slice(&bytes)
            .map_err(|e| IacVerifyError::InvalidSignatureHex(e.to_string()))?;
        let xonly = public
            .xonly()
            .map_err(|e| IacVerifyError::InvalidSignerPubkey(e.to_string()))?;
        let msg = nostr::secp256k1::Message::from_digest(self.digest(audience, path, body, iac)?);
        nostr::secp256k1::Secp256k1::verification_only()
            .verify_schnorr(&signature, &msg, &xonly)
            .map_err(|_| IacVerifyError::InvalidSignature)?;
        Ok(key.into())
    }
}
