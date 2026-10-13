//! Operator token validation and bounded IAC issuance. Never a caller-proof bypass.
use crate::{Gate, GateError};
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use membrane_core::iac::IntentAuthorizationCredential;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

fn denied(reason: &str) -> GateError {
    GateError::IdentityAuthentication(format!("operator OIDC: {reason}"))
}
fn default_cache() -> u64 {
    300
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    pub issuer: String,
    pub audience: String,
    /// Admin-pinned JWKS URL, not obtained from a token header.
    pub jwks_url: String,
    /// Exact top-level string claim. Prefer immutable sub or tenant-bound oid.
    pub identity_claim: String,
    /// Exact claim value -> existing trusted operator signing public key.
    pub operators: BTreeMap<String, String>,
    #[serde(default = "default_cache")]
    pub cache_ttl_secs: u64,
}
struct Cache {
    keys: Option<(JwkSet, Instant)>,
    last_attempt: Option<Instant>,
}
pub struct OperatorOidc {
    config: OidcConfig,
    client: reqwest::Client,
    cache: Mutex<Cache>,
}
#[derive(Debug)]
pub struct OperatorIdentity {
    pub operator: String,
    /// The value of the configured identity claim (for example the OIDC `sub`).
    pub subject: String,
    pub expires_at: i64,
}
impl OperatorOidc {
    pub fn new(config: OidcConfig, trusted_operator: &str) -> Result<Self, GateError> {
        Self::build(config, trusted_operator, false)
    }
    fn build(
        config: OidcConfig,
        trusted_operator: &str,
        loopback_test: bool,
    ) -> Result<Self, GateError> {
        for raw in [&config.issuer, &config.jwks_url] {
            let url = reqwest::Url::parse(raw).map_err(|_| denied("invalid URL"))?;
            if (url.scheme() != "https"
                && !(loopback_test
                    && url.scheme() == "http"
                    && url.host_str() == Some("127.0.0.1")))
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
            {
                return Err(denied(
                    "issuer and JWKS require HTTPS without credentials or fragments",
                ));
            }
        }
        if config.audience.trim().is_empty()
            || config.identity_claim.trim().is_empty()
            || !(30..=3600).contains(&config.cache_ttl_secs)
            || config.operators.is_empty()
            || config
                .operators
                .iter()
                .any(|(claim, key)| claim.is_empty() || key != trusted_operator)
        {
            return Err(denied(
                "invalid audience, claim, cache lifetime or operator mapping",
            ));
        }
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|_| denied("HTTP client unavailable"))?;
        Ok(Self {
            config,
            client,
            cache: Mutex::new(Cache {
                keys: None,
                last_attempt: None,
            }),
        })
    }
    pub async fn validate(&self, token: &str) -> Result<OperatorIdentity, GateError> {
        if token.len() > 16_384 {
            return Err(denied("token too large"));
        }
        let header = decode_header(token).map_err(|_| denied("invalid token header"))?;
        if header.alg != Algorithm::RS256 {
            return Err(denied("RS256 required"));
        }
        let kid = header
            .kid
            .filter(|s| !s.is_empty() && s.len() <= 256)
            .ok_or_else(|| denied("kid required"))?;
        let key = self.key(&kid).await?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.leeway = 0;
        validation.validate_nbf = true;
        validation.set_required_spec_claims(&["iss", "aud", "exp", "sub"]);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.audience]);
        let claims = decode::<Value>(token, &key, &validation)
            .map_err(|_| denied("invalid signature or claims"))?
            .claims;
        let expiry = claims
            .get("exp")
            .and_then(Value::as_i64)
            .ok_or_else(|| denied("invalid expiry"))?;
        // The library accepts exp == now; operator access is exclusive at expiry.
        let now = chrono::Utc::now().timestamp();
        if expiry <= now
            || claims
                .get("nbf")
                .is_some_and(|v| v.as_i64().is_none_or(|n| n > now))
        {
            return Err(denied("expired or not yet valid"));
        }
        let claim = claims
            .get(&self.config.identity_claim)
            .and_then(Value::as_str)
            .ok_or_else(|| denied("identity claim missing or not a string"))?;
        let operator = self
            .config
            .operators
            .get(claim)
            .ok_or_else(|| denied("operator not mapped"))?
            .clone();
        Ok(OperatorIdentity {
            operator,
            subject: claim.to_string(),
            expires_at: expiry,
        })
    }
    async fn key(&self, kid: &str) -> Result<DecodingKey, GateError> {
        let mut cache = self.cache.lock().await;
        let fresh = cache.keys.as_ref().is_some_and(|(_, fetched)| {
            fetched.elapsed() < Duration::from_secs(self.config.cache_ttl_secs)
        });
        let found = fresh
            && cache
                .keys
                .as_ref()
                .is_some_and(|(keys, _)| keys.find(kid).is_some());
        if !found {
            // Coalesce refreshes and bound attacker-controlled unknown-kid traffic.
            if cache
                .last_attempt
                .is_some_and(|t| t.elapsed() < Duration::from_secs(30))
            {
                return Err(denied("JWKS refresh cooldown or unknown key"));
            }
            cache.last_attempt = Some(Instant::now());
            // Failed refresh must not fall back to old trust material.
            cache.keys = None;
            let keys = self.fetch_keys().await?;
            cache.keys = Some((keys, Instant::now()));
        }
        let keys = &cache
            .keys
            .as_ref()
            .ok_or_else(|| denied("JWKS unavailable"))?
            .0;
        let key = keys
            .find(kid)
            .ok_or_else(|| denied("unknown signing key"))?;
        use jsonwebtoken::jwk::{AlgorithmParameters, KeyAlgorithm, KeyOperations, PublicKeyUse};
        if !matches!(key.algorithm, AlgorithmParameters::RSA(_))
            || key
                .common
                .key_algorithm
                .is_some_and(|a| a != KeyAlgorithm::RS256)
            || key
                .common
                .public_key_use
                .as_ref()
                .is_some_and(|u| *u != PublicKeyUse::Signature)
            || key
                .common
                .key_operations
                .as_ref()
                .is_some_and(|ops| !ops.contains(&KeyOperations::Verify))
        {
            return Err(denied("JWKS key is not an RS256 verification key"));
        }
        DecodingKey::from_jwk(key).map_err(|_| denied("invalid RSA key"))
    }
    async fn fetch_keys(&self) -> Result<JwkSet, GateError> {
        let mut response = self
            .client
            .get(&self.config.jwks_url)
            .send()
            .await
            .map_err(|_| denied("JWKS unreachable"))?
            .error_for_status()
            .map_err(|_| denied("JWKS HTTP failure"))?;
        if !response.status().is_success() {
            return Err(denied("JWKS redirect refused"));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| denied("JWKS read failed"))?
        {
            if bytes.len() + chunk.len() > 262_144 {
                return Err(denied("JWKS too large"));
            }
            bytes.extend_from_slice(&chunk);
        }
        let mut document: Value =
            serde_json::from_slice(&bytes).map_err(|_| denied("invalid JWKS"))?;
        // Exclude keys with incompatible issuer constraints. A provider key set
        // can contain unrelated issuers; only selected trust material matters.
        let configured =
            reqwest::Url::parse(&self.config.issuer).map_err(|_| denied("invalid issuer"))?;
        let tenant = configured
            .path_segments()
            .and_then(|mut segments| segments.next())
            .unwrap_or("");
        if let Some(keys) = document.get_mut("keys").and_then(Value::as_array_mut) {
            keys.retain(|key| {
                let Some(key_issuer) = key.get("issuer") else {
                    return true;
                };
                let Some(key_issuer) = key_issuer.as_str() else {
                    return false;
                };
                let resolved = if configured.host_str() == Some("login.microsoftonline.com")
                    && tenant.len() == 36
                    && tenant.bytes().enumerate().all(|(i, c)| {
                        if [8, 13, 18, 23].contains(&i) {
                            c == b'-'
                        } else {
                            c.is_ascii_hexdigit()
                        }
                    }) {
                    key_issuer.replace("{tenantid}", tenant)
                } else {
                    key_issuer.to_string()
                };
                resolved == self.config.issuer
            });
        }
        let keys: JwkSet = serde_json::from_value(document).map_err(|_| denied("invalid JWKS"))?;
        if keys.keys.is_empty() || keys.keys.len() > 128 {
            return Err(denied("invalid JWKS key count"));
        }
        let mut ids = std::collections::BTreeSet::new();
        for key in &keys.keys {
            if let Some(id) = &key.common.key_id {
                if !ids.insert(id) {
                    return Err(denied("duplicate JWKS kid"));
                }
            }
        }
        Ok(keys)
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorIacRequest {
    pub caller_pubkey: String,
    pub scope_id: String,
    pub model: String,
    #[serde(default)]
    pub tools: Vec<String>,
    pub ttl_secs: i64,
}
impl Gate {
    /// OIDC authenticates only the operator exchange; signed IAC/caller proofs remain mandatory.
    pub fn with_operator_oidc(mut self, config: OidcConfig) -> Result<Self, GateError> {
        self.operator_oidc = Some(OperatorOidc::new(config, &self.iac_signer_pubkey)?);
        Ok(self)
    }
    /// Authenticate a human operator for an approval decision. Returns the OIDC subject
    /// only when it maps to this gate's trusted operator key.
    pub async fn authenticate_operator(&self, token: &str) -> Result<OperatorIdentity, GateError> {
        let identity = self
            .operator_oidc
            .as_ref()
            .ok_or_else(|| denied("not configured"))?
            .validate(token)
            .await?;
        if identity.operator != self.iac_signer_pubkey {
            return Err(denied("operator no longer trusted"));
        }
        Ok(identity)
    }
    pub async fn issue_operator_iac(
        &self,
        token: &str,
        request: &OperatorIacRequest,
        parent_cp_hash: &str,
    ) -> Result<(String, IntentAuthorizationCredential), GateError> {
        let identity = self
            .operator_oidc
            .as_ref()
            .ok_or_else(|| denied("not configured"))?
            .validate(token)
            .await?;
        if identity.operator != self.iac_signer_pubkey {
            return Err(denied("operator no longer trusted"));
        }
        let now = chrono::Utc::now().timestamp();
        if !(1..=300).contains(&request.ttl_secs)
            || request.scope_id.is_empty()
            || request.scope_id.len() > 128
            || !request
                .scope_id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_.:".contains(&c))
            || request.caller_pubkey.len() != 64
            || !request
                .caller_pubkey
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            || nostr::PublicKey::from_hex(&request.caller_pubkey).is_err()
        {
            return Err(denied("invalid issuance request"));
        }
        let live;
        let registry = if let Some(path) = &self.identity_registry_path {
            live =
                crate::ChannelRegistry::load(path).map_err(|_| denied("registry unavailable"))?;
            &live
        } else {
            &self.registry
        };
        let grant = registry
            .identities
            .get(&request.caller_pubkey)
            .ok_or_else(|| denied("caller not granted"))?;
        grant.check_window(now)?;
        if grant.revoked
            || !grant.scopes.contains(&request.scope_id)
            || !grant.model_allowlist.contains(&request.model)
            || !registry.model_allowlist.contains(&request.model)
            || !grant.permitted_channels.contains(&"local-llm".into())
            || registry
                .permitted_channels
                .iter()
                .any(|c| !grant.permitted_channels.contains(c))
            || request
                .tools
                .iter()
                .any(|t| !grant.tool_allowlist.contains(t))
        {
            return Err(denied("issuance exceeds caller grant"));
        }
        let mut expiry = (now + request.ttl_secs).min(identity.expires_at);
        if let Some(until) = grant.effective_expiry()? {
            expiry = expiry.min(until);
        }
        // IACs use inclusive valid_until; never extend past exclusive token/grant expiry.
        expiry -= 1;
        if expiry < now {
            return Err(denied("no remaining validity"));
        }
        let mut channels = registry.permitted_channels.clone();
        if !channels.contains(&"local-llm".into()) {
            channels.push("local-llm".into());
        }
        let mut iac = IntentAuthorizationCredential::new_session_with_tools(
            &request.scope_id,
            &request.model,
            parent_cp_hash,
            expiry,
            channels,
            registry.forbidden_exports.clone(),
            request.tools.clone(),
        );
        iac.caller_pubkey = Some(request.caller_pubkey.clone());
        iac.sign(self.publisher.keys())
            .map_err(|_| denied("IAC signing failed"))?;
        Ok((identity.operator, iac))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use membrane_core::{BusPublisher, BusPublisherConfig};
    use nostr::Keys;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    struct Idp {
        url: String,
        keys: Arc<std::sync::Mutex<Value>>,
        hits: Arc<AtomicUsize>,
        task: tokio::task::JoinHandle<()>,
    }
    impl Drop for Idp {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    fn jwks(kid: &str) -> Value {
        serde_json::from_str(match kid {
            "a" => include_str!("../tests/fixtures/oidc-a.json"),
            _ => include_str!("../tests/fixtures/oidc-b.json"),
        })
        .unwrap()
    }
    async fn idp() -> Idp {
        let keys = Arc::new(std::sync::Mutex::new(jwks("a")));
        let hits = Arc::new(AtomicUsize::new(0));
        let state = (keys.clone(), hits.clone());
        let app = axum::Router::new()
            .route(
                "/jwks",
                axum::routing::get(
                    |axum::extract::State((keys, hits)): axum::extract::State<(
                        Arc<std::sync::Mutex<Value>>,
                        Arc<AtomicUsize>,
                    )>| async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        axum::Json(keys.lock().unwrap().clone())
                    },
                ),
            )
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/jwks", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Idp {
            url,
            keys,
            hits,
            task,
        }
    }
    fn config(idp: &Idp, operator: &str) -> OidcConfig {
        OidcConfig {
            issuer: "https://idp.example/tenant".into(),
            audience: "membrane-operator".into(),
            jwks_url: idp.url.clone(),
            identity_claim: "sub".into(),
            operators: [("alice".into(), operator.into())].into(),
            cache_ttl_secs: 300,
        }
    }
    fn claims() -> Value {
        let now = chrono::Utc::now().timestamp();
        serde_json::json!({"iss":"https://idp.example/tenant", "aud":"membrane-operator", "sub":"alice", "exp":now+3600,"nbf":now-1})
    }
    fn token(kid: &str, claims: &Value) -> String {
        let pem = if kid == "a" {
            include_bytes!("../tests/fixtures/oidc-a.pem").as_slice()
        } else {
            include_bytes!("../tests/fixtures/oidc-b.pem").as_slice()
        };
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.into());
        encode(&header, claims, &EncodingKey::from_rsa_pem(pem).unwrap()).unwrap()
    }
    async fn advance_refresh(auth: &OperatorOidc, expire: bool) {
        let mut cache = auth.cache.lock().await;
        cache.last_attempt = Some(Instant::now() - Duration::from_secs(31));
        if expire {
            if let Some((_, fetched)) = &mut cache.keys {
                *fetched = Instant::now() - Duration::from_secs(301);
            }
        }
    }
    #[tokio::test]
    async fn valid_cached_token_and_claim_mapping() {
        let idp = idp().await;
        let mut cfg = config(&idp, "operator");
        cfg.identity_claim = "oid".into();
        let auth = OperatorOidc::build(cfg, "operator", true).unwrap();
        let mut c = claims();
        c["oid"] = "alice".into();
        c["sub"] = "different".into();
        assert_eq!(
            auth.validate(&token("a", &c)).await.unwrap().operator,
            "operator"
        );
        auth.validate(&token("a", &c)).await.unwrap();
        assert_eq!(idp.hits.load(Ordering::SeqCst), 1);
        c.as_object_mut().unwrap().remove("nbf");
        c["aud"] = serde_json::json!(["other", "membrane-operator"]);
        auth.validate(&token("a", &c)).await.unwrap();
        c["oid"] = "unknown".into();
        assert!(auth.validate(&token("a", &c)).await.is_err());
        c["oid"] = serde_json::json!(["alice"]);
        assert!(auth.validate(&token("a", &c)).await.is_err());
    }
    #[tokio::test]
    async fn wrong_issuer_audience_expiry_nbf_missing_and_alg_fail_closed() {
        let idp = idp().await;
        let auth = OperatorOidc::build(config(&idp, "operator"), "operator", true).unwrap();
        for (name, value) in [
            ("iss", Value::from("wrong")),
            ("aud", Value::from("wrong")),
            ("exp", Value::from(chrono::Utc::now().timestamp())),
            ("nbf", Value::from(chrono::Utc::now().timestamp() + 3600)),
            ("nbf", Value::from("bad")),
            ("sub", Value::from("unknown")),
        ] {
            let mut c = claims();
            c[name] = value;
            assert!(auth.validate(&token("a", &c)).await.is_err(), "{name}");
        }
        for name in ["iss", "aud", "exp", "sub"] {
            let mut c = claims();
            c.as_object_mut().unwrap().remove(name);
            assert!(
                auth.validate(&token("a", &c)).await.is_err(),
                "missing {name}"
            );
        }
        let bad = encode(
            &Header::new(Algorithm::HS256),
            &claims(),
            &EncodingKey::from_secret(b"secret"),
        )
        .unwrap();
        assert!(auth.validate(&bad).await.is_err());
        assert!(auth.validate("bad").await.is_err());
        assert!(auth.validate(&"x".repeat(16_385)).await.is_err());
        let mut t = token("a", &claims()).into_bytes();
        let n = t.len() - 10;
        t[n] = if t[n] == b'A' { b'B' } else { b'A' };
        assert!(auth
            .validate(std::str::from_utf8(&t).unwrap())
            .await
            .is_err());
    }
    #[tokio::test]
    async fn rotation_unknown_kid_refresh_cooldown_and_removed_key() {
        let idp = idp().await;
        let auth = OperatorOidc::build(config(&idp, "operator"), "operator", true).unwrap();
        auth.validate(&token("a", &claims())).await.unwrap();
        *idp.keys.lock().unwrap() = jwks("b");
        assert!(auth.validate(&token("b", &claims())).await.is_err());
        assert_eq!(idp.hits.load(Ordering::SeqCst), 1);
        advance_refresh(&auth, false).await;
        auth.validate(&token("b", &claims())).await.unwrap();
        assert!(auth.validate(&token("a", &claims())).await.is_err());
        assert_eq!(idp.hits.load(Ordering::SeqCst), 2);
    }
    #[tokio::test]
    async fn unreachable_and_expired_cache_never_fall_back() {
        let idp = idp().await;
        let auth = OperatorOidc::build(config(&idp, "operator"), "operator", true).unwrap();
        auth.validate(&token("a", &claims())).await.unwrap();
        idp.task.abort();
        advance_refresh(&auth, true).await;
        assert!(auth.validate(&token("a", &claims())).await.is_err());
        assert!(auth.cache.lock().await.keys.is_none());
        let empty = OperatorOidc::build(config(&idp, "operator"), "operator", true).unwrap();
        assert!(empty.validate(&token("a", &claims())).await.is_err());
    }
    #[tokio::test]
    async fn ambiguous_jwks_or_non_signing_key_denied() {
        let idp = idp().await;
        let mut keys = jwks("a");
        let duplicate = keys["keys"][0].clone();
        keys["keys"].as_array_mut().unwrap().push(duplicate);
        *idp.keys.lock().unwrap() = keys;
        let auth = OperatorOidc::build(config(&idp, "operator"), "operator", true).unwrap();
        assert!(auth.validate(&token("a", &claims())).await.is_err());
        for (field, value) in [
            ("use", serde_json::json!("enc")),
            ("alg", serde_json::json!("RS512")),
            ("key_ops", serde_json::json!(["encrypt"])),
        ] {
            let mut keys = jwks("a");
            keys["keys"][0][field] = value;
            *idp.keys.lock().unwrap() = keys;
            let auth = OperatorOidc::build(config(&idp, "operator"), "operator", true).unwrap();
            assert!(auth.validate(&token("a", &claims())).await.is_err());
        }
    }
    #[tokio::test]
    async fn production_config_https_and_exact_operator_trust_required() {
        let idp = idp().await;
        assert!(OperatorOidc::new(config(&idp, "operator"), "operator").is_err());
        let mut c = config(&idp, "operator");
        c.jwks_url = "https://idp.example/keys".into();
        OperatorOidc::new(c.clone(), "operator").unwrap();
        assert!(OperatorOidc::new(c.clone(), "other").is_err());
        c.cache_ttl_secs = 0;
        assert!(OperatorOidc::new(c, "operator").is_err());
    }
    #[tokio::test]
    async fn key_issuer_is_checked_including_entra_template() {
        let idp = idp().await;
        let mut keys = jwks("a");
        keys["keys"][0]["issuer"] = "https://other.example".into();
        *idp.keys.lock().unwrap() = keys.clone();
        let auth = OperatorOidc::build(config(&idp, "operator"), "operator", true).unwrap();
        assert!(auth.validate(&token("a", &claims())).await.is_err());
        keys["keys"][0]["issuer"] = "https://login.microsoftonline.com/{tenantid}/v2.0".into();
        let mut foreign = jwks("b")["keys"][0].clone();
        foreign["issuer"] = "https://other.example".into();
        keys["keys"].as_array_mut().unwrap().push(foreign);
        *idp.keys.lock().unwrap() = keys;
        let issuer = "https://login.microsoftonline.com/12345678-1234-1234-1234-123456789abc/v2.0";
        let mut cfg = config(&idp, "operator");
        cfg.issuer = issuer.into();
        let auth = OperatorOidc::build(cfg, "operator", true).unwrap();
        let mut c = claims();
        c["iss"] = issuer.into();
        auth.validate(&token("a", &c)).await.unwrap();
    }
    fn gate() -> (Gate, OperatorIacRequest) {
        let operator = Keys::generate();
        let caller = Keys::generate().public_key().to_hex();
        let grant = crate::identity::IdentityGrant {
            scopes: vec!["s".into()],
            permitted_channels: vec!["local-llm".into()],
            model_allowlist: vec!["m".into()],
            tool_allowlist: vec!["github.comment".into()],
            ..Default::default()
        };
        let registry = crate::ChannelRegistry {
            approval: None,
            identities: [(caller.clone(), grant)].into(),
            permitted_channels: vec!["local-llm".into()],
            forbidden_exports: vec!["training".into()],
            model_allowlist: vec!["m".into()],
            delta_t_secs: 300,
            model_api_url: None,
            github_repo_allowlist: vec![],
        };
        let gate = Gate::new(
            registry,
            BusPublisher::new(BusPublisherConfig {
                relay_url: "memory://oidc".into(),
                keys: operator,
            }),
        );
        (
            gate,
            OperatorIacRequest {
                caller_pubkey: caller,
                scope_id: "s".into(),
                model: "m".into(),
                tools: vec!["github.comment".into()],
                ttl_secs: 300,
            },
        )
    }
    #[tokio::test]
    async fn issuance_reads_live_grants_and_registry_failures_deny() {
        let idp = idp().await;
        let (mut g, req) = gate();
        g.operator_oidc = Some(
            OperatorOidc::build(
                config(&idp, &g.iac_signer_pubkey),
                &g.iac_signer_pubkey,
                true,
            )
            .unwrap(),
        );
        let path = std::env::temp_dir().join(format!("oidc-grant-{}.yaml", req.caller_pubkey));
        std::fs::write(&path, serde_yaml::to_string(&g.registry).unwrap()).unwrap();
        g.identity_registry_path = Some(path.clone());
        let t = token("a", &claims());
        g.issue_operator_iac(&t, &req, &"0".repeat(64))
            .await
            .unwrap();
        let mut changed = g.registry.clone();
        changed
            .identities
            .get_mut(&req.caller_pubkey)
            .unwrap()
            .revoked = true;
        std::fs::write(&path, serde_yaml::to_string(&changed).unwrap()).unwrap();
        assert!(g.issue_operator_iac(&t, &req, "0").await.is_err());
        std::fs::write(&path, "not: [yaml").unwrap();
        assert!(g.issue_operator_iac(&t, &req, "0").await.is_err());
        std::fs::remove_file(path).unwrap();
        assert!(g.issue_operator_iac(&t, &req, "0").await.is_err());
    }
    #[tokio::test]
    async fn exchange_binds_caller_and_limits_scope_expiry_without_keypair_regression() {
        let idp = idp().await;
        let (mut g, mut req) = gate();
        // Disabled exchange does not affect keypair verification.
        assert!(g
            .issue_operator_iac(&token("a", &claims()), &req, &"0".repeat(64))
            .await
            .is_err());
        let now = chrono::Utc::now().timestamp();
        let mut original = IntentAuthorizationCredential::new_session(
            "s",
            "m",
            "0".repeat(64),
            now + 100,
            vec!["local-llm".into()],
            vec![],
        );
        original.sign(g.publisher.keys()).unwrap();
        g.validate_iac(Some(&original), now).unwrap();
        g.operator_oidc = Some(
            OperatorOidc::build(
                config(&idp, &g.iac_signer_pubkey),
                &g.iac_signer_pubkey,
                true,
            )
            .unwrap(),
        );
        let mut c = claims();
        c["exp"] = Value::from(now + 100);
        g.registry
            .identities
            .get_mut(&req.caller_pubkey)
            .unwrap()
            .expires_at = Some(now + 50);
        let (operator, iac) = g
            .issue_operator_iac(&token("a", &c), &req, &"0".repeat(64))
            .await
            .unwrap();
        assert_eq!(operator, g.iac_signer_pubkey);
        assert_eq!(iac.valid_until, now + 49);
        assert_eq!(iac.caller_pubkey, Some(req.caller_pubkey.clone()));
        assert_eq!(iac.forbidden_exports, vec!["training"]);
        g.validate_iac(Some(&iac), now).unwrap();
        g.validate_iac(Some(&original), now).unwrap();
        req.tools.push("github.merge".into());
        assert!(g
            .issue_operator_iac(&token("a", &c), &req, "0")
            .await
            .is_err());
        req.tools.pop();
        req.scope_id = "other".into();
        assert!(g
            .issue_operator_iac(&token("a", &c), &req, "0")
            .await
            .is_err());
        req.scope_id = "s".into();
        req.ttl_secs = 301;
        assert!(g
            .issue_operator_iac(&token("a", &c), &req, "0")
            .await
            .is_err());
        req.ttl_secs = 300;
        g.registry
            .identities
            .get_mut(&req.caller_pubkey)
            .unwrap()
            .revoked = true;
        assert!(g
            .issue_operator_iac(&token("a", &c), &req, "0")
            .await
            .is_err());
        idp.task.abort();
        advance_refresh(g.operator_oidc.as_ref().unwrap(), true).await;
        assert!(g
            .issue_operator_iac(&token("a", &c), &req, "0")
            .await
            .is_err());
        g.validate_iac(Some(&original), now).unwrap();
    }
}
