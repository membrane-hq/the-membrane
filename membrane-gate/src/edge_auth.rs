//! Edge assertion validation: proof that a request traversed the trusted
//! edge. Never a caller-proof bypass and never a human login, MFA or
//! web-attack screening layer.
//!
//! When an operator pins an edge issuer, every production route must carry a
//! valid RS256 assertion from that issuer in addition to the signed IAC and
//! per-request caller proof. Two independent checks then hold: permission to
//! reach the gate through the edge, then permission to perform the specific
//! action. The gate performs only the second half itself; the first half is
//! verifying a signed assertion from an edge identity layer the operator
//! already runs (for example Cloudflare Access). This module does not
//! authenticate humans, enroll devices, filter bots or hide the origin; the
//! edge and the network do those jobs.
use crate::GateError;
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

fn denied(reason: &str) -> GateError {
    GateError::IdentityAuthentication(format!("edge assertion: {reason}"))
}
fn default_cache() -> u64 {
    300
}
fn default_header() -> String {
    "cf-access-jwt-assertion".into()
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeAuthConfig {
    /// Exact expected issuer, pinned by the operator. Never read from a token.
    pub issuer: String,
    /// Exact expected audience: this gate, as registered at the edge.
    pub audience: String,
    /// Admin-pinned JWKS URL, not obtained from a token header.
    pub jwks_url: String,
    /// Exact top-level string claim naming the edge subject (for example
    /// `sub`). Recorded nowhere on the allow path; a missing claim denies.
    pub identity_claim: String,
    /// Header carrying the assertion on every production request.
    #[serde(default = "default_header")]
    pub header: String,
    #[serde(default = "default_cache")]
    pub cache_ttl_secs: u64,
    /// Local and CI reference deployments only: permit plain-HTTP issuer and
    /// JWKS URLs. Production assertions cross untrusted networks and require
    /// HTTPS; leaving this off refuses plain HTTP at startup.
    #[serde(default)]
    pub insecure_http_for_testing: bool,
}

struct Cache {
    keys: Option<(JwkSet, Instant)>,
    last_attempt: Option<Instant>,
}

pub struct EdgeAuth {
    config: EdgeAuthConfig,
    client: reqwest::Client,
    cache: Mutex<Cache>,
}

#[derive(Debug)]
pub struct EdgeIdentity {
    /// The value of the configured identity claim (for example the `sub`).
    pub subject: String,
    pub expires_at: i64,
}

impl EdgeAuth {
    pub fn new(config: EdgeAuthConfig) -> Result<Self, GateError> {
        Self::build(config, false)
    }
    fn build(config: EdgeAuthConfig, loopback_test: bool) -> Result<Self, GateError> {
        for raw in [&config.issuer, &config.jwks_url] {
            let url = reqwest::Url::parse(raw).map_err(|_| denied("invalid URL"))?;
            let plain_http_ok = config.insecure_http_for_testing
                || (loopback_test && url.scheme() == "http" && url.host_str() == Some("127.0.0.1"));
            if (url.scheme() != "https" && !plain_http_ok)
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
        let header_ok = !config.header.is_empty()
            && config
                .header
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"-".contains(&c))
            && axum::http::header::HeaderName::from_bytes(config.header.as_bytes()).is_ok();
        if config.audience.trim().is_empty()
            || config.identity_claim.trim().is_empty()
            || !(30..=3600).contains(&config.cache_ttl_secs)
            || !header_ok
        {
            return Err(denied(
                "invalid audience, claim, cache lifetime or assertion header",
            ));
        }
        if config.insecure_http_for_testing {
            tracing::warn!(
                "edge auth: plain-HTTP issuer/JWKS accepted (insecure_http_for_testing); \
                 never enable this outside local or CI reference deployments"
            );
        }
        membrane_core::tls::install_default_provider();
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
    /// The configured assertion header, exactly as requests must carry it.
    pub fn header_name(&self) -> &str {
        &self.config.header
    }
    pub fn issuer(&self) -> &str {
        &self.config.issuer
    }
    /// Validate one presented assertion. A valid assertion proves only that
    /// the holder passed the trusted edge; it grants no action authority.
    pub async fn validate(&self, token: &str) -> Result<EdgeIdentity, GateError> {
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
        // The library accepts exp == now; edge access is exclusive at expiry.
        let now = chrono::Utc::now().timestamp();
        if expiry <= now
            || claims
                .get("nbf")
                .is_some_and(|v| v.as_i64().is_none_or(|n| n > now))
        {
            return Err(denied("expired or not yet valid"));
        }
        let subject = claims
            .get(&self.config.identity_claim)
            .and_then(Value::as_str)
            .ok_or_else(|| denied("identity claim missing or not a string"))?;
        Ok(EdgeIdentity {
            subject: subject.to_string(),
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
        let response = self
            .client
            .get(&self.config.jwks_url)
            .send()
            .await
            .map_err(|_| denied("JWKS unreachable"))?
            .error_for_status()
            .map_err(|_| denied("JWKS HTTP failure"))?;
        let mut bytes = Vec::new();
        let mut response = response;
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
        let document: Value = serde_json::from_slice(&bytes).map_err(|_| denied("invalid JWKS"))?;
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

impl crate::Gate {
    /// Require a valid edge assertion on every production route, in addition
    /// to the signed IAC and per-request caller proof. Invalid configuration
    /// fails startup; a missing or invalid assertion fails closed per request.
    pub fn with_edge_auth(mut self, config: EdgeAuthConfig) -> Result<Self, GateError> {
        self.edge_auth = Some(EdgeAuth::new(config)?);
        Ok(self)
    }
    pub fn edge_auth(&self) -> Option<&EdgeAuth> {
        self.edge_auth.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
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
    fn config(idp: &Idp) -> EdgeAuthConfig {
        EdgeAuthConfig {
            issuer: "https://edge.example/team".into(),
            audience: "membrane-gate".into(),
            jwks_url: idp.url.clone(),
            identity_claim: "sub".into(),
            header: "cf-access-jwt-assertion".into(),
            cache_ttl_secs: 300,
            insecure_http_for_testing: false,
        }
    }
    fn claims() -> Value {
        let now = chrono::Utc::now().timestamp();
        serde_json::json!({"iss":"https://edge.example/team", "aud":"membrane-gate", "sub":"agent-7", "exp":now+3600,"nbf":now-1})
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
    async fn advance_refresh(auth: &EdgeAuth, expire: bool) {
        let mut cache = auth.cache.lock().await;
        cache.last_attempt = Some(Instant::now() - Duration::from_secs(31));
        if expire {
            if let Some((_, fetched)) = &mut cache.keys {
                *fetched = Instant::now() - Duration::from_secs(301);
            }
        }
    }

    #[tokio::test]
    async fn valid_token_passes_and_jwks_is_cached() {
        let idp = idp().await;
        let auth = EdgeAuth::build(config(&idp), true).unwrap();
        assert_eq!(
            auth.validate(&token("a", &claims())).await.unwrap().subject,
            "agent-7"
        );
        auth.validate(&token("a", &claims())).await.unwrap();
        assert_eq!(idp.hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn wrong_issuer_audience_expiry_nbf_and_alg_fail_closed() {
        let idp = idp().await;
        let auth = EdgeAuth::build(config(&idp), true).unwrap();
        for (name, value) in [
            ("iss", Value::from("https://edge.example/other")),
            ("aud", Value::from("other-gate")),
        ] {
            let mut c = claims();
            c[name] = value;
            assert!(auth.validate(&token("a", &c)).await.is_err(), "{name}");
        }
        let now = chrono::Utc::now().timestamp();
        let mut c = claims();
        c["exp"] = Value::from(now);
        assert!(auth.validate(&token("a", &c)).await.is_err(), "exp == now");
        let mut c = claims();
        c["exp"] = Value::from(now - 60);
        assert!(auth.validate(&token("a", &c)).await.is_err(), "expired");
        let mut c = claims();
        c["nbf"] = Value::from(now + 300);
        assert!(auth.validate(&token("a", &c)).await.is_err(), "future nbf");
        let mut c = claims();
        c.as_object_mut().unwrap().remove("sub");
        assert!(auth.validate(&token("a", &c)).await.is_err(), "missing sub");
        let mut c = claims();
        c["sub"] = serde_json::json!(["agent-7"]);
        assert!(
            auth.validate(&token("a", &c)).await.is_err(),
            "non-string sub"
        );
        // HS256 with the same claims must never verify.
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("a".into());
        let hs = encode(&header, &claims(), &EncodingKey::from_secret(b"attacker")).unwrap();
        assert!(auth.validate(&hs).await.is_err(), "HS256 refused");
        // A token signed by the other fixture key under kid "a" fails.
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("a".into());
        let forged = encode(
            &header,
            &claims(),
            &EncodingKey::from_rsa_pem(include_bytes!("../tests/fixtures/oidc-b.pem")).unwrap(),
        )
        .unwrap();
        assert!(auth.validate(&forged).await.is_err(), "wrong key");
    }

    #[tokio::test]
    async fn unknown_kid_refresh_cooldown_and_rotation_fail_closed() {
        let idp = idp().await;
        let auth = EdgeAuth::build(config(&idp), true).unwrap();
        // Unknown kid: one refresh attempt, then cooldown-bound refusal.
        let mut c = claims();
        c["sub"] = Value::from("agent-7");
        let pem = include_bytes!("../tests/fixtures/oidc-a.pem").as_slice();
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("zzz".into());
        let unknown = encode(&header, &c, &EncodingKey::from_rsa_pem(pem).unwrap()).unwrap();
        assert!(auth.validate(&unknown).await.is_err());
        assert!(auth.validate(&unknown).await.is_err());
        // Rotate the served JWKS to key b: old tokens fail, new pass after refresh.
        *idp.keys.lock().unwrap() = jwks("b");
        advance_refresh(&auth, true).await;
        assert!(auth.validate(&token("a", &claims())).await.is_err());
        assert_eq!(
            auth.validate(&token("b", &claims())).await.unwrap().subject,
            "agent-7"
        );
    }

    #[tokio::test]
    async fn unreachable_jwks_and_failed_refresh_deny() {
        let idp = idp().await;
        let mut cfg = config(&idp);
        cfg.jwks_url = "http://127.0.0.1:9/jwks".into();
        let auth = EdgeAuth::build(cfg, true).unwrap();
        assert!(auth.validate(&token("a", &claims())).await.is_err());
        // After a successful fetch, a failed refresh drops trust material.
        let auth = EdgeAuth::build(config(&idp), true).unwrap();
        auth.validate(&token("a", &claims())).await.unwrap();
        drop(idp);
        advance_refresh(&auth, true).await;
        assert!(auth.validate(&token("a", &claims())).await.is_err());
    }

    #[test]
    fn config_validation_fails_closed() {
        let base = EdgeAuthConfig {
            issuer: "https://edge.example/team".into(),
            audience: "membrane-gate".into(),
            jwks_url: "https://edge.example/jwks".into(),
            identity_claim: "sub".into(),
            header: "cf-access-jwt-assertion".into(),
            cache_ttl_secs: 300,
            insecure_http_for_testing: false,
        };
        // Plain-HTTP issuer or JWKS refused without the explicit testing override.
        let mut c = base.clone();
        c.issuer = "http://edge.example/team".into();
        assert!(EdgeAuth::new(c).is_err());
        let mut c = base.clone();
        c.jwks_url = "http://edge.example/jwks".into();
        assert!(EdgeAuth::new(c).is_err());
        let mut c = base.clone();
        c.issuer = "http://edge.example/team".into();
        c.insecure_http_for_testing = true;
        assert!(EdgeAuth::new(c).is_ok());
        // Credentials, fragments, empty audience/claim, bad header, bad cache.
        let mut c = base.clone();
        c.jwks_url = "https://user:pw@edge.example/jwks".into();
        assert!(EdgeAuth::new(c).is_err());
        let mut c = base.clone();
        c.jwks_url = "https://edge.example/jwks#frag".into();
        assert!(EdgeAuth::new(c).is_err());
        let mut c = base.clone();
        c.audience = "  ".into();
        assert!(EdgeAuth::new(c).is_err());
        let mut c = base.clone();
        c.identity_claim = "".into();
        assert!(EdgeAuth::new(c).is_err());
        let mut c = base.clone();
        c.header = "X Mixed Case".into();
        assert!(EdgeAuth::new(c).is_err());
        let mut c = base.clone();
        c.header = "x-membrane-edge-assertion".into();
        assert!(EdgeAuth::new(c).is_ok());
        let mut c = base.clone();
        c.cache_ttl_secs = 10;
        assert!(EdgeAuth::new(c).is_err());
        // Unknown YAML keys refuse at parse time.
        assert!(serde_yaml::from_str::<EdgeAuthConfig>(
            "issuer: https://edge.example/team\naudience: g\njwks_url: https://e.example/j\nidentity_claim: sub\nextra: 1\n"
        )
        .is_err());
    }
}
