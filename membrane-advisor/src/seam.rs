//! Model-agnostic advisor seam (spike).
//!
//! The advisor asks a decision backend bounded, typed questions about denial groups the
//! deterministic pass already found. A backend can only answer; it cannot emit policy.
//! Everything it returns is validated against a fixed schema. Anything that does not fit is
//! dropped, and the output is a [`Note`] (an explanation plus a triage label) that is
//! attached to an existing recommendation. A note never creates, widens or applies a patch.
//!
//! Wire shape: Clef (Cloudflare Workers AI) and Jev (TypeSafe) both speak the "System One"
//! shape, a `state` plus a map of typed `questions` (`choice`, `score`, `noul`) in, and
//! `answers` keyed by the same ids out. [`Backend`] is that shape; transports differ only in
//! URL, auth header and model string, so they are config, not code.
//!
//! Observational only: nothing here feeds the gate or any authorization decision.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MAX_QUESTIONS: usize = 8;
pub const MAX_STATE_BYTES: usize = 16_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Question {
    Choice {
        instructions: String,
        criteria: BTreeMap<String, String>,
    },
    Score {
        instructions: String,
        criteria: Vec<String>,
    },
    Noul {
        instructions: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Request {
    pub model: String,
    pub state: serde_json::Value,
    pub questions: BTreeMap<String, Question>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Answer {
    Choice {
        choice: String,
        #[serde(default)]
        confidence: Option<f64>,
        #[serde(default)]
        probabilities: BTreeMap<String, f64>,
    },
    Score {
        score: f64,
        #[serde(default)]
        confidence: Option<f64>,
    },
    Noul {
        noul: f64,
    },
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct Response {
    /// Model actually used, as echoed by the backend. Logged for replay.
    #[serde(default)]
    pub model: Option<String>,
    pub answers: BTreeMap<String, Answer>,
}

/// What a backend must do: answer one request. Nothing else crosses the seam.
pub trait Backend {
    /// Stable name logged with every note (backend + pinned model).
    fn id(&self) -> String;
    fn ask(&self, req: &Request) -> Result<Response>;
}

/// Moves a JSON body to a URL and returns the JSON reply. Kept separate so the HTTP client
/// is swappable and tests need no network.
pub trait Transport {
    fn post_json(&self, url: &str, bearer: Option<&str>, body: &str) -> Result<String>;
}

/// Config line that selects a backend. Clef local is the default.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(tag = "backend", rename_all = "snake_case")]
pub enum Config {
    /// Open-weight Clef served locally (OpenAI-style System One endpoint on loopback).
    ClefLocal { url: String, model: String },
    /// Clef on Cloudflare Workers AI.
    ClefWorkersAi {
        account_id: String,
        token_env: String,
        model: String,
    },
    /// Jev through TypeSafe's API.
    JevApi { token_env: String },
}

pub struct HttpBackend<T: Transport> {
    pub transport: T,
    pub url: String,
    pub bearer: Option<String>,
    pub model: String,
    pub name: &'static str,
}

impl<T: Transport> Backend for HttpBackend<T> {
    fn id(&self) -> String {
        format!("{}:{}", self.name, self.model)
    }
    fn ask(&self, req: &Request) -> Result<Response> {
        let mut r = req.clone();
        r.model = self.model.clone();
        let raw = self.transport.post_json(
            &self.url,
            self.bearer.as_deref(),
            &serde_json::to_string(&r)?,
        )?;
        if raw.len() > 1_000_000 {
            bail!("backend reply too large");
        }
        unwrap_envelope(serde_json::from_str(&raw)?)
    }
}

/// Cloudflare's REST API wraps model output as `{"result": {...}, "success": true}`.
/// Jev's direct API and a local server return the body unwrapped. Accept both; a wrapped
/// reply with `success` not true is an error (fail closed).
fn unwrap_envelope(v: serde_json::Value) -> Result<Response> {
    let v = match v.get("result") {
        Some(inner) if v.get("answers").is_none() => {
            if v.get("success").and_then(|s| s.as_bool()) != Some(true) {
                bail!("backend reported failure");
            }
            inner.clone()
        }
        _ => v,
    };
    Ok(serde_json::from_value(v)?)
}

/// Build an HTTP backend from config. Secrets come from the named env var, never the file.
pub fn from_config<T: Transport>(cfg: &Config, transport: T) -> Result<HttpBackend<T>> {
    let tok = |env: &str| std::env::var(env).map_err(|_| anyhow::anyhow!("{env} is not set"));
    Ok(match cfg {
        Config::ClefLocal { url, model } => {
            HttpBackend { transport, url: url.clone(), bearer: None, model: model.clone(), name: "clef-local" }
        }
        Config::ClefWorkersAi { account_id, token_env, model } => HttpBackend {
            transport,
            url: format!("https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/run/@cf/cloudflare/clef"),
            bearer: Some(tok(token_env)?),
            model: model.clone(),
            name: "clef-workers-ai",
        },
        Config::JevApi { token_env } => HttpBackend {
            transport,
            url: "https://api.typesafe.ai/v1/systemone".into(),
            bearer: Some(tok(token_env)?),
            model: "jev-latest".into(),
            name: "jev-api",
        },
    })
}

/// Fixed triage labels. Deliberately no "allow", "loosen" or "apply".
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Triage {
    LikelyMisconfiguration,
    LikelyProbe,
    Unclear,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Note {
    pub rule: String,
    pub triage: Triage,
    /// Probability the denial is a legitimate caller hitting a missing entry (0..1).
    pub p_legitimate: f64,
    pub backend: String,
    pub backend_model: Option<String>,
    /// Advisory only. Never read by the gate; never applied.
    pub advisory: bool,
}

/// Bounded, sanitized view of one denial group. No raw log lines, no free text from callers.
#[derive(Debug, Clone, Serialize)]
pub struct GroupView {
    pub rule: String,
    pub denials: usize,
    pub distinct_subjects: usize,
    pub identified_callers: usize,
}

const Q: &str = "legit";

pub fn build_request(g: &GroupView) -> Request {
    let mut questions = BTreeMap::new();
    questions.insert(
        Q.to_string(),
        Question::Noul {
            instructions: "Is this pattern of gate denials most likely a legitimate caller missing an allowlist entry, rather than probing?".into(),
        },
    );
    Request {
        model: String::new(),
        state: serde_json::to_value(g).expect("serializable"),
        questions,
    }
}

/// Validate a response into a note, or drop it. Fail closed: any shape, range or id
/// mismatch yields `None`, never a guess.
pub fn validate(g: &GroupView, resp: &Response, backend: &str) -> Option<Note> {
    if resp.answers.len() != 1 {
        return None;
    }
    let Some(Answer::Noul { noul }) = resp.answers.get(Q) else {
        return None;
    };
    if !noul.is_finite() || !(0.0..=1.0).contains(noul) {
        return None;
    }
    let triage = if *noul >= 0.8 {
        Triage::LikelyMisconfiguration
    } else if *noul <= 0.2 {
        Triage::LikelyProbe
    } else {
        Triage::Unclear
    };
    Some(Note {
        rule: g.rule.clone(),
        triage,
        p_legitimate: *noul,
        backend: backend.to_string(),
        backend_model: resp.model.clone(),
        advisory: true,
    })
}

/// Ask the backend about one group. A transport or parse error returns `None`.
pub fn advise<B: Backend>(b: &B, g: &GroupView) -> Option<Note> {
    let req = build_request(g);
    if req.questions.len() > MAX_QUESTIONS
        || serde_json::to_string(&req.state).map_or(true, |s| s.len() > MAX_STATE_BYTES)
    {
        return None;
    }
    validate(g, &b.ask(&req).ok()?, &b.id())
}

/// Blocking HTTP transport. Plain http is accepted only for loopback (a local model);
/// anything else must be https. Short timeout, no redirects.
pub struct ReqwestTransport;

impl Transport for ReqwestTransport {
    fn post_json(&self, url: &str, bearer: Option<&str>, body: &str) -> Result<String> {
        let loopback = url.starts_with("http://127.0.0.1")
            || url.starts_with("http://localhost")
            || url.starts_with("http://[::1]");
        if !(url.starts_with("https://") || loopback) {
            bail!("advisor backend url must be https (or loopback http)");
        }
        membrane_gate::tls::install_default_provider();
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let mut rq = client
            .post(url)
            .header("content-type", "application/json")
            .body(body.to_string());
        if let Some(t) = bearer {
            rq = rq.bearer_auth(t);
        }
        let resp = rq.send()?;
        if !resp.status().is_success() {
            bail!("backend returned {}", resp.status());
        }
        Ok(resp.text()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct Canned(RefCell<Vec<String>>, String);
    impl Transport for Canned {
        fn post_json(&self, url: &str, bearer: Option<&str>, body: &str) -> Result<String> {
            self.0
                .borrow_mut()
                .push(format!("{url}|{}|{body}", bearer.unwrap_or("-")));
            Ok(self.1.clone())
        }
    }
    fn view() -> GroupView {
        GroupView {
            rule: "tool_not_allowed".into(),
            denials: 5,
            distinct_subjects: 1,
            identified_callers: 1,
        }
    }
    const JEV: &str = r#"{"model":"jev-1.13.0","answers":{"legit":{"type":"noul","noul":0.99}},"usage":{"input_tokens":3,"output_tokens":1}}"#;

    #[test]
    fn jev_shaped_reply_becomes_advisory_note() {
        let t = Canned(RefCell::new(vec![]), JEV.into());
        let b = HttpBackend {
            transport: t,
            url: "https://api.typesafe.ai/v1/systemone".into(),
            bearer: Some("k".into()),
            model: "jev-latest".into(),
            name: "jev-api",
        };
        let n = advise(&b, &view()).unwrap();
        assert_eq!(n.triage, Triage::LikelyMisconfiguration);
        assert!(n.advisory);
        assert_eq!(n.backend_model.as_deref(), Some("jev-1.13.0"));
        let sent = b.transport.0.borrow()[0].clone();
        assert!(sent.contains("\"model\":\"jev-latest\"") && sent.contains("\"type\":\"noul\""));
    }

    #[test]
    fn cloudflare_rest_envelope_is_unwrapped_and_failure_dropped() {
        let ok = r#"{"result":{"model":"clef","answers":{"legit":{"type":"noul","noul":0.9}}},"success":true,"errors":[],"messages":[]}"#;
        let bad = r#"{"result":{"answers":{"legit":{"type":"noul","noul":0.9}}},"success":false,"errors":[{"code":1}]}"#;
        let mk = |body: &str| HttpBackend {
            transport: Canned(RefCell::new(vec![]), body.into()),
            url: "u".into(),
            bearer: None,
            model: "clef".into(),
            name: "clef-workers-ai",
        };
        assert_eq!(
            advise(&mk(ok), &view()).unwrap().triage,
            Triage::LikelyMisconfiguration
        );
        assert!(advise(&mk(bad), &view()).is_none());
    }

    #[test]
    fn invalid_output_is_dropped() {
        for bad in [
            r#"{"answers":{"legit":{"type":"noul","noul":1.5}}}"#,
            r#"{"answers":{"legit":{"type":"choice","choice":"allow"}}}"#,
            r#"{"answers":{"other":{"type":"noul","noul":0.9}}}"#,
            r#"{"answers":{"legit":{"type":"noul","noul":0.9},"x":{"type":"noul","noul":0.9}}}"#,
            r#"not json"#,
        ] {
            let b = HttpBackend {
                transport: Canned(RefCell::new(vec![]), bad.into()),
                url: "u".into(),
                bearer: None,
                model: "m".into(),
                name: "t",
            };
            assert!(advise(&b, &view()).is_none(), "{bad}");
        }
    }

    #[test]
    fn local_backend_needs_no_secret_and_swaps_by_config() {
        let cfg: Config = serde_json::from_str(r#"{"backend":"clef_local","url":"http://127.0.0.1:8000/v1/systemone","model":"clef-flash"}"#).unwrap();
        let b = from_config(&cfg, Canned(RefCell::new(vec![]), JEV.into())).unwrap();
        assert_eq!(b.id(), "clef-local:clef-flash");
        assert!(advise(&b, &view()).is_some());
    }

    #[test]
    fn missing_token_fails_closed() {
        let cfg = Config::JevApi {
            token_env: "MEMBRANE_TEST_NO_SUCH_TOKEN".into(),
        };
        assert!(from_config(&cfg, Canned(RefCell::new(vec![]), String::new())).is_err());
    }

    #[test]
    fn triage_has_no_authorizing_variant() {
        let s = serde_json::to_string(&[
            Triage::LikelyMisconfiguration,
            Triage::LikelyProbe,
            Triage::Unclear,
        ])
        .unwrap();
        assert!(!s.contains("allow") && !s.contains("apply"));
    }
}
