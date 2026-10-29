//! Live SIEM webhook shipper for Membrane authorization telemetry.
//!
//! Delivery is fail-open by default: webhook outages must not block the gate.
//! Secrets (URL auth headers) come only from the environment — never hardcode.

use crate::siem::{
    build_ocsf_inspired_pack, render_jsonl, SiemEvent, OCSF_INSPIRED_SCHEMA, SIEM_SCHEMA_VERSION,
};
use async_trait::async_trait;
use serde::Serialize;
use serde_json::json;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

pub const DEFAULT_SECRET_HEADER: &str = "X-Membrane-Webhook-Secret";
pub const ENV_WEBHOOK_URL: &str = "MEMBRANE_SIEM_WEBHOOK_URL";
pub const ENV_WEBHOOK_FORMAT: &str = "MEMBRANE_SIEM_WEBHOOK_FORMAT";
pub const ENV_WEBHOOK_SECRET: &str = "MEMBRANE_SIEM_WEBHOOK_SECRET";
pub const ENV_WEBHOOK_SECRET_HEADER: &str = "MEMBRANE_SIEM_WEBHOOK_SECRET_HEADER";
pub const ENV_WEBHOOK_FAIL_OPEN: &str = "MEMBRANE_SIEM_WEBHOOK_FAIL_OPEN";
pub const ENV_WEBHOOK_DEAD_LETTER: &str = "MEMBRANE_SIEM_WEBHOOK_DEAD_LETTER";
pub const ENV_WEBHOOK_MAX_ATTEMPTS: &str = "MEMBRANE_SIEM_WEBHOOK_MAX_ATTEMPTS";
pub const ENV_WEBHOOK_BACKOFF_MS: &str = "MEMBRANE_SIEM_WEBHOOK_BACKOFF_MS";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiemWebhookFormat {
    Jsonl,
    Ocsf,
}

impl SiemWebhookFormat {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "jsonl" | "ndjson" => Some(Self::Jsonl),
            "ocsf" => Some(Self::Ocsf),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Jsonl => "jsonl",
            Self::Ocsf => "ocsf",
        }
    }

    pub fn content_type(self) -> &'static str {
        match self {
            Self::Jsonl => "application/x-ndjson",
            Self::Ocsf => "application/json",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SiemWebhookConfig {
    pub urls: Vec<String>,
    pub format: SiemWebhookFormat,
    pub shared_secret: Option<String>,
    pub shared_secret_header: String,
    /// Total POST attempts per URL (including the first try).
    pub max_attempts: u32,
    pub initial_backoff: Duration,
    /// When true, delivery failures are logged/dead-lettered but do not surface
    /// as hard errors to callers that honor fail-open.
    pub fail_open: bool,
    pub dead_letter_path: Option<PathBuf>,
}

impl SiemWebhookConfig {
    /// Load from environment. Returns `Ok(None)` when no webhook URL is set.
    pub fn from_env() -> Result<Option<Self>, String> {
        let Some(raw_urls) = std::env::var(ENV_WEBHOOK_URL).ok() else {
            return Ok(None);
        };
        let urls: Vec<String> = raw_urls
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect();
        if urls.is_empty() {
            return Ok(None);
        }

        let format = match std::env::var(ENV_WEBHOOK_FORMAT) {
            Ok(raw) => SiemWebhookFormat::parse(&raw).ok_or_else(|| {
                format!("{ENV_WEBHOOK_FORMAT} must be jsonl or ocsf, got {raw:?}")
            })?,
            Err(_) => SiemWebhookFormat::Jsonl,
        };

        let shared_secret = std::env::var(ENV_WEBHOOK_SECRET)
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        let shared_secret_header = std::env::var(ENV_WEBHOOK_SECRET_HEADER)
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| DEFAULT_SECRET_HEADER.into());

        let fail_open = match std::env::var(ENV_WEBHOOK_FAIL_OPEN) {
            Ok(raw) => parse_bool(&raw).ok_or_else(|| {
                format!("{ENV_WEBHOOK_FAIL_OPEN} must be true or false, got {raw:?}")
            })?,
            Err(_) => true,
        };

        let dead_letter_path = std::env::var(ENV_WEBHOOK_DEAD_LETTER)
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .map(PathBuf::from);

        let max_attempts = match std::env::var(ENV_WEBHOOK_MAX_ATTEMPTS) {
            Ok(raw) => raw
                .parse::<u32>()
                .map_err(|_| format!("{ENV_WEBHOOK_MAX_ATTEMPTS} must be a positive integer"))
                .and_then(|value| {
                    if value == 0 {
                        Err(format!("{ENV_WEBHOOK_MAX_ATTEMPTS} must be >= 1"))
                    } else {
                        Ok(value)
                    }
                })?,
            Err(_) => 4,
        };

        let backoff_ms = match std::env::var(ENV_WEBHOOK_BACKOFF_MS) {
            Ok(raw) => raw
                .parse::<u64>()
                .map_err(|_| format!("{ENV_WEBHOOK_BACKOFF_MS} must be an integer"))?,
            Err(_) => 100,
        };

        Ok(Some(Self {
            urls,
            format,
            shared_secret,
            shared_secret_header,
            max_attempts,
            initial_backoff: Duration::from_millis(backoff_ms),
            fail_open,
            dead_letter_path,
        }))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SiemWebhookError {
    #[error("serialize SIEM payload: {0}")]
    Serialize(String),
    #[error("webhook delivery failed after {attempts} attempt(s): {detail}")]
    Delivery { attempts: u32, detail: String },
    #[error("dead-letter write failed: {0}")]
    DeadLetter(String),
    #[error("HTTP client: {0}")]
    Http(String),
}

// async_trait adds a redundant must_use to its boxed Future on Rust 1.99.
#[allow(clippy::double_must_use)]
#[async_trait]
pub trait WebhookPoster: Send + Sync {
    async fn post(
        &self,
        url: &str,
        headers: &[(String, String)],
        body: String,
    ) -> Result<u16, String>;
}

#[derive(Debug, Clone)]
pub struct ReqwestWebhookPoster {
    client: reqwest::Client,
}

impl ReqwestWebhookPoster {
    pub fn new() -> Result<Self, SiemWebhookError> {
        crate::tls::install_default_provider();
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent(concat!("membrane-siem-webhook/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|err| SiemWebhookError::Http(err.to_string()))?;
        Ok(Self { client })
    }
}

impl Default for ReqwestWebhookPoster {
    fn default() -> Self {
        Self::new().expect("reqwest client")
    }
}

#[async_trait]
impl WebhookPoster for ReqwestWebhookPoster {
    async fn post(
        &self,
        url: &str,
        headers: &[(String, String)],
        body: String,
    ) -> Result<u16, String> {
        let mut request = self.client.post(url).body(body);
        for (name, value) in headers {
            request = request.header(name.as_str(), value.as_str());
        }
        let response = request.send().await.map_err(|err| err.to_string())?;
        Ok(response.status().as_u16())
    }
}

pub struct SiemWebhookShipper<P: WebhookPoster = ReqwestWebhookPoster> {
    config: SiemWebhookConfig,
    poster: P,
}

impl SiemWebhookShipper<ReqwestWebhookPoster> {
    pub fn from_config(config: SiemWebhookConfig) -> Result<Self, SiemWebhookError> {
        Ok(Self {
            config,
            poster: ReqwestWebhookPoster::new()?,
        })
    }

    /// Construct from env when `MEMBRANE_SIEM_WEBHOOK_URL` is set.
    pub fn from_env() -> Result<Option<Self>, SiemWebhookError> {
        match SiemWebhookConfig::from_env() {
            Ok(Some(config)) => Ok(Some(Self::from_config(config)?)),
            Ok(None) => Ok(None),
            Err(err) => Err(SiemWebhookError::Http(err)),
        }
    }
}

impl<P: WebhookPoster> SiemWebhookShipper<P> {
    pub fn new(config: SiemWebhookConfig, poster: P) -> Self {
        Self { config, poster }
    }

    pub fn config(&self) -> &SiemWebhookConfig {
        &self.config
    }

    pub fn render_body(
        &self,
        event: &SiemEvent,
    ) -> Result<(String, &'static str), SiemWebhookError> {
        match self.config.format {
            SiemWebhookFormat::Jsonl => {
                let body = render_jsonl(std::slice::from_ref(event))
                    .map_err(|err| SiemWebhookError::Serialize(err.to_string()))?;
                Ok((body, self.config.format.content_type()))
            }
            SiemWebhookFormat::Ocsf => {
                let projected = event.to_ocsf_inspired();
                let body = serde_json::to_string(&projected)
                    .map_err(|err| SiemWebhookError::Serialize(err.to_string()))?;
                Ok((body, self.config.format.content_type()))
            }
        }
    }

    fn request_headers(&self, content_type: &str) -> Vec<(String, String)> {
        let mut headers = vec![("Content-Type".into(), content_type.into())];
        if let Some(secret) = &self.config.shared_secret {
            headers.push((self.config.shared_secret_header.clone(), secret.clone()));
        }
        headers.push(("X-Membrane-Schema".into(), SIEM_SCHEMA_VERSION.into()));
        if self.config.format == SiemWebhookFormat::Ocsf {
            headers.push(("X-Membrane-Ocsf-Schema".into(), OCSF_INSPIRED_SCHEMA.into()));
        }
        headers
    }

    /// Deliver to every configured URL with retries and optional dead-letter.
    pub async fn deliver(&self, event: &SiemEvent) -> Result<(), SiemWebhookError> {
        let (body, content_type) = self.render_body(event)?;
        let headers = self.request_headers(content_type);
        let mut failures = Vec::new();

        for url in &self.config.urls {
            match self.deliver_one(url, &headers, body.clone()).await {
                Ok(()) => {}
                Err(err) => {
                    if let Some(path) = &self.config.dead_letter_path {
                        write_dead_letter(path, url, event, &err)?;
                    }
                    failures.push(format!("{url}: {err}"));
                }
            }
        }

        if failures.is_empty() {
            Ok(())
        } else {
            Err(SiemWebhookError::Delivery {
                attempts: self.config.max_attempts,
                detail: failures.join("; "),
            })
        }
    }

    async fn deliver_one(
        &self,
        url: &str,
        headers: &[(String, String)],
        body: String,
    ) -> Result<(), SiemWebhookError> {
        let mut last_detail = String::new();
        for attempt in 1..=self.config.max_attempts {
            match self.poster.post(url, headers, body.clone()).await {
                Ok(status) if (200..300).contains(&status) => {
                    info!(
                        url = %url,
                        attempt,
                        status,
                        format = self.config.format.as_str(),
                        "SIEM webhook delivered"
                    );
                    return Ok(());
                }
                Ok(status) => {
                    last_detail = format!("HTTP {status}");
                }
                Err(err) => {
                    last_detail = err;
                }
            }

            if attempt < self.config.max_attempts {
                let shift = (attempt - 1).min(8);
                let delay = self.config.initial_backoff.saturating_mul(1u32 << shift);
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
            }
        }

        Err(SiemWebhookError::Delivery {
            attempts: self.config.max_attempts,
            detail: last_detail,
        })
    }

    /// Honor `fail_open`: log and swallow delivery errors when configured.
    pub async fn deliver_respecting_fail_open(
        &self,
        event: &SiemEvent,
    ) -> Result<(), SiemWebhookError> {
        match self.deliver(event).await {
            Ok(()) => Ok(()),
            Err(err) if self.config.fail_open => {
                warn!(
                    error = %err,
                    event_type = %event.event_type,
                    event_id = %event.event_id,
                    "SIEM webhook delivery failed (fail-open)"
                );
                Ok(())
            }
            Err(err) => Err(err),
        }
    }
}

/// Fire-and-forget best-effort ship for gate paths (never blocks the caller).
pub fn spawn_siem_ship(shipper: &Option<Arc<SiemWebhookShipper>>, event: SiemEvent) {
    let Some(shipper) = shipper.clone() else {
        return;
    };
    tokio::spawn(async move {
        let _ = shipper.deliver_respecting_fail_open(&event).await;
    });
}

pub fn map_and_spawn_siem_ship(
    shipper: &Option<Arc<SiemWebhookShipper>>,
    membrane_event: &crate::MembraneEvent,
    bus_event_id: Option<&str>,
) {
    let Some(_) = shipper else {
        return;
    };
    let mapped = SiemEvent::from_membrane_event(membrane_event, bus_event_id);
    spawn_siem_ship(shipper, mapped);
}

#[derive(Debug, Serialize)]
struct DeadLetterRecord<'a> {
    failed_at: i64,
    url: &'a str,
    error: String,
    attempts: u32,
    format_note: &'static str,
    event: &'a SiemEvent,
}

fn write_dead_letter(
    path: &Path,
    url: &str,
    event: &SiemEvent,
    err: &SiemWebhookError,
) -> Result<(), SiemWebhookError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|io_err| SiemWebhookError::DeadLetter(io_err.to_string()))?;
        }
    }

    let attempts = match err {
        SiemWebhookError::Delivery { attempts, .. } => *attempts,
        _ => 0,
    };
    let record = DeadLetterRecord {
        failed_at: now_secs(),
        url,
        error: err.to_string(),
        attempts,
        format_note: "membrane.action_receipt dead-letter; digests only",
        event,
    };
    let line = serde_json::to_string(&record)
        .map_err(|ser_err| SiemWebhookError::DeadLetter(ser_err.to_string()))?;

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|io_err| SiemWebhookError::DeadLetter(io_err.to_string()))?;
    writeln!(file, "{line}").map_err(|io_err| SiemWebhookError::DeadLetter(io_err.to_string()))?;
    Ok(())
}

fn parse_bool(raw: &str) -> Option<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
}

/// Convenience: render a multi-event OCSF pack body (batch / file exporters).
pub fn render_ocsf_webhook_pack(events: &[SiemEvent], exported_at: i64) -> serde_json::Value {
    json!(build_ocsf_inspired_pack(events, exported_at))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::siem::SIEM_SCHEMA_VERSION;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    #[derive(Default)]
    struct ScriptedPoster {
        statuses: Mutex<Vec<Result<u16, String>>>,
        calls: AtomicUsize,
        bodies: Mutex<Vec<String>>,
        headers: Mutex<Vec<Vec<(String, String)>>>,
    }

    impl ScriptedPoster {
        fn with_statuses(statuses: Vec<Result<u16, String>>) -> Self {
            Self {
                statuses: Mutex::new(statuses),
                calls: AtomicUsize::new(0),
                bodies: Mutex::new(Vec::new()),
                headers: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl WebhookPoster for ScriptedPoster {
        async fn post(
            &self,
            _url: &str,
            headers: &[(String, String)],
            body: String,
        ) -> Result<u16, String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.bodies.lock().unwrap().push(body);
            self.headers.lock().unwrap().push(headers.to_vec());
            let mut statuses = self.statuses.lock().unwrap();
            if statuses.is_empty() {
                return Err("no scripted status left".into());
            }
            statuses.remove(0)
        }
    }

    fn sample_event() -> SiemEvent {
        SiemEvent {
            schema_version: SIEM_SCHEMA_VERSION.into(),
            timestamp: 1_700_000_000,
            event_id: "evt-1".into(),
            event_type: "blocked_action".into(),
            outcome: "blocked".into(),
            severity: "high".into(),
            agent_id: "agent-1".into(),
            session_id: Some("session-1".into()),
            scope_id: Some("scope-1".into()),
            models: vec!["allowlisted-model".into()],
            tools: vec!["tool.write".into()],
            policy_hash: Some("aa".repeat(32)),
            receipt_hash: Some("bb".repeat(32)),
            parent_receipt_hash: None,
            reason: Some("tool not in allowlist".into()),
            simulation: false,
            source_event_type: "membrane.action.blocked".into(),
        }
    }

    fn test_config(poster_ready: bool) -> SiemWebhookConfig {
        let _ = poster_ready;
        SiemWebhookConfig {
            urls: vec!["http://siem.example/hook".into()],
            format: SiemWebhookFormat::Jsonl,
            shared_secret: Some("test-secret".into()),
            shared_secret_header: DEFAULT_SECRET_HEADER.into(),
            max_attempts: 3,
            initial_backoff: Duration::from_millis(0),
            fail_open: true,
            dead_letter_path: None,
        }
    }

    #[tokio::test]
    async fn retries_then_succeeds() {
        let poster = ScriptedPoster::with_statuses(vec![Ok(500), Ok(503), Ok(204)]);
        let shipper = SiemWebhookShipper::new(test_config(true), poster);
        shipper.deliver(&sample_event()).await.unwrap();
        assert_eq!(shipper.poster.calls.load(Ordering::SeqCst), 3);
        let body = shipper.poster.bodies.lock().unwrap()[0].clone();
        assert!(body.contains("blocked_action"));
        assert!(body.ends_with('\n'));
        let headers = &shipper.poster.headers.lock().unwrap()[0];
        assert!(headers
            .iter()
            .any(|(k, v)| k == DEFAULT_SECRET_HEADER && v == "test-secret"));
    }

    #[tokio::test]
    async fn exhausts_retries_and_dead_letters() {
        let dir = std::env::temp_dir().join(format!(
            "membrane-siem-dlq-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let dlq = dir.join("dead.jsonl");

        let poster =
            ScriptedPoster::with_statuses(vec![Ok(500), Err("connection reset".into()), Ok(502)]);
        let mut config = test_config(true);
        config.dead_letter_path = Some(dlq.clone());
        config.fail_open = false;
        let shipper = SiemWebhookShipper::new(config, poster);

        let err = shipper.deliver(&sample_event()).await.unwrap_err();
        assert!(matches!(
            err,
            SiemWebhookError::Delivery { attempts: 3, .. }
        ));
        assert_eq!(shipper.poster.calls.load(Ordering::SeqCst), 3);

        let dlq_body = std::fs::read_to_string(&dlq).unwrap();
        assert!(dlq_body.contains("blocked_action"));
        assert!(dlq_body.contains("HTTP 502") || dlq_body.contains("connection reset"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn fail_open_swallows_delivery_error() {
        let poster = ScriptedPoster::with_statuses(vec![Ok(500), Ok(500), Ok(500)]);
        let shipper = SiemWebhookShipper::new(test_config(true), poster);
        shipper
            .deliver_respecting_fail_open(&sample_event())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn ocsf_body_is_single_projected_object() {
        let poster = ScriptedPoster::with_statuses(vec![Ok(200)]);
        let mut config = test_config(true);
        config.format = SiemWebhookFormat::Ocsf;
        let shipper = SiemWebhookShipper::new(config, poster);
        shipper.deliver(&sample_event()).await.unwrap();
        let body = shipper.poster.bodies.lock().unwrap()[0].clone();
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["activity_name"], "Action Blocked");
        assert!(value.get("class_uid").is_none());
        assert_eq!(
            value["unmapped"]["membrane"]["event_type"],
            "blocked_action"
        );
    }

    #[test]
    fn config_from_env_parses_urls_and_defaults() {
        std::env::set_var(
            ENV_WEBHOOK_URL,
            "https://a.example/hook, https://b.example/hook",
        );
        std::env::remove_var(ENV_WEBHOOK_FORMAT);
        std::env::remove_var(ENV_WEBHOOK_FAIL_OPEN);
        std::env::set_var(ENV_WEBHOOK_SECRET, "s3cret");
        let config = SiemWebhookConfig::from_env().unwrap().unwrap();
        assert_eq!(config.urls.len(), 2);
        assert_eq!(config.format, SiemWebhookFormat::Jsonl);
        assert!(config.fail_open);
        assert_eq!(config.shared_secret.as_deref(), Some("s3cret"));
        std::env::remove_var(ENV_WEBHOOK_URL);
        std::env::remove_var(ENV_WEBHOOK_SECRET);
    }
}
