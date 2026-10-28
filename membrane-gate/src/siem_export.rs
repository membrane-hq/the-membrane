//! Bounded, durable export of receipts and denials to a customer SIEM.
//!
//! Delivery is at-least-once through an on-disk spool of hash-chained
//! envelopes. The spool and every retry loop are bounded. A configured failure
//! mode decides what the gate does when the SIEM cannot keep up: refuse new
//! authorizations (`fail_closed`) or keep authorizing and record an explicit gap
//! (`degrade`). Nothing here is an authorization input for the signed receipt
//! chain; the gate's receipts are produced before an event is queued.
use crate::GateError;
use async_trait::async_trait;
use membrane_core::SiemEvent;
use rustls::{
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        WebPkiServerVerifier,
    },
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    collections::VecDeque,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};
use tokio::sync::Notify;
use tracing::{info, warn};

pub const ENV_EXPORT_CONFIG: &str = "MEMBRANE_SIEM_EXPORT_CONFIG";
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const MAX_URL_LEN: usize = 2048;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FailureMode {
    /// Refuse new authorizations while the export cannot keep up.
    FailClosed,
    /// Keep authorizing; drop the newest events past the buffer and record a gap.
    Degrade,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Target {
    /// Splunk HTTP Event Collector, `/services/collector/event`.
    SplunkHec {
        url: String,
        token_env: String,
        #[serde(default)]
        source: Option<String>,
        #[serde(default)]
        sourcetype: Option<String>,
        #[serde(default)]
        index: Option<String>,
        #[serde(default)]
        host: Option<String>,
    },
    /// Datadog logs intake, `/api/v2/logs`.
    DatadogLogs {
        url: String,
        token_env: String,
        #[serde(default)]
        service: Option<String>,
        #[serde(default)]
        tags: Option<String>,
        #[serde(default)]
        hostname: Option<String>,
    },
    /// Generic HTTPS endpoint receiving newline-delimited JSON envelopes.
    Webhook {
        url: String,
        /// Optional. Without it no credential is sent.
        #[serde(default)]
        token_env: Option<String>,
        /// Header carrying the token. Default `Authorization` with a `Bearer ` prefix.
        #[serde(default)]
        auth_header: Option<String>,
    },
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// PEM trust anchors for the endpoint. Ambient/public roots are never used.
    pub ca_bundle_file: PathBuf,
    /// Optional lowercase hex SHA-256 fingerprints of the accepted leaf
    /// certificate DER, checked after normal chain and name validation.
    #[serde(default)]
    pub pinned_cert_sha256: Vec<String>,
}

fn d_max_events() -> usize {
    10_000
}
fn d_batch_events() -> usize {
    100
}
fn d_batch_bytes() -> usize {
    1 << 20
}
fn d_flush() -> u64 {
    5
}
fn d_timeout() -> u64 {
    10
}
fn d_backoff_ms() -> u64 {
    500
}
fn d_backoff_max() -> u64 {
    60
}
fn d_lag() -> u64 {
    300
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportConfig {
    /// Required; there is deliberately no default.
    pub failure_mode: FailureMode,
    pub target: Target,
    pub tls: TlsConfig,
    /// Defaults to `<MEMBRANE_OPERATION_DIR>/siem-export`.
    #[serde(default)]
    pub spool_dir: Option<PathBuf>,
    #[serde(default = "d_max_events")]
    pub max_buffered_events: usize,
    #[serde(default = "d_batch_events")]
    pub batch_max_events: usize,
    #[serde(default = "d_batch_bytes")]
    pub batch_max_bytes: usize,
    #[serde(default = "d_flush")]
    pub flush_interval_secs: u64,
    #[serde(default = "d_timeout")]
    pub request_timeout_secs: u64,
    #[serde(default = "d_backoff_ms")]
    pub backoff_initial_ms: u64,
    #[serde(default = "d_backoff_max")]
    pub backoff_max_secs: u64,
    /// `fail_closed` refuses new work once the oldest unacknowledged event is this old.
    #[serde(default = "d_lag")]
    pub fail_closed_lag_secs: u64,
}

fn bad(msg: impl std::fmt::Display) -> GateError {
    GateError::Registry(format!("SIEM export config: {msg}"))
}

fn check_url(raw: &str) -> Result<(), GateError> {
    let url = reqwest::Url::parse(raw).map_err(|_| bad("invalid url"))?;
    if raw.len() > MAX_URL_LEN
        || url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(bad(
            "url must be HTTPS with no credentials, query or fragment (put credentials in token_env)",
        ));
    }
    Ok(())
}

fn check_env_name(name: &str) -> Result<(), GateError> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    {
        return Err(bad(
            "token_env must be an environment variable name like SIEM_TOKEN",
        ));
    }
    Ok(())
}

fn check_label(name: &str, value: &Option<String>) -> Result<(), GateError> {
    if let Some(v) = value {
        if v.is_empty() || v.len() > 256 || v.chars().any(|c| c.is_control()) {
            return Err(bad(format!("{name} must be 1-256 printable characters")));
        }
    }
    Ok(())
}

impl ExportConfig {
    pub fn validate(&self) -> Result<(), GateError> {
        let in_range = |name: &str, v: u64, lo: u64, hi: u64| {
            if (lo..=hi).contains(&v) {
                Ok(())
            } else {
                Err(bad(format!("{name} must be {lo}..={hi}")))
            }
        };
        in_range(
            "max_buffered_events",
            self.max_buffered_events as u64,
            100,
            1_000_000,
        )?;
        in_range("batch_max_events", self.batch_max_events as u64, 1, 1000)?;
        in_range(
            "batch_max_bytes",
            self.batch_max_bytes as u64,
            4096,
            4 << 20,
        )?;
        in_range("flush_interval_secs", self.flush_interval_secs, 1, 300)?;
        in_range("request_timeout_secs", self.request_timeout_secs, 1, 60)?;
        in_range("backoff_initial_ms", self.backoff_initial_ms, 50, 60_000)?;
        in_range("backoff_max_secs", self.backoff_max_secs, 1, 3600)?;
        in_range(
            "fail_closed_lag_secs",
            self.fail_closed_lag_secs,
            10,
            86_400,
        )?;
        if self.batch_max_events > self.max_buffered_events {
            return Err(bad("batch_max_events exceeds max_buffered_events"));
        }
        if Duration::from_millis(self.backoff_initial_ms)
            > Duration::from_secs(self.backoff_max_secs)
        {
            return Err(bad("backoff_initial_ms exceeds backoff_max_secs"));
        }
        for pin in &self.tls.pinned_cert_sha256 {
            parse_pin(pin)?;
        }
        if self.tls.pinned_cert_sha256.len() > 8 {
            return Err(bad("at most 8 pinned_cert_sha256 entries"));
        }
        match &self.target {
            Target::SplunkHec {
                url,
                token_env,
                source,
                sourcetype,
                index,
                host,
            } => {
                check_url(url)?;
                check_env_name(token_env)?;
                for (n, v) in [
                    ("source", source),
                    ("sourcetype", sourcetype),
                    ("index", index),
                    ("host", host),
                ] {
                    check_label(n, v)?;
                }
            }
            Target::DatadogLogs {
                url,
                token_env,
                service,
                tags,
                hostname,
            } => {
                check_url(url)?;
                check_env_name(token_env)?;
                for (n, v) in [("service", service), ("tags", tags), ("hostname", hostname)] {
                    check_label(n, v)?;
                }
            }
            Target::Webhook {
                url,
                token_env,
                auth_header,
            } => {
                check_url(url)?;
                if let Some(env) = token_env {
                    check_env_name(env)?;
                }
                if let Some(h) = auth_header {
                    if token_env.is_none()
                        || h.is_empty()
                        || reqwest::header::HeaderName::from_bytes(h.as_bytes()).is_err()
                    {
                        return Err(bad("auth_header needs token_env and a valid header name"));
                    }
                }
            }
        }
        Ok(())
    }

    fn url(&self) -> &str {
        match &self.target {
            Target::SplunkHec { url, .. }
            | Target::DatadogLogs { url, .. }
            | Target::Webhook { url, .. } => url,
        }
    }
}

fn parse_pin(raw: &str) -> Result<[u8; 32], GateError> {
    let bytes =
        hex::decode(raw).map_err(|_| bad("pinned_cert_sha256 must be 64 hex characters"))?;
    bytes
        .try_into()
        .map_err(|_| bad("pinned_cert_sha256 must be 64 hex characters"))
}

/// Never printed: Debug redacts, and values only travel in sensitive headers.
#[derive(Clone)]
struct Secret(String);
impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[redacted]")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Gap {
    /// `started` is written the moment the buffer overflows; `ended` carries the count.
    pub phase: String,
    pub dropped: u64,
}

/// One link of the export chain. `hash` covers every other field.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Envelope {
    pub seq: u64,
    pub prev: String,
    pub ts: i64,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub event: Option<SiemEvent>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub gap: Option<Gap>,
    pub hash: String,
}

fn envelope_hash(
    seq: u64,
    prev: &str,
    ts: i64,
    kind: &str,
    event: &Option<SiemEvent>,
    gap: &Option<Gap>,
) -> Result<String, GateError> {
    let bytes = serde_json::to_vec(&(seq, prev, ts, kind, event, gap))
        .map_err(|e| bad(format!("hash: {e}")))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

/// Check linkage and hashes of consecutive envelopes. `expected_prev` is the hash
/// that must precede the first one.
pub fn verify_chain(envelopes: &[Envelope], expected_prev: &str) -> Result<(), GateError> {
    let mut prev = expected_prev.to_string();
    let mut seq = envelopes.first().map(|e| e.seq);
    for e in envelopes {
        if Some(e.seq) != seq
            || e.prev != prev
            || e.hash != envelope_hash(e.seq, &e.prev, e.ts, &e.kind, &e.event, &e.gap)?
        {
            return Err(bad("export spool chain discontinuity"));
        }
        prev = e.hash.clone();
        seq = Some(e.seq + 1);
    }
    Ok(())
}

// ----- payloads -----

fn envelope_value(e: &Envelope) -> Result<Value, GateError> {
    serde_json::to_value(e).map_err(|err| bad(format!("serialize: {err}")))
}

/// Request body for one batch. Pure so the formats can be tested without a network.
pub fn render_batch(
    target: &Target,
    batch: &[Envelope],
) -> Result<(Vec<u8>, &'static str), GateError> {
    let mut out = Vec::new();
    match target {
        Target::SplunkHec {
            source,
            sourcetype,
            index,
            host,
            ..
        } => {
            // HEC accepts concatenated JSON objects in one request.
            for e in batch {
                let mut obj = json!({
                    "time": e.ts,
                    "source": source.as_deref().unwrap_or("membrane"),
                    "sourcetype": sourcetype.as_deref().unwrap_or("membrane:receipt"),
                    "event": envelope_value(e)?,
                });
                if let Some(v) = index {
                    obj["index"] = json!(v);
                }
                if let Some(v) = host {
                    obj["host"] = json!(v);
                }
                out.extend(serde_json::to_vec(&obj).map_err(|e| bad(e.to_string()))?);
                out.push(b'\n');
            }
            Ok((out, "application/json"))
        }
        Target::DatadogLogs {
            service,
            tags,
            hostname,
            ..
        } => {
            let logs: Result<Vec<Value>, GateError> = batch
                .iter()
                .map(|e| {
                    let mut obj = json!({
                        "ddsource": "membrane",
                        "service": service.as_deref().unwrap_or("membrane"),
                        "message": format!("membrane {}", e.kind),
                        "membrane": envelope_value(e)?,
                    });
                    if let Some(v) = tags {
                        obj["ddtags"] = json!(v);
                    }
                    if let Some(v) = hostname {
                        obj["hostname"] = json!(v);
                    }
                    Ok(obj)
                })
                .collect();
            out = serde_json::to_vec(&logs?).map_err(|e| bad(e.to_string()))?;
            Ok((out, "application/json"))
        }
        Target::Webhook { .. } => {
            for e in batch {
                out.extend(serde_json::to_vec(e).map_err(|e| bad(e.to_string()))?);
                out.push(b'\n');
            }
            Ok((out, "application/x-ndjson"))
        }
    }
}

// ----- transport -----

// async_trait adds a redundant must_use to its boxed Future on Rust 1.99.
#[allow(clippy::double_must_use)]
#[async_trait]
trait Transport: Send + Sync {
    /// Returns the HTTP status. Errors carry no URL, header or body.
    async fn post(&self, body: Vec<u8>, content_type: &'static str) -> Result<u16, String>;
}

struct HttpTransport {
    client: reqwest::Client,
    url: String,
    auth: Option<(reqwest::header::HeaderName, reqwest::header::HeaderValue)>,
}

#[allow(clippy::double_must_use)]
#[async_trait]
impl Transport for HttpTransport {
    async fn post(&self, body: Vec<u8>, content_type: &'static str) -> Result<u16, String> {
        let mut req = self
            .client
            .post(&self.url)
            .header(reqwest::header::CONTENT_TYPE, content_type)
            .body(body);
        if let Some((name, value)) = &self.auth {
            req = req.header(name.clone(), value.clone());
        }
        let resp = req.send().await.map_err(|e| {
            let e = e.without_url();
            if e.is_timeout() {
                "request timed out".to_string()
            } else if e.is_connect() {
                "connection or TLS validation failed".to_string()
            } else {
                "request failed".to_string()
            }
        })?;
        Ok(resp.status().as_u16())
    }
}

#[derive(Debug)]
struct PinVerifier {
    inner: Arc<WebPkiServerVerifier>,
    pins: Vec<[u8; 32]>,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let verified =
            self.inner
                .verify_server_cert(end_entity, intermediates, server_name, ocsp, now)?;
        if !self.pins.is_empty() {
            let fp: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
            if !self.pins.contains(&fp) {
                return Err(rustls::Error::General("certificate pin mismatch".into()));
            }
        }
        Ok(verified)
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// rustls client config trusting only `ca_pem`, optionally also requiring a leaf pin.
pub fn pinned_tls_config(
    ca_pem: &[u8],
    pins: &[[u8; 32]],
) -> Result<rustls::ClientConfig, GateError> {
    use rustls::pki_types::pem::PemObject;
    let provider = membrane_core::tls::provider();
    let mut roots = RootCertStore::empty();
    let mut count = 0;
    for cert in CertificateDer::pem_slice_iter(ca_pem) {
        let cert = cert.map_err(|_| bad("ca_bundle_file is not valid PEM"))?;
        roots
            .add(cert)
            .map_err(|_| bad("ca_bundle_file holds an unusable certificate"))?;
        count += 1;
    }
    if count == 0 {
        return Err(bad("ca_bundle_file holds no certificates"));
    }
    let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|_| bad("could not build certificate verifier"))?;
    Ok(rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| bad("TLS protocol setup failed"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinVerifier {
            inner,
            pins: pins.to_vec(),
        }))
        .with_no_client_auth())
}

fn http_transport(cfg: &ExportConfig, secret: Option<Secret>) -> Result<HttpTransport, GateError> {
    let ca = fs::read(&cfg.tls.ca_bundle_file).map_err(|_| bad("cannot read ca_bundle_file"))?;
    let pins: Vec<[u8; 32]> = cfg
        .tls
        .pinned_cert_sha256
        .iter()
        .map(|p| parse_pin(p))
        .collect::<Result<_, _>>()?;
    let tls = pinned_tls_config(&ca, &pins)?;
    let client = reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(cfg.request_timeout_secs))
        .connect_timeout(Duration::from_secs(cfg.request_timeout_secs))
        .user_agent(concat!("membrane-siem-export/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|_| bad("HTTP client setup failed"))?;
    let auth = match (&cfg.target, secret) {
        (Target::SplunkHec { .. }, Some(s)) => {
            Some(("authorization".to_string(), format!("Splunk {}", s.0)))
        }
        (Target::DatadogLogs { .. }, Some(s)) => Some(("dd-api-key".to_string(), s.0)),
        (Target::Webhook { auth_header, .. }, Some(s)) => Some(match auth_header {
            Some(h) => (h.to_ascii_lowercase(), s.0),
            None => ("authorization".to_string(), format!("Bearer {}", s.0)),
        }),
        _ => None,
    };
    let auth = auth
        .map(|(name, value)| {
            let mut value = reqwest::header::HeaderValue::from_str(&value)
                .map_err(|_| bad("token holds characters that are invalid in a header"))?;
            value.set_sensitive(true);
            let name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| bad("invalid auth_header"))?;
            Ok::<_, GateError>((name, value))
        })
        .transpose()?;
    Ok(HttpTransport {
        client,
        url: cfg.url().to_string(),
        auth,
    })
}

// ----- exporter -----

struct State {
    pending: VecDeque<Envelope>,
    next_seq: u64,
    last_hash: String,
    acked_hash: String,
    acked_in_file: usize,
    overflow_open: bool,
    overflow_dropped: u64,
    dropped_total: u64,
    delivered_total: u64,
    consecutive_failures: u32,
    last_success: Option<i64>,
    last_error: Option<String>,
    io_failed: bool,
    batch_cap: usize,
}

#[derive(Debug, Serialize)]
pub struct ExportStatus {
    pub enabled: bool,
    pub failure_mode: FailureMode,
    pub state: &'static str,
    pub pending: usize,
    pub capacity: usize,
    pub oldest_pending_age_secs: Option<i64>,
    pub last_success_age_secs: Option<i64>,
    pub consecutive_failures: u32,
    pub dropped_total: u64,
    pub delivered_total: u64,
    pub last_error: Option<String>,
}

pub struct SiemExporter {
    cfg: ExportConfig,
    spool: PathBuf,
    cursor: PathBuf,
    state: Mutex<State>,
    wake: Notify,
    worker: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn io(e: std::io::Error) -> GateError {
    bad(format!("spool I/O: {}", e.kind()))
}

fn sync_dir(dir: &Path) -> Result<(), GateError> {
    File::open(dir).and_then(|f| f.sync_all()).map_err(io)
}

fn open_append(path: &Path) -> Result<File, GateError> {
    let mut o = OpenOptions::new();
    o.create(true).append(true);
    #[cfg(unix)]
    o.mode(0o600);
    o.open(path).map_err(io)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), GateError> {
    let tmp = path.with_extension("tmp");
    let mut o = OpenOptions::new();
    o.create(true).write(true).truncate(true);
    #[cfg(unix)]
    o.mode(0o600);
    let mut f = o.open(&tmp).map_err(io)?;
    f.write_all(bytes).map_err(io)?;
    f.sync_all().map_err(io)?;
    fs::rename(&tmp, path).map_err(io)?;
    sync_dir(path.parent().unwrap_or(Path::new(".")))
}

impl SiemExporter {
    /// Parse and validate `path`, resolve the token from the environment, load the
    /// spool and start the delivery task. Any problem is a startup error.
    pub fn start_from_file(path: &Path, default_dir: &Path) -> Result<Arc<Self>, GateError> {
        let text = fs::read_to_string(path).map_err(|_| bad("cannot read config file"))?;
        let cfg: ExportConfig = serde_yaml::from_str(&text).map_err(|e| {
            bad(format!(
                "parse: {}",
                e.to_string().lines().next().unwrap_or("")
            ))
        })?;
        cfg.validate()?;
        let env_name = match &cfg.target {
            Target::SplunkHec { token_env, .. } | Target::DatadogLogs { token_env, .. } => {
                Some(token_env.clone())
            }
            Target::Webhook { token_env, .. } => token_env.clone(),
        };
        let secret = match env_name {
            Some(name) => {
                let v = std::env::var(&name).unwrap_or_default();
                if v.trim().is_empty() {
                    return Err(bad(format!(
                        "environment variable {name} is unset or empty"
                    )));
                }
                Some(Secret(v.trim().to_string()))
            }
            None => None,
        };
        let transport = Arc::new(http_transport(&cfg, secret)?);
        let dir = cfg
            .spool_dir
            .clone()
            .unwrap_or_else(|| default_dir.join("siem-export"));
        Self::start(cfg, &dir, transport)
    }

    fn start(
        cfg: ExportConfig,
        dir: &Path,
        transport: Arc<dyn Transport>,
    ) -> Result<Arc<Self>, GateError> {
        let exporter = Arc::new(Self::open(cfg, dir)?);
        let task = exporter.clone();
        let handle = tokio::spawn(async move { task.run(transport).await });
        *exporter.worker.lock().map_err(|_| bad("poisoned"))? = Some(handle);
        Ok(exporter)
    }

    fn open(cfg: ExportConfig, dir: &Path) -> Result<Self, GateError> {
        fs::create_dir_all(dir).map_err(io)?;
        let spool = dir.join("spool.jsonl");
        let cursor = dir.join("cursor.json");
        let (acked_seq, acked_hash) = match fs::read(&cursor) {
            Ok(b) => {
                let v: Value =
                    serde_json::from_slice(&b).map_err(|_| bad("cursor.json is corrupt"))?;
                let seq = v["acked_seq"]
                    .as_u64()
                    .ok_or_else(|| bad("cursor.json is corrupt"))?;
                let hash = v["acked_hash"]
                    .as_str()
                    .ok_or_else(|| bad("cursor.json is corrupt"))?;
                (Some(seq), hash.to_string())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (None, GENESIS.to_string()),
            Err(e) => return Err(io(e)),
        };
        let bytes = match fs::read(&spool) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => vec![],
            Err(e) => return Err(io(e)),
        };
        if !bytes.is_empty() && !bytes.ends_with(b"\n") {
            return Err(bad("torn export spool tail; operator review required"));
        }
        let mut all: Vec<Envelope> = vec![];
        for line in bytes.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
            all.push(serde_json::from_slice(line).map_err(|_| bad("export spool is corrupt"))?);
        }
        let mut pending: VecDeque<Envelope> = VecDeque::new();
        let mut acked_in_file = 0;
        let (mut next_seq, mut last_hash) = match acked_seq {
            Some(s) => (s + 1, acked_hash.clone()),
            None => (0, GENESIS.to_string()),
        };
        if let Some(first) = all.first() {
            // The file may start before the cursor (not yet compacted) or right after it.
            let anchor = match acked_seq {
                Some(a) if first.seq <= a => {
                    let idx = (a - first.seq) as usize;
                    if idx >= all.len() || all[idx].hash != acked_hash {
                        return Err(bad("export spool does not match its cursor"));
                    }
                    acked_in_file = idx + 1;
                    None
                }
                Some(a) if first.seq == a + 1 => Some(acked_hash.clone()),
                None if first.seq == 0 => Some(GENESIS.to_string()),
                _ => return Err(bad("export spool does not match its cursor")),
            };
            verify_chain(&all, anchor.as_deref().unwrap_or(&all[0].prev))?;
            if anchor.is_none() && acked_in_file == 0 {
                return Err(bad("export spool does not match its cursor"));
            }
            pending.extend(all.iter().skip(acked_in_file).cloned());
            if let Some(last) = all.last() {
                next_seq = last.seq + 1;
                last_hash = last.hash.clone();
            }
        }
        if pending.len() > cfg.max_buffered_events + 1 {
            return Err(bad("export spool exceeds max_buffered_events; raise it or clear the spool deliberately"));
        }
        let overflow_open = pending
            .iter()
            .rev()
            .find_map(|e| e.gap.as_ref())
            .is_some_and(|g| g.phase == "started");
        let overflow_open = overflow_open
            && !pending
                .back()
                .and_then(|e| e.gap.as_ref())
                .is_some_and(|g| g.phase == "ended");
        let batch_cap = cfg.batch_max_events;
        Ok(Self {
            cfg,
            spool,
            cursor,
            state: Mutex::new(State {
                pending,
                next_seq,
                last_hash,
                acked_hash,
                acked_in_file,
                overflow_open,
                // Counts before a crash are not recoverable; the `started` marker proves the gap.
                overflow_dropped: 0,
                dropped_total: 0,
                delivered_total: 0,
                consecutive_failures: 0,
                last_success: None,
                last_error: None,
                io_failed: false,
                batch_cap,
            }),
            wake: Notify::new(),
            worker: Mutex::new(None),
        })
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // A poisoned lock means a panic mid-update. Recover the data, never unwrap.
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn push(
        &self,
        st: &mut State,
        kind: &str,
        event: Option<SiemEvent>,
        gap: Option<Gap>,
    ) -> Result<(), GateError> {
        let ts = now_secs();
        let hash = envelope_hash(st.next_seq, &st.last_hash, ts, kind, &event, &gap)?;
        let env = Envelope {
            seq: st.next_seq,
            prev: st.last_hash.clone(),
            ts,
            kind: kind.into(),
            event,
            gap,
            hash,
        };
        let mut line = serde_json::to_vec(&env).map_err(|e| bad(e.to_string()))?;
        line.push(b'\n');
        let mut f = open_append(&self.spool)?;
        f.write_all(&line).map_err(io)?;
        f.sync_data().map_err(io)?;
        st.next_seq += 1;
        st.last_hash = env.hash.clone();
        st.pending.push_back(env);
        Ok(())
    }

    /// Queue an event. Never blocks on the network and never fails the caller:
    /// bounded buffer, durable append, explicit gap marker on overflow.
    pub fn enqueue(&self, event: SiemEvent) {
        let mut st = self.lock();
        let cap = self.cfg.max_buffered_events;
        let result = (|| {
            if st.overflow_open {
                if st.pending.len() < cap {
                    let dropped = st.overflow_dropped;
                    self.push(
                        &mut st,
                        "gap",
                        None,
                        Some(Gap {
                            phase: "ended".into(),
                            dropped,
                        }),
                    )?;
                    st.overflow_open = false;
                    st.overflow_dropped = 0;
                } else {
                    st.overflow_dropped += 1;
                    st.dropped_total += 1;
                    return Ok(());
                }
            }
            if st.pending.len() >= cap {
                // One reserved slot beyond the cap holds the marker.
                self.push(
                    &mut st,
                    "gap",
                    None,
                    Some(Gap {
                        phase: "started".into(),
                        dropped: 0,
                    }),
                )?;
                st.overflow_open = true;
                st.overflow_dropped = 1;
                st.dropped_total += 1;
                return Ok(());
            }
            self.push(&mut st, "event", Some(event), None)
        })();
        if let Err(err) = result {
            st.io_failed = true;
            st.dropped_total += 1;
            st.last_error = Some("spool write failed".into());
            warn!(error = %err, "SIEM export could not queue an event");
        }
        drop(st);
        self.wake.notify_one();
    }

    /// Admission check for new authorizations. In `degrade` mode it always passes.
    pub fn admission(&self) -> Result<(), GateError> {
        if self.cfg.failure_mode == FailureMode::Degrade {
            return Ok(());
        }
        let st = self.lock();
        let cap = self.cfg.max_buffered_events;
        let headroom = (cap / 10).max(10);
        let lag = st.pending.front().map(|e| now_secs() - e.ts).unwrap_or(0);
        if st.io_failed
            || st.overflow_open
            || st.pending.len() + headroom > cap
            || lag > self.cfg.fail_closed_lag_secs as i64
        {
            return Err(GateError::SiemExport(
                "audit export is not keeping up; new authorizations are refused".into(),
            ));
        }
        Ok(())
    }

    pub fn status(&self) -> ExportStatus {
        let st = self.lock();
        let now = now_secs();
        let oldest = st.pending.front().map(|e| now - e.ts);
        let degraded = st.io_failed
            || st.overflow_open
            || st.consecutive_failures > 0
            || oldest.is_some_and(|a| a > self.cfg.flush_interval_secs as i64 * 4);
        ExportStatus {
            enabled: true,
            failure_mode: self.cfg.failure_mode,
            state: if degraded { "degraded" } else { "ok" },
            pending: st.pending.len(),
            capacity: self.cfg.max_buffered_events,
            oldest_pending_age_secs: oldest,
            last_success_age_secs: st.last_success.map(|t| now - t),
            consecutive_failures: st.consecutive_failures,
            dropped_total: st.dropped_total,
            delivered_total: st.delivered_total,
            last_error: st.last_error.clone(),
        }
    }

    fn take_batch(&self) -> Vec<Envelope> {
        let st = self.lock();
        let mut bytes = 0;
        let mut out = vec![];
        for e in st.pending.iter().take(st.batch_cap) {
            let size = serde_json::to_vec(e).map(|v| v.len()).unwrap_or(0) + 512;
            if !out.is_empty() && bytes + size > self.cfg.batch_max_bytes {
                break;
            }
            bytes += size;
            out.push(e.clone());
        }
        out
    }

    fn ack(&self, count: usize) {
        let mut st = self.lock();
        let mut failed = false;
        for _ in 0..count {
            if let Some(e) = st.pending.pop_front() {
                st.acked_hash = e.hash.clone();
                st.acked_in_file += 1;
                st.delivered_total += 1;
                let cursor = json!({"acked_seq": e.seq, "acked_hash": e.hash});
                if write_atomic(&self.cursor, cursor.to_string().as_bytes()).is_err() {
                    failed = true;
                }
            }
        }
        // Compact after the cursor is durable.
        let compact = st.pending.is_empty() || st.acked_in_file >= self.cfg.max_buffered_events;
        if compact && !failed {
            let mut buf = vec![];
            for e in &st.pending {
                if let Ok(mut line) = serde_json::to_vec(e) {
                    line.push(b'\n');
                    buf.extend(line);
                }
            }
            if write_atomic(&self.spool, &buf).is_ok() {
                st.acked_in_file = 0;
            } else {
                failed = true;
            }
        }
        if failed {
            st.io_failed = true;
            st.last_error = Some("spool cursor write failed".into());
        }
    }

    fn backoff(&self, failures: u32) -> Duration {
        let base = Duration::from_millis(self.cfg.backoff_initial_ms)
            .saturating_mul(1u32 << failures.saturating_sub(1).min(16));
        let capped = base.min(Duration::from_secs(self.cfg.backoff_max_secs));
        // Up to 20% jitter from the clock; not a security input.
        let jitter = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
            % 200;
        capped + capped / 1000 * jitter
    }

    async fn run(self: Arc<Self>, transport: Arc<dyn Transport>) {
        let host = reqwest::Url::parse(self.cfg.url())
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned))
            .unwrap_or_default();
        loop {
            let batch = self.take_batch();
            if batch.is_empty() {
                let _ = tokio::time::timeout(
                    Duration::from_secs(self.cfg.flush_interval_secs),
                    self.wake.notified(),
                )
                .await;
                // Let a burst accumulate into one request.
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
            let outcome = match render_batch(&self.cfg.target, &batch) {
                Ok((body, ct)) => transport.post(body, ct).await,
                Err(_) => Err("render failed".to_string()),
            };
            match outcome {
                Ok(status) if (200..300).contains(&status) => {
                    self.ack(batch.len());
                    let mut st = self.lock();
                    st.consecutive_failures = 0;
                    st.last_success = Some(now_secs());
                    st.last_error = None;
                    st.batch_cap = self.cfg.batch_max_events;
                    info!(host = %host, events = batch.len(), "SIEM export delivered");
                }
                other => {
                    let (detail, retry_smaller) = match other {
                        Ok(s) => (format!("HTTP {s}"), s == 413),
                        Err(e) => (e, false),
                    };
                    let failures = {
                        let mut st = self.lock();
                        st.consecutive_failures = st.consecutive_failures.saturating_add(1);
                        st.last_error = Some(detail.clone());
                        if retry_smaller {
                            st.batch_cap = (st.batch_cap / 2).max(1);
                        }
                        st.consecutive_failures
                    };
                    // Rejections such as 401 are retried at the capped rate, never discarded.
                    warn!(host = %host, failures, detail = %detail, "SIEM export delivery failed");
                    tokio::time::sleep(self.backoff(failures)).await;
                }
            }
        }
    }
}

impl Drop for SiemExporter {
    fn drop(&mut self) {
        if let Ok(mut w) = self.worker.lock() {
            if let Some(h) = w.take() {
                h.abort();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static N: AtomicUsize = AtomicUsize::new(0);

    fn dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "membrane-siem-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = fs::remove_dir_all(&d);
        d
    }

    fn event(id: &str) -> SiemEvent {
        SiemEvent {
            schema_version: "1.0.0".into(),
            timestamp: 1,
            event_id: id.into(),
            event_type: "blocked_action".into(),
            outcome: "blocked".into(),
            severity: "high".into(),
            agent_id: "agent".into(),
            session_id: None,
            scope_id: Some("scope".into()),
            models: vec![],
            tools: vec![],
            policy_hash: None,
            receipt_hash: Some("r".into()),
            parent_receipt_hash: None,
            reason: Some("tool_denied".into()),
            simulation: false,
            source_event_type: "x".into(),
        }
    }

    fn config(mode: FailureMode) -> ExportConfig {
        ExportConfig {
            failure_mode: mode,
            target: Target::Webhook {
                url: "https://siem.example.invalid/ingest".into(),
                token_env: None,
                auth_header: None,
            },
            tls: TlsConfig {
                ca_bundle_file: "/nonexistent".into(),
                pinned_cert_sha256: vec![],
            },
            spool_dir: None,
            max_buffered_events: 100,
            batch_max_events: 10,
            batch_max_bytes: 1 << 20,
            flush_interval_secs: 1,
            request_timeout_secs: 5,
            backoff_initial_ms: 50,
            backoff_max_secs: 1,
            fail_closed_lag_secs: 300,
        }
    }

    struct Mock {
        fail_first: AtomicUsize,
        status: u16,
        bodies: Mutex<Vec<Vec<u8>>>,
    }
    #[allow(clippy::double_must_use)]
    #[async_trait]
    impl Transport for Mock {
        async fn post(&self, body: Vec<u8>, _: &'static str) -> Result<u16, String> {
            if self.fail_first.load(Ordering::SeqCst) > 0
                && self.fail_first.fetch_sub(1, Ordering::SeqCst) > 0
            {
                return Err("connection or TLS validation failed".into());
            }
            if self.status < 300 {
                self.bodies.lock().unwrap().push(body);
            }
            Ok(self.status)
        }
    }

    #[test]
    fn config_rejects_unsafe_or_ambiguous_settings() {
        assert!(config(FailureMode::Degrade).validate().is_ok());
        let mut c = config(FailureMode::Degrade);
        for url in [
            "http://siem.example.invalid/x",
            "https://user:pw@siem.example.invalid/x",
            "https://siem.example.invalid/x?token=abc",
            "https://siem.example.invalid/x#f",
            "not a url",
        ] {
            c.target = Target::Webhook {
                url: url.into(),
                token_env: None,
                auth_header: None,
            };
            assert!(c.validate().is_err(), "{url}");
        }
        let mut c = config(FailureMode::Degrade);
        c.max_buffered_events = 50;
        assert!(c.validate().is_err());
        let mut c = config(FailureMode::Degrade);
        c.tls.pinned_cert_sha256 = vec!["abcd".into()];
        assert!(c.validate().is_err());
        let mut c = config(FailureMode::Degrade);
        c.target = Target::SplunkHec {
            url: "https://h.example.invalid/e".into(),
            token_env: "lower case".into(),
            source: None,
            sourcetype: None,
            index: None,
            host: None,
        };
        assert!(c.validate().is_err());
        // Inline secrets, unknown keys and a missing failure mode are parse errors.
        for yaml in [
            "target: {kind: webhook, url: 'https://a.invalid/x', token: s}\ntls: {ca_bundle_file: /x}\nfailure_mode: degrade",
            "target: {kind: webhook, url: 'https://a.invalid/x'}\ntls: {ca_bundle_file: /x}",
            "target: {kind: webhook, url: 'https://a.invalid/x'}\ntls: {ca_bundle_file: /x}\nfailure_mode: degrade\nextra: 1",
            "target: {kind: webhook, url: 'https://a.invalid/x'}\nfailure_mode: degrade",
        ] {
            assert!(serde_yaml::from_str::<ExportConfig>(yaml).is_err(), "{yaml}");
        }
    }

    #[test]
    fn startup_errors_for_missing_secret_and_trust_anchor() {
        let d = dir();
        fs::create_dir_all(&d).unwrap();
        let cfg = d.join("c.yaml");
        fs::write(&cfg, "failure_mode: degrade\ntarget: {kind: datadog_logs, url: 'https://a.invalid/x', token_env: MEMBRANE_TEST_UNSET_TOKEN}\ntls: {ca_bundle_file: /nonexistent}\n").unwrap();
        let err = SiemExporter::start_from_file(&cfg, &d)
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("MEMBRANE_TEST_UNSET_TOKEN"), "{err}");
        std::env::set_var("MEMBRANE_TEST_SET_TOKEN", "super-secret-value");
        fs::write(&cfg, "failure_mode: degrade\ntarget: {kind: datadog_logs, url: 'https://a.invalid/x', token_env: MEMBRANE_TEST_SET_TOKEN}\ntls: {ca_bundle_file: /nonexistent}\n").unwrap();
        let err = SiemExporter::start_from_file(&cfg, &d)
            .err()
            .unwrap()
            .to_string();
        assert!(
            err.contains("ca_bundle_file") && !err.contains("super-secret-value"),
            "{err}"
        );
        assert_eq!(
            format!("{:?}", Secret("super-secret-value".into())),
            "[redacted]"
        );
    }

    #[test]
    fn spool_is_hash_chained_and_tamper_evident() {
        let d = dir();
        let x = SiemExporter::open(config(FailureMode::Degrade), &d).unwrap();
        for i in 0..3 {
            x.enqueue(event(&format!("e{i}")));
        }
        drop(x);
        let y = SiemExporter::open(config(FailureMode::Degrade), &d).unwrap();
        let v: Vec<_> = y.lock().pending.iter().cloned().collect();
        assert_eq!(v.len(), 3);
        assert_eq!(v[0].prev, GENESIS);
        verify_chain(&v, GENESIS).unwrap();
        assert_eq!(y.lock().next_seq, 3);
        drop(y);
        let text = fs::read_to_string(d.join("spool.jsonl"))
            .unwrap()
            .replace("\"e1\"", "\"eX\"");
        fs::write(d.join("spool.jsonl"), text).unwrap();
        assert!(SiemExporter::open(config(FailureMode::Degrade), &d).is_err());
        // A torn tail also stops startup.
        let d = dir();
        let x = SiemExporter::open(config(FailureMode::Degrade), &d).unwrap();
        x.enqueue(event("a"));
        drop(x);
        let mut f = OpenOptions::new()
            .append(true)
            .open(d.join("spool.jsonl"))
            .unwrap();
        f.write_all(b"{\"seq\"").unwrap();
        assert!(SiemExporter::open(config(FailureMode::Degrade), &d).is_err());
    }

    #[test]
    fn degrade_mode_bounds_the_buffer_and_records_a_gap() {
        let d = dir();
        let x = SiemExporter::open(config(FailureMode::Degrade), &d).unwrap();
        for i in 0..150 {
            x.enqueue(event(&format!("e{i}")));
        }
        let st = x.status();
        assert_eq!(st.pending, 101, "cap plus one reserved gap marker");
        assert_eq!(st.dropped_total, 50);
        assert_eq!(st.state, "degraded");
        assert!(x.admission().is_ok());
        let gaps: Vec<_> = x
            .lock()
            .pending
            .iter()
            .filter_map(|e| e.gap.clone())
            .collect();
        assert_eq!(
            gaps,
            vec![Gap {
                phase: "started".into(),
                dropped: 0
            }]
        );
        // Draining closes the gap with the dropped count before the next event.
        x.ack(50);
        x.enqueue(event("after"));
        let tail: Vec<_> = x
            .lock()
            .pending
            .iter()
            .filter_map(|e| e.gap.clone())
            .collect();
        assert_eq!(
            tail.last().unwrap(),
            &Gap {
                phase: "ended".into(),
                dropped: 50
            }
        );
        let all: Vec<_> = x.lock().pending.iter().cloned().collect();
        verify_chain(&all, &all[0].prev).unwrap();
        // The marker survives a restart.
        drop(x);
        let y = SiemExporter::open(config(FailureMode::Degrade), &d).unwrap();
        assert!(!y.lock().overflow_open);
    }

    #[test]
    fn fail_closed_refuses_before_the_buffer_fills() {
        let d = dir();
        let x = SiemExporter::open(config(FailureMode::FailClosed), &d).unwrap();
        for i in 0..90 {
            x.enqueue(event(&format!("e{i}")));
        }
        assert!(x.admission().is_ok());
        x.enqueue(event("e90"));
        assert!(matches!(x.admission(), Err(GateError::SiemExport(_))));
        // Draining restores admission.
        x.ack(20);
        assert!(x.admission().is_ok());
        // Lag also refuses.
        let mut c = config(FailureMode::FailClosed);
        c.fail_closed_lag_secs = 10;
        let d = dir();
        let y = SiemExporter::open(c, &d).unwrap();
        y.enqueue(event("old"));
        y.lock().pending[0].ts -= 60;
        assert!(y.admission().is_err());
    }

    #[test]
    fn spool_failure_fails_closed_and_is_counted_in_degrade() {
        let d = dir();
        let x = SiemExporter::open(config(FailureMode::FailClosed), &d).unwrap();
        fs::remove_dir_all(&d).unwrap();
        x.enqueue(event("lost"));
        assert!(x.admission().is_err());
        assert_eq!(x.status().dropped_total, 1);
    }

    #[tokio::test]
    async fn delivers_in_order_retries_and_acks_durably() {
        let d = dir();
        let mock = Arc::new(Mock {
            fail_first: AtomicUsize::new(2),
            status: 200,
            bodies: Mutex::new(vec![]),
        });
        let x = SiemExporter::start(config(FailureMode::FailClosed), &d, mock.clone()).unwrap();
        for i in 0..25 {
            x.enqueue(event(&format!("e{i}")));
        }
        for _ in 0..100 {
            if x.status().pending == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let st = x.status();
        assert_eq!(st.pending, 0, "{:?}", st.last_error);
        assert_eq!(st.delivered_total, 25);
        let mut seqs = vec![];
        for body in mock.bodies.lock().unwrap().iter() {
            for line in body.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
                let e: Envelope = serde_json::from_slice(line).unwrap();
                seqs.push(e.seq);
            }
        }
        assert_eq!(seqs, (0..25).collect::<Vec<_>>());
        assert!(seqs.len() == 25);
        drop(x);
        // Restart continues the chain after the cursor and resends nothing.
        let y = SiemExporter::open(config(FailureMode::FailClosed), &d).unwrap();
        assert_eq!(y.lock().pending.len(), 0);
        assert_eq!(y.lock().next_seq, 25);
        y.enqueue(event("next"));
        let e = y.lock().pending[0].clone();
        assert_eq!(e.seq, 25);
        assert_eq!(e.prev, y.lock().acked_hash);
    }

    #[tokio::test]
    async fn rejections_are_retried_not_discarded() {
        let d = dir();
        let mock = Arc::new(Mock {
            fail_first: AtomicUsize::new(0),
            status: 401,
            bodies: Mutex::new(vec![]),
        });
        let x = SiemExporter::start(config(FailureMode::Degrade), &d, mock).unwrap();
        x.enqueue(event("a"));
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let st = x.status();
        assert_eq!(st.pending, 1);
        assert!(st.consecutive_failures >= 2);
        assert_eq!(st.last_error.as_deref(), Some("HTTP 401"));
    }

    #[test]
    fn backoff_is_capped() {
        let d = dir();
        let x = SiemExporter::open(config(FailureMode::Degrade), &d).unwrap();
        assert!(x.backoff(1) >= Duration::from_millis(50));
        assert!(x.backoff(40) <= Duration::from_millis(1300));
    }

    #[test]
    fn payload_formats() {
        let env = |seq| {
            let ev = Some(event("e"));
            Envelope {
                seq,
                prev: GENESIS.into(),
                ts: 7,
                kind: "event".into(),
                hash: envelope_hash(seq, GENESIS, 7, "event", &ev, &None).unwrap(),
                event: ev,
                gap: None,
            }
        };
        let batch = vec![env(0), env(1)];
        let (b, ct) = render_batch(
            &Target::SplunkHec {
                url: String::new(),
                token_env: String::new(),
                source: None,
                sourcetype: None,
                index: Some("sec".into()),
                host: None,
            },
            &batch,
        )
        .unwrap();
        assert_eq!(ct, "application/json");
        let first: Value =
            serde_json::from_slice(b.split(|c| *c == b'\n').next().unwrap()).unwrap();
        assert_eq!(first["index"], "sec");
        assert_eq!(first["event"]["seq"], 0);
        assert_eq!(first["sourcetype"], "membrane:receipt");
        let (b, _) = render_batch(
            &Target::DatadogLogs {
                url: String::new(),
                token_env: String::new(),
                service: None,
                tags: Some("env:prod".into()),
                hostname: None,
            },
            &batch,
        )
        .unwrap();
        let v: Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 2);
        assert_eq!(v[1]["membrane"]["seq"], 1);
        assert_eq!(v[0]["ddtags"], "env:prod");
        let (b, ct) = render_batch(
            &Target::Webhook {
                url: String::new(),
                token_env: None,
                auth_header: None,
            },
            &batch,
        )
        .unwrap();
        assert_eq!(ct, "application/x-ndjson");
        assert_eq!(
            b.split(|c| *c == b'\n').filter(|l| !l.is_empty()).count(),
            2
        );
        // Only the allowlisted SiemEvent fields appear.
        let text = String::from_utf8(b).unwrap();
        assert!(!text.contains("signature") && !text.contains("prompt"));
    }

    // ---- TLS pinning against a real handshake ----

    async fn tls_server(cert: &rcgen::CertifiedKey) -> std::net::SocketAddr {
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.cert.der().clone()], key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(sock).await else {
                        return;
                    };
                    let mut buf = [0u8; 4096];
                    let _ = tls.read(&mut buf).await;
                    let _ = tls
                        .write_all(b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                        .await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        addr
    }

    async fn post_with(
        ca_pem: &str,
        pins: &[[u8; 32]],
        port: u16,
        host: &str,
    ) -> Result<u16, String> {
        let tls = pinned_tls_config(ca_pem.as_bytes(), pins).unwrap();
        let client = reqwest::Client::builder()
            .use_preconfigured_tls(tls)
            .https_only(true)
            .resolve(host, std::net::SocketAddr::from(([127, 0, 0, 1], port)))
            .build()
            .unwrap();
        let t = HttpTransport {
            client,
            url: format!("https://{host}:{port}/x"),
            auth: None,
        };
        t.post(b"{}".to_vec(), "application/json").await
    }

    #[tokio::test]
    async fn tls_trusts_only_the_bundle_and_enforces_leaf_pins() {
        let good = rcgen::generate_simple_self_signed(vec!["siem.test".into()]).unwrap();
        let other = rcgen::generate_simple_self_signed(vec!["siem.test".into()]).unwrap();
        let addr = tls_server(&good).await;
        let good_pem = good.cert.pem();
        let other_pem = other.cert.pem();
        let fp: [u8; 32] = Sha256::digest(good.cert.der().as_ref()).into();
        // Trusted anchor, no pin: accepted.
        assert_eq!(
            post_with(&good_pem, &[], addr.port(), "siem.test").await,
            Ok(204)
        );
        // Matching leaf pin: accepted.
        assert_eq!(
            post_with(&good_pem, &[fp], addr.port(), "siem.test").await,
            Ok(204)
        );
        // Wrong pin: rejected even though the chain is valid.
        assert!(post_with(&good_pem, &[[7u8; 32]], addr.port(), "siem.test")
            .await
            .is_err());
        // Different trust anchor: rejected.
        assert!(post_with(&other_pem, &[], addr.port(), "siem.test")
            .await
            .is_err());
        // Right anchor, wrong hostname: rejected.
        assert!(post_with(&good_pem, &[], addr.port(), "evil.test")
            .await
            .is_err());
        // Empty or invalid bundles are rejected up front.
        assert!(pinned_tls_config(b"", &[]).is_err());
        assert!(pinned_tls_config(
            b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
            &[]
        )
        .is_err());
    }
}
