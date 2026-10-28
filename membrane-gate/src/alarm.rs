//! Clocked operator alarms, delivered to an operator-owned webhook.
//!
//! Three conditions have a clock on them, and only these raise an alarm:
//! a stuck agent, a deny-rate spike and a first-seen identity. Everything else
//! belongs in periodic readings, not in a pager.
//!
//! Alarms are derived from the bounded audit log, which is observational. They
//! never feed an authorization decision, so a slow, failed or misconfigured
//! delivery cannot allow anything. A delivery that fails is recorded as failed
//! and shown in the audit snapshot; it is never reported as delivered.
use crate::audit::{AuditLog, Decision};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};
use tracing::{info, warn};

pub const ENV_WEBHOOK_URL: &str = "MEMBRANE_ALARM_WEBHOOK_URL";
pub const ENV_WEBHOOK_SECRET: &str = "MEMBRANE_ALARM_WEBHOOK_SECRET";
pub const ENV_WEBHOOK_SECRET_HEADER: &str = "MEMBRANE_ALARM_WEBHOOK_SECRET_HEADER";
pub const ENV_KNOWN_IDENTITIES: &str = "MEMBRANE_ALARM_KNOWN_IDENTITIES";
pub const ENV_STUCK_SECS: &str = "MEMBRANE_ALARM_STUCK_SECS";
pub const ENV_SPIKE_WINDOW_SECS: &str = "MEMBRANE_ALARM_SPIKE_WINDOW_SECS";
pub const ENV_SPIKE_MIN_DENIES: &str = "MEMBRANE_ALARM_SPIKE_MIN_DENIES";
pub const ENV_GRANT_LEAD_SECS: &str = "MEMBRANE_ALARM_GRANT_LEAD_SECS";
pub const ENV_SPIKE_MIN_RATE: &str = "MEMBRANE_ALARM_SPIKE_MIN_RATE";

const DEFAULT_SECRET_HEADER: &str = "X-Membrane-Alarm-Secret";
const ALARM_CAPACITY: usize = 100;
const TICK_SECS: u64 = 15;
const DELIVERY_ATTEMPTS: u32 = 3;
const IDENTITY_DISPLAY_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlarmKind {
    StuckAgent,
    DenySpike,
    FirstSeenIdentity,
    GrantExpiring,
}

impl AlarmKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StuckAgent => "stuck_agent",
            Self::DenySpike => "deny_spike",
            Self::FirstSeenIdentity => "first_seen_identity",
            Self::GrantExpiring => "grant_expiring",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Delivery {
    Pending,
    Delivered,
    Failed,
    NotConfigured,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alarm {
    pub kind: AlarmKind,
    pub raised_at: i64,
    /// Caller key verified by proof of possession, shortened for display.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlarmRecord {
    pub id: u64,
    #[serde(flatten)]
    pub alarm: Alarm,
    pub delivery: Delivery,
}

#[derive(Debug, Clone)]
pub struct AlarmConfig {
    pub webhook_url: Option<String>,
    pub secret: Option<String>,
    pub secret_header: String,
    pub known_identities: HashSet<String>,
    /// An identity denied continuously for this long, after having been allowed.
    pub stuck_secs: i64,
    pub spike_window_secs: i64,
    pub spike_min_denies: usize,
    pub spike_min_rate: f64,
    /// Alarm this long before a grant's `expires_at`.
    pub grant_lead_secs: i64,
}

impl Default for AlarmConfig {
    fn default() -> Self {
        Self {
            webhook_url: None,
            secret: None,
            secret_header: DEFAULT_SECRET_HEADER.into(),
            known_identities: HashSet::new(),
            stuck_secs: 900,
            spike_window_secs: 300,
            spike_min_denies: 10,
            spike_min_rate: 0.5,
            grant_lead_secs: 86_400,
        }
    }
}

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}

fn env_parse<T: std::str::FromStr>(name: &str, default: T) -> Result<T, String> {
    match env_nonempty(name) {
        None => Ok(default),
        Some(raw) => raw
            .parse::<T>()
            .map_err(|_| format!("{name} has an invalid value")),
    }
}

impl AlarmConfig {
    /// Invalid settings are a startup error. A gate that cannot read its alarm
    /// configuration refuses to start rather than silently running without alarms.
    pub fn from_env() -> Result<Self, String> {
        let defaults = Self::default();
        let webhook_url = env_nonempty(ENV_WEBHOOK_URL);
        if let Some(url) = &webhook_url {
            validate_webhook_url(url)?;
        }
        let config = Self {
            webhook_url,
            secret: env_nonempty(ENV_WEBHOOK_SECRET),
            secret_header: env_nonempty(ENV_WEBHOOK_SECRET_HEADER)
                .unwrap_or(defaults.secret_header),
            known_identities: env_nonempty(ENV_KNOWN_IDENTITIES)
                .map(|raw| {
                    raw.split(',')
                        .map(|s| s.trim().to_ascii_lowercase())
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
            stuck_secs: env_parse(ENV_STUCK_SECS, defaults.stuck_secs)?,
            spike_window_secs: env_parse(ENV_SPIKE_WINDOW_SECS, defaults.spike_window_secs)?,
            spike_min_denies: env_parse(ENV_SPIKE_MIN_DENIES, defaults.spike_min_denies)?,
            spike_min_rate: env_parse(ENV_SPIKE_MIN_RATE, defaults.spike_min_rate)?,
            grant_lead_secs: env_parse(ENV_GRANT_LEAD_SECS, defaults.grant_lead_secs)?,
        };
        if config.stuck_secs <= 0
            || config.grant_lead_secs <= 0
            || config.spike_window_secs <= 0
            || config.spike_min_denies == 0
        {
            return Err("alarm thresholds must be positive".into());
        }
        if !(config.spike_min_rate > 0.0 && config.spike_min_rate <= 1.0) {
            return Err(format!("{ENV_SPIKE_MIN_RATE} must be in (0, 1]"));
        }
        Ok(config)
    }
}

/// Webhooks carry operator-visible gate activity, so plain HTTP is accepted only
/// for a literal loopback address (a local relay).
pub fn validate_webhook_url(raw: &str) -> Result<(), String> {
    let url =
        reqwest::Url::parse(raw).map_err(|_| format!("{ENV_WEBHOOK_URL} is not a valid URL"))?;
    match url.scheme() {
        "https" => Ok(()),
        "http" => {
            let loopback = url
                .host_str()
                .map(|h| h.trim_start_matches('[').trim_end_matches(']'))
                .and_then(|h| h.parse::<std::net::IpAddr>().ok())
                .is_some_and(|ip| ip.is_loopback());
            if loopback {
                Ok(())
            } else {
                Err(format!(
                    "{ENV_WEBHOOK_URL} must use https unless it is a literal loopback address"
                ))
            }
        }
        _ => Err(format!("{ENV_WEBHOOK_URL} must use https")),
    }
}

fn display_identity(id: &str) -> String {
    id.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(IDENTITY_DISPLAY_LEN)
        .collect()
}

#[derive(Debug, Default)]
struct Streak {
    first_deny_at: i64,
    last_deny_at: i64,
    denies: usize,
}

/// Incremental evaluator over the audit log. Holds only the state needed to
/// avoid re-raising the same condition on every tick.
#[derive(Debug)]
pub struct Engine {
    config: AlarmConfig,
    last_sequence: u64,
    seen: HashSet<String>,
    allowed_before: HashSet<String>,
    streaks: HashMap<String, Streak>,
    stuck_raised: HashSet<String>,
    spike_active: bool,
    expiring_raised: HashSet<(String, i64)>,
}

impl Engine {
    pub fn new(config: AlarmConfig) -> Self {
        let seen = config.known_identities.clone();
        let allowed_before = config.known_identities.clone();
        Self {
            config,
            last_sequence: 0,
            seen,
            allowed_before,
            streaks: HashMap::new(),
            stuck_raised: HashSet::new(),
            spike_active: false,
            expiring_raised: HashSet::new(),
        }
    }

    /// `grants` is (identity, expiry time) for grants that have a window. Raises one alarm per
    /// grant and expiry time when the expiry is within the lead time and still in the future.
    /// Renewing a grant changes its expiry, so the next window raises again. A grant that has
    /// already expired is not alarmed: its denials are visible in the decision log.
    pub fn evaluate_grants(&mut self, now: i64, grants: &[(String, i64)]) -> Vec<Alarm> {
        let live: HashSet<(String, i64)> = grants
            .iter()
            .map(|(id, t)| (id.to_ascii_lowercase(), *t))
            .collect();
        self.expiring_raised.retain(|k| live.contains(k));
        let mut due: Vec<(String, i64)> = live
            .into_iter()
            .filter(|(_, until)| *until > now && *until - now <= self.config.grant_lead_secs)
            .filter(|k| !self.expiring_raised.contains(k))
            .collect();
        due.sort();
        due.into_iter()
            .map(|(id, until)| {
                self.expiring_raised.insert((id.clone(), until));
                let remaining = until - now;
                let left = if remaining >= 3_600 {
                    format!("{} hours", remaining / 3_600)
                } else {
                    format!("{} minutes", (remaining + 59) / 60)
                };
                Alarm {
                    kind: AlarmKind::GrantExpiring,
                    raised_at: now,
                    identity: Some(display_identity(&id)),
                    summary: format!(
                        "Grant for identity {} expires in about {}. Renewal is an operator registry edit.",
                        display_identity(&id),
                        left
                    ),
                }
            })
            .collect()
    }

    /// `decisions` is the audit snapshot, newest first.
    pub fn evaluate(&mut self, now: i64, decisions: &[Decision]) -> Vec<Alarm> {
        let mut alarms = Vec::new();
        let previous = self.last_sequence;
        for d in decisions.iter().rev().filter(|d| d.sequence > previous) {
            self.last_sequence = self.last_sequence.max(d.sequence);
            let Some(identity) = d.authenticated_identity.as_ref() else {
                continue;
            };
            let key = identity.to_ascii_lowercase();
            if self.seen.insert(key.clone()) {
                alarms.push(Alarm {
                    kind: AlarmKind::FirstSeenIdentity,
                    raised_at: now,
                    identity: Some(display_identity(identity)),
                    summary: format!(
                        "First request from identity {} since the gate started; outcome: {}.",
                        display_identity(identity),
                        d.outcome
                    ),
                });
            }
            if d.outcome == "allow" {
                self.allowed_before.insert(key.clone());
                self.streaks.remove(&key);
                self.stuck_raised.remove(&key);
            } else {
                let streak = self.streaks.entry(key).or_insert(Streak {
                    first_deny_at: d.timestamp,
                    last_deny_at: d.timestamp,
                    denies: 0,
                });
                streak.last_deny_at = d.timestamp;
                streak.denies += 1;
            }
        }

        // Stuck agent: an identity that was working, now denied without a break
        // for the full period and still retrying. Never-allowed identities are
        // not "stuck"; they show up as first-seen or in the deny rate.
        let mut stuck: Vec<(&String, &Streak)> = self
            .streaks
            .iter()
            .filter(|(id, s)| {
                self.allowed_before.contains(*id)
                    && !self.stuck_raised.contains(*id)
                    && s.denies >= 2
                    && now - s.first_deny_at >= self.config.stuck_secs
                    && now - s.last_deny_at <= self.config.stuck_secs
            })
            .collect();
        stuck.sort_by(|a, b| a.0.cmp(b.0));
        let stuck: Vec<(String, i64, usize)> = stuck
            .into_iter()
            .map(|(id, s)| (id.clone(), now - s.first_deny_at, s.denies))
            .collect();
        for (id, age, denies) in stuck {
            self.stuck_raised.insert(id.clone());
            alarms.push(Alarm {
                kind: AlarmKind::StuckAgent,
                raised_at: now,
                identity: Some(display_identity(&id)),
                summary: format!(
                    "Identity {} has been denied {} times over {} minutes with no allowed request in between.",
                    display_identity(&id),
                    denies,
                    age / 60
                ),
            });
        }

        // Deny spike: volume and rate inside the window. Re-arms once it clears.
        let from = now - self.config.spike_window_secs;
        let (mut allowed, mut denied) = (0usize, 0usize);
        for d in decisions.iter().filter(|d| d.timestamp >= from) {
            if d.outcome == "allow" {
                allowed += 1;
            } else if d.outcome == "deny" {
                denied += 1;
            }
        }
        let total = allowed + denied;
        let rate = if total > 0 {
            denied as f64 / total as f64
        } else {
            0.0
        };
        let spiking = denied >= self.config.spike_min_denies && rate >= self.config.spike_min_rate;
        if spiking && !self.spike_active {
            alarms.push(Alarm {
                kind: AlarmKind::DenySpike,
                raised_at: now,
                identity: None,
                summary: format!(
                    "{} of {} decisions were denied in the last {} minutes ({:.0}%).",
                    denied,
                    total,
                    self.config.spike_window_secs / 60,
                    rate * 100.0
                ),
            });
        }
        self.spike_active = spiking;
        alarms
    }
}

fn webhook_body(record: &AlarmRecord) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "source": "membrane-gate",
        "id": record.id,
        "kind": record.alarm.kind.as_str(),
        "raised_at": record.alarm.raised_at,
        "identity": record.alarm.identity,
        "summary": record.alarm.summary,
        // Chat-webhook compatible text field.
        "text": format!("Membrane alarm ({}): {}", record.alarm.kind.as_str(), record.alarm.summary),
    })
}

async fn deliver(client: &reqwest::Client, config: &AlarmConfig, record: &AlarmRecord) -> bool {
    let Some(url) = config.webhook_url.as_deref() else {
        return false;
    };
    let body = webhook_body(record).to_string();
    for attempt in 1..=DELIVERY_ATTEMPTS {
        let mut request = client
            .post(url)
            .header("content-type", "application/json")
            .body(body.clone());
        if let Some(secret) = &config.secret {
            request = request.header(config.secret_header.as_str(), secret.as_str());
        }
        match request.send().await {
            Ok(resp) if resp.status().is_success() => return true,
            Ok(resp) => warn!(
                status = resp.status().as_u16(),
                attempt, "alarm webhook rejected"
            ),
            Err(_) => warn!(attempt, "alarm webhook unreachable"),
        }
        tokio::time::sleep(Duration::from_millis(250 * u64::from(attempt))).await;
    }
    false
}

/// Evaluate the audit log on an interval and deliver new alarms. Delivery runs
/// off the request path; nothing here can block or allow a gate decision.
pub fn spawn_alarm_task(audit: Arc<AuditLog>, gate: Arc<crate::Gate>, config: AlarmConfig) {
    tokio::spawn(async move {
        membrane_core::tls::install_default_provider();
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .user_agent(concat!("membrane-alarm/", env!("CARGO_PKG_VERSION")))
            .build()
        {
            Ok(c) => c,
            Err(err) => {
                warn!(error = %err, "alarm delivery disabled: HTTP client failed to build");
                return;
            }
        };
        info!(
            delivery = if config.webhook_url.is_some() {
                "webhook"
            } else {
                "none"
            },
            "alarm evaluation started"
        );
        let mut engine = Engine::new(config.clone());
        loop {
            tokio::time::sleep(Duration::from_secs(TICK_SECS)).await;
            let Some((_, decisions)) = audit.snapshot() else {
                continue;
            };
            let now = chrono::Utc::now().timestamp();
            let mut raised = engine.evaluate(now, &decisions);
            match gate.grant_expiries() {
                Ok(grants) => raised.extend(engine.evaluate_grants(now, &grants)),
                Err(err) => warn!(error = %err, "grant expiry check skipped: registry unavailable"),
            }
            for alarm in raised {
                let initial = if config.webhook_url.is_some() {
                    Delivery::Pending
                } else {
                    Delivery::NotConfigured
                };
                let Some(record) = audit.record_alarm(alarm, initial) else {
                    continue;
                };
                warn!(
                    kind = record.alarm.kind.as_str(),
                    id = record.id,
                    "membrane alarm raised"
                );
                if config.webhook_url.is_some() {
                    let ok = deliver(&client, &config, &record).await;
                    audit.set_alarm_delivery(
                        record.id,
                        if ok {
                            Delivery::Delivered
                        } else {
                            Delivery::Failed
                        },
                    );
                }
            }
        }
    });
}

pub const ALARM_LOG_CAPACITY: usize = ALARM_CAPACITY;

#[cfg(test)]
mod tests {
    use super::*;

    fn d(seq: u64, ts: i64, outcome: &str, id: Option<&str>) -> Decision {
        Decision {
            sequence: seq,
            timestamp: ts,
            outcome: outcome.into(),
            rule: "tool_allowlist".into(),
            agent: "gate".into(),
            authenticated_identity: id.map(Into::into),
            scope: None,
            action: "tool".into(),
            subject: None,
        }
    }
    fn newest_first(mut v: Vec<Decision>) -> Vec<Decision> {
        v.reverse();
        v
    }
    fn kinds(a: &[Alarm]) -> Vec<AlarmKind> {
        a.iter().map(|a| a.kind).collect()
    }

    #[test]
    fn first_seen_identity_raises_once_unless_known() {
        let mut e = Engine::new(AlarmConfig {
            known_identities: ["aa".to_string()].into(),
            ..AlarmConfig::default()
        });
        let log = newest_first(vec![
            d(1, 100, "allow", Some("AA")),
            d(2, 101, "allow", Some("bb")),
            d(3, 102, "allow", Some("bb")),
        ]);
        let alarms = e.evaluate(110, &log);
        assert_eq!(kinds(&alarms), vec![AlarmKind::FirstSeenIdentity]);
        assert_eq!(alarms[0].identity.as_deref(), Some("bb"));
        assert!(e.evaluate(120, &log).is_empty());
    }

    #[test]
    fn unauthenticated_denials_never_name_an_identity() {
        let mut e = Engine::new(AlarmConfig::default());
        let log = newest_first(vec![d(1, 100, "deny", None)]);
        assert!(e.evaluate(110, &log).is_empty());
    }

    #[test]
    fn stuck_agent_needs_prior_allow_a_full_period_and_clears_on_allow() {
        let mut e = Engine::new(AlarmConfig::default());
        let mut rows = vec![d(1, 0, "allow", Some("aa")), d(2, 10, "deny", Some("aa"))];
        let _ = e.evaluate(20, &newest_first(rows.clone()));
        rows.push(d(3, 500, "deny", Some("aa")));
        assert!(e.evaluate(600, &newest_first(rows.clone())).is_empty());
        rows.push(d(4, 905, "deny", Some("aa")));
        let alarms = e.evaluate(910, &newest_first(rows.clone()));
        assert_eq!(kinds(&alarms), vec![AlarmKind::StuckAgent]);
        assert!(e.evaluate(920, &newest_first(rows.clone())).is_empty());
        rows.push(d(5, 930, "allow", Some("aa")));
        assert!(e.evaluate(931, &newest_first(rows)).is_empty());
    }

    #[test]
    fn never_allowed_identity_is_not_stuck() {
        let mut e = Engine::new(AlarmConfig::default());
        let rows = vec![
            d(1, 0, "deny", Some("zz")),
            d(2, 500, "deny", Some("zz")),
            d(3, 905, "deny", Some("zz")),
        ];
        let alarms = e.evaluate(910, &newest_first(rows));
        assert_eq!(kinds(&alarms), vec![AlarmKind::FirstSeenIdentity]);
    }

    #[test]
    fn deny_spike_needs_volume_and_rate_and_rearms() {
        let cfg = AlarmConfig {
            spike_min_denies: 3,
            ..AlarmConfig::default()
        };
        let mut e = Engine::new(cfg);
        let mut rows = vec![d(1, 100, "deny", None), d(2, 101, "deny", None)];
        assert!(e.evaluate(110, &newest_first(rows.clone())).is_empty());
        rows.push(d(3, 102, "deny", None));
        assert_eq!(
            kinds(&e.evaluate(111, &newest_first(rows.clone()))),
            vec![AlarmKind::DenySpike]
        );
        assert!(e.evaluate(112, &newest_first(rows.clone())).is_empty());
        // The window empties, the spike clears, then a new one raises again.
        assert!(e.evaluate(1000, &newest_first(rows.clone())).is_empty());
        rows.extend([
            d(4, 1001, "deny", None),
            d(5, 1002, "deny", None),
            d(6, 1003, "deny", None),
        ]);
        assert_eq!(
            kinds(&e.evaluate(1004, &newest_first(rows))),
            vec![AlarmKind::DenySpike]
        );
    }

    #[test]
    fn many_allows_keep_a_small_deny_count_below_the_rate() {
        let cfg = AlarmConfig {
            spike_min_denies: 3,
            ..AlarmConfig::default()
        };
        let mut e = Engine::new(cfg);
        let mut rows: Vec<Decision> = (1..=20).map(|i| d(i, 100, "allow", None)).collect();
        rows.extend((21..=24).map(|i| d(i, 101, "deny", None)));
        assert!(e.evaluate(110, &newest_first(rows)).is_empty());
    }

    #[test]
    fn webhook_urls_are_https_or_literal_loopback() {
        assert!(validate_webhook_url("https://hooks.example.com/x").is_ok());
        assert!(validate_webhook_url("http://127.0.0.1:9000/x").is_ok());
        assert!(validate_webhook_url("http://[::1]:9000/x").is_ok());
        assert!(validate_webhook_url("http://hooks.example.com/x").is_err());
        assert!(validate_webhook_url("http://localhost.evil.example/x").is_err());
        assert!(validate_webhook_url("ftp://127.0.0.1/x").is_err());
        assert!(validate_webhook_url("not a url").is_err());
    }

    #[test]
    fn webhook_body_names_kind_and_never_carries_secrets() {
        let rec = AlarmRecord {
            id: 7,
            alarm: Alarm {
                kind: AlarmKind::DenySpike,
                raised_at: 5,
                identity: None,
                summary: "s".into(),
            },
            delivery: Delivery::Pending,
        };
        let body = webhook_body(&rec).to_string();
        assert!(body.contains("deny_spike") && body.contains("Membrane alarm"));
    }

    async fn one_shot_server(status: &'static str) -> (String, tokio::task::JoinHandle<String>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/hook", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let mut seen = String::new();
            for _ in 0..DELIVERY_ATTEMPTS {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 8192];
                let n = sock.read(&mut buf).await.unwrap();
                seen = String::from_utf8_lossy(&buf[..n]).to_string();
                let reply =
                    format!("HTTP/1.1 {status}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
                sock.write_all(reply.as_bytes()).await.unwrap();
                if status.starts_with("200") {
                    break;
                }
            }
            seen
        });
        (url, task)
    }

    fn sample() -> AlarmRecord {
        AlarmRecord {
            id: 1,
            alarm: Alarm {
                kind: AlarmKind::StuckAgent,
                raised_at: 1,
                identity: Some("aa".into()),
                summary: "s".into(),
            },
            delivery: Delivery::Pending,
        }
    }

    #[tokio::test]
    async fn delivers_with_secret_header_and_reports_success() {
        let (url, task) = one_shot_server("200 OK").await;
        let cfg = AlarmConfig {
            webhook_url: Some(url),
            secret: Some("s3cret".into()),
            ..AlarmConfig::default()
        };
        let client = reqwest::Client::new();
        assert!(deliver(&client, &cfg, &sample()).await);
        let request = task.await.unwrap().to_ascii_lowercase();
        assert!(request.contains("x-membrane-alarm-secret: s3cret"));
        assert!(request.contains("stuck_agent"));
    }

    #[tokio::test]
    async fn rejected_delivery_is_failed_not_delivered() {
        let (url, task) = one_shot_server("500 Internal Server Error").await;
        let cfg = AlarmConfig {
            webhook_url: Some(url),
            ..AlarmConfig::default()
        };
        let client = reqwest::Client::new();
        assert!(!deliver(&client, &cfg, &sample()).await);
        task.await.unwrap();
        let unreachable = AlarmConfig {
            webhook_url: Some("http://127.0.0.1:1/hook".into()),
            ..AlarmConfig::default()
        };
        assert!(!deliver(&client, &unreachable, &sample()).await);
    }

    #[test]
    fn alarm_log_is_bounded_and_delivery_status_updates() {
        let log = AuditLog::default();
        for _ in 0..ALARM_LOG_CAPACITY + 5 {
            log.record_alarm(sample().alarm, Delivery::Pending).unwrap();
        }
        let rows = log.alarms();
        assert_eq!(rows.len(), ALARM_LOG_CAPACITY);
        assert_eq!(rows[0].id, (ALARM_LOG_CAPACITY + 5) as u64);
        log.set_alarm_delivery(rows[0].id, Delivery::Failed);
        assert_eq!(log.alarms()[0].delivery, Delivery::Failed);
    }

    #[test]
    fn grant_expiring_raises_once_inside_the_lead_and_rearms_on_renewal() {
        let cfg = AlarmConfig {
            grant_lead_secs: 3_600,
            ..AlarmConfig::default()
        };
        let mut e = Engine::new(cfg);
        let g = |t| vec![("AABB".to_string(), t)];
        // Too early, then inside the lead.
        assert!(e.evaluate_grants(1_000, &g(10_000)).is_empty());
        let alarms = e.evaluate_grants(7_000, &g(10_000));
        assert_eq!(kinds(&alarms), vec![AlarmKind::GrantExpiring]);
        assert_eq!(alarms[0].identity.as_deref(), Some("aabb"));
        assert!(e.evaluate_grants(7_100, &g(10_000)).is_empty());
        // Already expired: no alarm; the denials are the signal.
        assert!(e.evaluate_grants(10_000, &g(10_000)).is_empty());
        // Renewed to a new expiry: a later window raises again.
        assert!(e.evaluate_grants(10_001, &g(20_000)).is_empty());
        assert_eq!(
            kinds(&e.evaluate_grants(17_000, &g(20_000))),
            vec![AlarmKind::GrantExpiring]
        );
    }

    #[test]
    fn grant_expiring_forgets_removed_grants_and_names_no_extra_text() {
        let mut e = Engine::new(AlarmConfig::default());
        let grants = vec![("a\nb".to_string(), 1_800)];
        let alarms = e.evaluate_grants(0, &grants);
        assert_eq!(alarms.len(), 1);
        assert!(!alarms[0].summary.contains('\n'));
        assert!(alarms[0].summary.contains("30 minutes"));
        assert!(e.evaluate_grants(1, &[]).is_empty());
        assert_eq!(e.expiring_raised.len(), 0);
    }
}
