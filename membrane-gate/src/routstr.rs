//! Routstr rail adapter (design: docs/settlement-adapters.md).
//!
//! Translates an already-authorized chat request into a paid Routstr call, with
//! the spend held against the shared [`BudgetLedger`]:
//!
//! 1. Check the request against this adapter's policy (model allowlist and
//!    pricing, required `max_tokens`, per-call ceiling). If a cost ceiling cannot
//!    be established, deny. Nothing is sent.
//! 2. Reserve the ceiling in the ledger. Only a *new* reservation may dispatch;
//!    a repeat of the same reservation id never sends a second request.
//! 3. Dispatch once, with the reservation id as the idempotency key.
//! 4. Settle: finalize at measured cost, release only when the rail definitively
//!    did not charge, otherwise keep the ceiling held as `uncertain` for
//!    reconciliation. A timeout is not proof that nothing was paid.
//!
//! The adapter never grants authority. The funded `sk-` key lives inside the
//! rail client, is redacted from `Debug`, and appears in no error or receipt.
use crate::spend::{BudgetLedger, Reserved, SpendError};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, fmt, sync::Arc, time::Duration};

/// Per-model price in millisatoshi. Operator-supplied; the adapter does not trust
/// a node's advertised price to bound spend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pricing {
    pub input_msat_per_mtok: u64,
    pub output_msat_per_mtok: u64,
    #[serde(default)]
    pub request_fee_msat: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutstrPolicy {
    /// Node base URL, for example `https://api.routstr.com/v1`. Receipt payee.
    pub node: String,
    pub models: BTreeMap<String, Pricing>,
    /// Hard ceiling for one call, in msat.
    pub per_call_ceiling_msat: u64,
}

pub const UNIT: &str = "msat";

#[derive(Debug, Clone)]
pub struct ChatCall {
    /// Reservation id, sent as the idempotency key.
    pub idempotency_key: String,
    pub body: Value,
}

#[derive(Debug, Clone)]
pub struct ChatReply {
    pub body: Value,
}

/// What a rail call can tell us about money.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RailError {
    /// Definitely not charged: refused before processing (4xx) or never connected.
    NotCharged(String),
    /// May have been charged: timeout, dropped connection, 5xx, unreadable reply.
    Unknown(String),
}

#[allow(clippy::double_must_use)]
#[async_trait]
pub trait RoutstrRail: Send + Sync {
    async fn chat(&self, call: &ChatCall) -> Result<ChatReply, RailError>;
    /// Spendable balance of the funded key, in msat.
    async fn balance_msat(&self) -> Result<u64, RailError>;
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AdapterError {
    #[error("denied before dispatch: {0}")]
    Denied(String),
    #[error("budget: {0}")]
    Budget(SpendError),
    #[error("rail refused, nothing charged, reservation released: {0}")]
    Rejected(String),
    #[error("outcome unknown, ceiling held for reconciliation: {0}")]
    Uncertain(String),
    #[error("reservation {0} already exists; refusing to dispatch it again")]
    AlreadyDispatched(String),
}

/// Evidence of one settled call. No bearer tokens, keys or Cashu proofs.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SpendReceipt {
    pub reservation_id: String,
    pub budget: String,
    pub rail: &'static str,
    pub unit: &'static str,
    pub payee: String,
    pub model: String,
    pub reserved_ceiling: u64,
    pub final_cost: u64,
    pub outcome: &'static str,
}

#[derive(Debug)]
pub struct Completed {
    pub reply: Value,
    pub receipt: SpendReceipt,
}

pub struct RoutstrAdapter<R: RoutstrRail> {
    ledger: Arc<BudgetLedger>,
    rail: R,
    policy: RoutstrPolicy,
}

impl<R: RoutstrRail> RoutstrAdapter<R> {
    pub fn new(ledger: Arc<BudgetLedger>, rail: R, policy: RoutstrPolicy) -> Self {
        Self {
            ledger,
            rail,
            policy,
        }
    }

    /// Upper bound on what this request can cost, or a denial.
    pub fn ceiling_for(&self, body: &Value) -> Result<(String, u64), AdapterError> {
        self.ceiling_with_limit(body, None)
    }

    fn ceiling_with_limit(
        &self,
        body: &Value,
        caller_limit: Option<u64>,
    ) -> Result<(String, u64), AdapterError> {
        let model = body
            .get("model")
            .and_then(Value::as_str)
            .ok_or_else(|| AdapterError::Denied("request has no model".into()))?;
        let price = self.policy.models.get(model).ok_or_else(|| {
            AdapterError::Denied(format!("model {model} has no configured price"))
        })?;
        let max_tokens = body
            .get("max_tokens")
            .or_else(|| body.get("max_completion_tokens"))
            .and_then(Value::as_u64)
            .filter(|n| *n > 0)
            .ok_or_else(|| AdapterError::Denied("max_tokens is required to bound cost".into()))?;
        if body.get("stream").and_then(Value::as_bool).unwrap_or(false) {
            return Err(AdapterError::Denied(
                "streaming is not supported yet".into(),
            ));
        }
        // Input tokens never exceed serialized bytes, so bytes is a safe bound.
        let input_bound = serde_json::to_vec(body.get("messages").unwrap_or(&Value::Null))
            .map_err(|e| AdapterError::Denied(e.to_string()))?
            .len() as u64;
        let ceiling = cost_msat(price, input_bound, max_tokens)
            .ok_or_else(|| AdapterError::Denied("cost overflow".into()))?;
        let limit = caller_limit.map_or(self.policy.per_call_ceiling_msat, |l| {
            l.min(self.policy.per_call_ceiling_msat)
        });
        if ceiling > limit {
            return Err(AdapterError::Denied(format!(
                "ceiling {ceiling} msat exceeds per-call limit {limit}"
            )));
        }
        Ok((model.to_string(), ceiling))
    }

    pub async fn dispatch(
        &self,
        budget: &str,
        reservation_id: &str,
        body: Value,
    ) -> Result<Completed, AdapterError> {
        self.dispatch_with_limit(budget, reservation_id, body, None)
            .await
    }

    /// Like `dispatch`, with a tighter per-call limit from the caller's grant. The
    /// effective limit is the smaller of it and the adapter policy's.
    pub async fn dispatch_with_limit(
        &self,
        budget: &str,
        reservation_id: &str,
        body: Value,
        per_call_limit: Option<u64>,
    ) -> Result<Completed, AdapterError> {
        let (model, ceiling) = self.ceiling_with_limit(&body, per_call_limit)?;
        match self.ledger.reserve(budget, reservation_id, ceiling) {
            Ok(Reserved::New) => {}
            Ok(Reserved::Existing) => {
                return Err(AdapterError::AlreadyDispatched(reservation_id.into()))
            }
            Err(e) => return Err(AdapterError::Budget(e)),
        }
        let call = ChatCall {
            idempotency_key: reservation_id.into(),
            body,
        };
        let result = self.rail.chat(&call).await;
        match result {
            Ok(reply) => match measured_cost(&self.policy.models[&model], &reply.body) {
                Some(cost) => {
                    self.ledger
                        .finalize(reservation_id, cost)
                        .map_err(AdapterError::Budget)?;
                    let outcome = if cost > ceiling { "overrun" } else { "settled" };
                    Ok(Completed {
                        receipt: self.receipt(
                            budget,
                            reservation_id,
                            &model,
                            ceiling,
                            cost,
                            outcome,
                        ),
                        reply: reply.body,
                    })
                }
                None => {
                    // The call succeeded but usage is missing, so the charge is
                    // unknown. Hold the ceiling rather than assume zero.
                    self.hold(reservation_id, "success without usable usage")?;
                    Err(AdapterError::Uncertain(
                        "success without usable usage".into(),
                    ))
                }
            },
            Err(RailError::NotCharged(why)) => {
                self.ledger
                    .release(reservation_id)
                    .map_err(AdapterError::Budget)?;
                Err(AdapterError::Rejected(why))
            }
            Err(RailError::Unknown(why)) => {
                self.hold(reservation_id, &why)?;
                Err(AdapterError::Uncertain(why))
            }
        }
    }

    fn hold(&self, id: &str, note: &str) -> Result<(), AdapterError> {
        self.ledger
            .mark_uncertain(id, note)
            .map_err(AdapterError::Budget)
    }

    fn receipt(
        &self,
        budget: &str,
        id: &str,
        model: &str,
        ceiling: u64,
        cost: u64,
        outcome: &'static str,
    ) -> SpendReceipt {
        SpendReceipt {
            reservation_id: id.into(),
            budget: budget.into(),
            rail: "routstr",
            unit: UNIT,
            payee: self.policy.node.clone(),
            model: model.into(),
            reserved_ceiling: ceiling,
            final_cost: cost,
            outcome,
        }
    }

    /// Current spendable balance of the funded key, for an operator or reconciler
    /// comparing against the ledger. It cannot attribute a charge to one call
    /// when calls run concurrently, so it never resolves a reservation by itself.
    pub async fn observe_balance(&self) -> Result<u64, RailError> {
        self.rail.balance_msat().await
    }

    /// Operator reconciliation of an uncertain reservation: `Some(cost)` if the
    /// rail shows it was charged, `None` if the rail confirms it was not.
    pub fn reconcile(
        &self,
        reservation_id: &str,
        observed_cost: Option<u64>,
    ) -> Result<(), SpendError> {
        self.ledger.resolve_uncertain(reservation_id, observed_cost)
    }
}

fn cost_msat(p: &Pricing, input_tokens: u64, output_tokens: u64) -> Option<u64> {
    let part = |tokens: u64, rate: u64| -> Option<u64> {
        let n = (tokens as u128) * (rate as u128);
        // round up: never under-reserve
        u64::try_from(n.div_ceil(1_000_000)).ok()
    };
    part(input_tokens, p.input_msat_per_mtok)?
        .checked_add(part(output_tokens, p.output_msat_per_mtok)?)?
        .checked_add(p.request_fee_msat)
}

/// Cost from the reply's reported token usage at the configured price.
fn measured_cost(p: &Pricing, reply: &Value) -> Option<u64> {
    let usage = reply.get("usage")?;
    let input = usage.get("prompt_tokens")?.as_u64()?;
    let output = usage.get("completion_tokens")?.as_u64()?;
    cost_msat(p, input, output)
}

#[async_trait]
impl RoutstrRail for Box<dyn RoutstrRail> {
    async fn chat(&self, call: &ChatCall) -> Result<ChatReply, RailError> {
        (**self).chat(call).await
    }
    async fn balance_msat(&self) -> Result<u64, RailError> {
        (**self).balance_msat().await
    }
}

/// Ledger plus adapter, as held by the gate server.
pub struct SpendService {
    pub ledger: Arc<BudgetLedger>,
    pub adapter: RoutstrAdapter<Box<dyn RoutstrRail>>,
}

pub const ENV_SPEND_DIR: &str = "MEMBRANE_SPEND_DIR";
pub const ENV_ROUTSTR_POLICY: &str = "MEMBRANE_ROUTSTR_POLICY";
pub const ENV_ROUTSTR_API_KEY: &str = "MEMBRANE_ROUTSTR_API_KEY";

impl SpendService {
    /// Spending is off unless all three variables are set. A partial setup is an
    /// error, never a silent half-configuration. The funded key is operator
    /// supplied and never read from a request.
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        let dir = std::env::var_os(ENV_SPEND_DIR);
        let policy = std::env::var_os(ENV_ROUTSTR_POLICY);
        let key = std::env::var(ENV_ROUTSTR_API_KEY).ok();
        let (Some(dir), Some(policy), Some(key)) = (dir, policy, key) else {
            if dir_or_any_set() {
                anyhow::bail!(
                    "spend is partly configured: set {ENV_SPEND_DIR}, {ENV_ROUTSTR_POLICY} and {ENV_ROUTSTR_API_KEY} together"
                );
            }
            return Ok(None);
        };
        let policy: RoutstrPolicy = serde_yaml::from_str(&std::fs::read_to_string(&policy)?)?;
        if policy.per_call_ceiling_msat == 0 || policy.models.is_empty() {
            anyhow::bail!("routstr policy needs models and a positive per_call_ceiling_msat");
        }
        let rail = HttpRoutstr::new(&policy.node, key, Duration::from_secs(120))
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let ledger = Arc::new(BudgetLedger::open(dir).map_err(|e| anyhow::anyhow!("{e}"))?);
        let adapter = RoutstrAdapter::new(
            ledger.clone(),
            Box::new(rail) as Box<dyn RoutstrRail>,
            policy,
        );
        Ok(Some(Self { ledger, adapter }))
    }
}

fn dir_or_any_set() -> bool {
    [ENV_SPEND_DIR, ENV_ROUTSTR_POLICY, ENV_ROUTSTR_API_KEY]
        .iter()
        .any(|k| std::env::var_os(k).is_some())
}

/// HTTP client for a Routstr node. The `sk-` key never leaves this struct.
pub struct HttpRoutstr {
    base: String,
    key: String,
    http: reqwest::Client,
}

impl fmt::Debug for HttpRoutstr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpRoutstr")
            .field("base", &self.base)
            .field("key", &"<redacted>")
            .finish()
    }
}

impl HttpRoutstr {
    pub fn new(base: &str, key: String, timeout: Duration) -> Result<Self, RailError> {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| RailError::NotCharged(e.to_string()))?;
        Ok(Self {
            base: base.trim_end_matches('/').to_string(),
            key,
            http,
        })
    }
}

#[async_trait]
impl RoutstrRail for HttpRoutstr {
    async fn chat(&self, call: &ChatCall) -> Result<ChatReply, RailError> {
        let resp = self
            .http
            .post(format!("{}/chat/completions", self.base))
            .bearer_auth(&self.key)
            .header("Idempotency-Key", &call.idempotency_key)
            .json(&call.body)
            .send()
            .await
            .map_err(|e| {
                if e.is_connect() {
                    RailError::NotCharged("could not connect".into())
                } else {
                    RailError::Unknown(redact(&e.to_string(), &self.key))
                }
            })?;
        let status = resp.status();
        if status.is_client_error() {
            return Err(RailError::NotCharged(format!("http {status}")));
        }
        if !status.is_success() {
            return Err(RailError::Unknown(format!("http {status}")));
        }
        let body: Value = resp
            .json()
            .await
            .map_err(|_| RailError::Unknown("unreadable success reply".into()))?;
        Ok(ChatReply { body })
    }

    async fn balance_msat(&self) -> Result<u64, RailError> {
        let resp = self
            .http
            .get(format!("{}/balance/info", self.base))
            .bearer_auth(&self.key)
            .send()
            .await
            .map_err(|e| RailError::Unknown(redact(&e.to_string(), &self.key)))?;
        if !resp.status().is_success() {
            return Err(RailError::Unknown(format!("http {}", resp.status())));
        }
        let v: Value = resp
            .json()
            .await
            .map_err(|_| RailError::Unknown("unreadable reply".into()))?;
        v.get("balance")
            .and_then(Value::as_u64)
            .ok_or_else(|| RailError::Unknown("no balance field".into()))
    }
}

fn redact(s: &str, key: &str) -> String {
    if key.is_empty() {
        s.to_string()
    } else {
        s.replace(key, "<redacted>")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    enum Mode {
        Ok(Value),
        NotCharged,
        Unknown,
    }
    struct Mock {
        mode: Mutex<Mode>,
        calls: AtomicUsize,
        keys: Mutex<Vec<String>>,
    }
    impl Mock {
        fn new(mode: Mode) -> Arc<Self> {
            Arc::new(Self {
                mode: Mutex::new(mode),
                calls: AtomicUsize::new(0),
                keys: Mutex::new(vec![]),
            })
        }
    }
    #[async_trait]
    impl RoutstrRail for Arc<Mock> {
        async fn chat(&self, call: &ChatCall) -> Result<ChatReply, RailError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.keys.lock().unwrap().push(call.idempotency_key.clone());
            match &*self.mode.lock().unwrap() {
                Mode::Ok(v) => Ok(ChatReply { body: v.clone() }),
                Mode::NotCharged => Err(RailError::NotCharged("http 402".into())),
                Mode::Unknown => Err(RailError::Unknown("timeout".into())),
            }
        }
        async fn balance_msat(&self) -> Result<u64, RailError> {
            Ok(0)
        }
    }

    fn dir(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "membrane-routstr-{name}-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ))
    }
    fn policy() -> RoutstrPolicy {
        RoutstrPolicy {
            node: "https://api.routstr.com/v1".into(),
            models: BTreeMap::from([(
                "m".to_string(),
                Pricing {
                    input_msat_per_mtok: 1_000_000,
                    output_msat_per_mtok: 2_000_000,
                    request_fee_msat: 10,
                },
            )]),
            per_call_ceiling_msat: 5_000,
        }
    }
    fn body(max_tokens: u64) -> Value {
        json!({"model":"m","max_tokens":max_tokens,"messages":[{"role":"user","content":"hi"}]})
    }
    fn reply(p: u64, c: u64) -> Value {
        json!({"choices":[],"usage":{"prompt_tokens":p,"completion_tokens":c}})
    }
    fn setup(
        name: &str,
        mode: Mode,
        cap: u64,
    ) -> (Arc<BudgetLedger>, Arc<Mock>, RoutstrAdapter<Arc<Mock>>) {
        let ledger = Arc::new(BudgetLedger::open(dir(name)).unwrap());
        ledger.open_budget("b", UNIT, cap).unwrap();
        let mock = Mock::new(mode);
        let adapter = RoutstrAdapter::new(ledger.clone(), mock.clone(), policy());
        (ledger, mock, adapter)
    }

    #[tokio::test]
    async fn settles_at_measured_cost_and_frees_the_rest() {
        let (ledger, mock, a) = setup("settle", Mode::Ok(reply(10, 20)), 100_000);
        let done = a.dispatch("b", "r1", body(1000)).await.unwrap();
        // 10 in @1/tok + 20 out @2/tok + 10 fee = 60 msat
        assert_eq!(done.receipt.final_cost, 60);
        assert_eq!(done.receipt.outcome, "settled");
        assert!(done.receipt.reserved_ceiling > 60);
        let v = ledger.budget("b").unwrap();
        assert_eq!((v.spent, v.held), (60, 0));
        assert_eq!(mock.keys.lock().unwrap().as_slice(), ["r1"]);
    }

    #[tokio::test]
    async fn denies_without_a_ceiling_and_never_dispatches() {
        let (_l, mock, a) = setup("deny", Mode::Ok(reply(1, 1)), 100_000);
        let no_max = json!({"model":"m","messages":[]});
        assert!(matches!(
            a.dispatch("b", "r", no_max).await,
            Err(AdapterError::Denied(_))
        ));
        let bad_model = json!({"model":"x","max_tokens":5,"messages":[]});
        assert!(matches!(
            a.dispatch("b", "r", bad_model).await,
            Err(AdapterError::Denied(_))
        ));
        let mut streaming = body(5);
        streaming["stream"] = json!(true);
        assert!(matches!(
            a.dispatch("b", "r", streaming).await,
            Err(AdapterError::Denied(_))
        ));
        // 10_000 output tokens * 2 msat = 20_000 > per-call limit 5_000
        assert!(matches!(
            a.dispatch("b", "r", body(10_000)).await,
            Err(AdapterError::Denied(_))
        ));
        assert_eq!(mock.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn exhausted_budget_denies_before_dispatch() {
        let (_l, mock, a) = setup("exhaust", Mode::Ok(reply(1, 1)), 100);
        let r = a.dispatch("b", "r", body(1000)).await;
        assert!(matches!(
            r,
            Err(AdapterError::Budget(SpendError::Insufficient { .. }))
        ));
        assert_eq!(mock.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn definitive_refusal_releases_the_reservation() {
        let (ledger, _m, a) = setup("refuse", Mode::NotCharged, 100_000);
        assert!(matches!(
            a.dispatch("b", "r", body(100)).await,
            Err(AdapterError::Rejected(_))
        ));
        let v = ledger.budget("b").unwrap();
        assert_eq!((v.spent, v.held), (0, 0));
    }

    #[tokio::test]
    async fn timeout_holds_the_ceiling_and_blocks_redispatch() {
        let (ledger, mock, a) = setup("timeout", Mode::Unknown, 100_000);
        assert!(matches!(
            a.dispatch("b", "r", body(100)).await,
            Err(AdapterError::Uncertain(_))
        ));
        let held = ledger.budget("b").unwrap().held;
        assert!(held > 0);
        assert_eq!(
            ledger.reservation("r").unwrap().state,
            crate::spend::ReservationState::Uncertain
        );
        // retry with the same id must not send a second request
        assert!(matches!(
            a.dispatch("b", "r", body(100)).await,
            Err(AdapterError::AlreadyDispatched(_))
        ));
        assert_eq!(mock.calls.load(Ordering::SeqCst), 1);
        // reconciliation: rail shows it was charged 42
        a.reconcile("r", Some(42)).unwrap();
        let v = ledger.budget("b").unwrap();
        assert_eq!((v.spent, v.held), (42, 0));
    }

    #[tokio::test]
    async fn timeout_resolved_as_not_charged_frees_budget() {
        let (ledger, _m, a) = setup("freed", Mode::Unknown, 100_000);
        let _ = a.dispatch("b", "r", body(100)).await;
        a.reconcile("r", None).unwrap();
        assert_eq!(ledger.budget("b").unwrap().held, 0);
    }

    #[tokio::test]
    async fn success_without_usage_is_unpriceable_and_held() {
        let (ledger, _m, a) = setup("nousage", Mode::Ok(json!({"choices":[]})), 100_000);
        assert!(matches!(
            a.dispatch("b", "r", body(100)).await,
            Err(AdapterError::Uncertain(_))
        ));
        assert!(ledger.budget("b").unwrap().held > 0);
    }

    #[tokio::test]
    async fn overrun_is_flagged_not_capped() {
        // reply claims far more tokens than the request allowed
        let (ledger, _m, a) = setup("overrun", Mode::Ok(reply(0, 900)), 100_000);
        let done = a.dispatch("b", "r", body(10)).await.unwrap();
        assert_eq!(done.receipt.outcome, "overrun");
        assert_eq!(ledger.budget("b").unwrap().spent, done.receipt.final_cost);
    }

    #[tokio::test]
    async fn concurrent_calls_share_one_budget() {
        // ceiling per call for body(100) is small; budget fits only some of them
        let (ledger, mock, a) = setup("conc", Mode::Ok(reply(1, 1)), 1_000);
        let a = Arc::new(a);
        let tasks: Vec<_> = (0..40)
            .map(|i| {
                let a = a.clone();
                tokio::spawn(
                    async move { a.dispatch("b", &format!("r{i}"), body(100)).await.is_ok() },
                )
            })
            .collect();
        let mut ok = 0;
        for t in tasks {
            if t.await.unwrap() {
                ok += 1;
            }
        }
        assert!(ok >= 1);
        assert_eq!(mock.calls.load(Ordering::SeqCst), ok);
        let v = ledger.budget("b").unwrap();
        assert!(v.spent <= 1_000);
        assert_eq!(v.held, 0);
    }

    #[test]
    fn debug_redacts_the_key() {
        let c =
            HttpRoutstr::new("https://x/v1", "sk-secret".into(), Duration::from_secs(1)).unwrap();
        let s = format!("{c:?}");
        assert!(!s.contains("sk-secret") && s.contains("redacted"));
        assert_eq!(
            redact("err sk-secret end", "sk-secret"),
            "err <redacted> end"
        );
    }

    #[test]
    fn rounds_cost_up() {
        let p = Pricing {
            input_msat_per_mtok: 1,
            output_msat_per_mtok: 0,
            request_fee_msat: 0,
        };
        assert_eq!(cost_msat(&p, 1, 0), Some(1));
        assert_eq!(cost_msat(&p, 0, 0), Some(0));
    }
}
