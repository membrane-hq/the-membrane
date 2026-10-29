//! Crossmint rail adapter (design: docs/settlement-adapters.md).
//!
//! Rail two, next to [`crate::routstr`]. Where Routstr meters inference, this
//! adapter moves a fixed amount of a stablecoin (USDC) from an operator-owned
//! Crossmint wallet to an allowlisted payee, using Crossmint's REST transfer
//! endpoint. The same discipline applies:
//!
//! 1. Check the intent against policy (payee allowlist, positive amount,
//!    per-call ceiling). A transfer has a known cost, so the ceiling is the
//!    amount. If it cannot be bounded, deny. Nothing is sent.
//! 2. Reserve the amount in the shared [`BudgetLedger`]. Only a *new*
//!    reservation may dispatch.
//! 3. Dispatch once, with the reservation id as the `x-idempotency-key`.
//! 4. Settle: finalize on `success`, release only on a definite refusal or an
//!    onchain `failed`, otherwise hold as uncertain. A transfer that is
//!    `pending` or `awaiting-approval` may still complete, so it is held.
//!
//! The API key and any signer secret live inside the rail client and appear in
//! no error, receipt or `Debug` output. The adapter never grants authority.
//!
//! Status: mock-tested, and the HTTP client is tested against a local stand-in
//! server. It has not been run against Crossmint. No signer implementation
//! ships, so a live transfer that needs an approval signature stays held.
use crate::secret::Secret;
use crate::spend::{BudgetLedger, Reserved, SpendError};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::BTreeSet, fmt, sync::Arc, time::Duration};

/// Ledger unit: millionths of a USDC (USDC has 6 decimals).
pub const UNIT: &str = "usdc_micro";
const DECIMALS: u32 = 6;
const API_VERSION: &str = "2025-06-09";

pub const ENV_CROSSMINT_POLICY: &str = "MEMBRANE_CROSSMINT_POLICY";
pub const ENV_CROSSMINT_API_KEY: &str = "MEMBRANE_CROSSMINT_API_KEY";
/// Path to a 0600 file holding the key. Preferred over the environment variable.
pub const ENV_CROSSMINT_API_KEY_FILE: &str = "MEMBRANE_CROSSMINT_API_KEY_FILE";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossmintPolicy {
    /// API origin, set by the operator: `https://staging.crossmint.com` or the
    /// production origin from their Crossmint console. No default, so a typo
    /// cannot silently point at the wrong environment.
    pub api_base: String,
    /// Wallet locator or address the transfers are sent from.
    pub wallet: String,
    /// Chain slug, for example `base` or `base-sepolia`.
    pub chain: String,
    /// Token slug, for example `usdc`.
    pub token: String,
    /// The only addresses that may be paid. Empty means deny everything.
    pub payees: BTreeSet<String>,
    /// Hard ceiling for one transfer, in micro-USDC.
    pub per_call_ceiling_micro: u64,
}

/// A payment intent that already passed the gate's scope checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferCall {
    /// Reservation id, sent as the idempotency key.
    pub idempotency_key: String,
    pub payee: String,
    pub amount_micro: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferStatus {
    /// Final on chain.
    Success,
    /// Submitted, not final. May still complete.
    Pending,
    /// Created but waiting for a wallet signer. Nothing signed yet, but it must
    /// not be assumed dead.
    AwaitingApproval,
    /// Failed on chain or at Crossmint.
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferResult {
    /// Crossmint transaction id, kept for reconciliation.
    pub id: String,
    pub status: TransferStatus,
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
pub trait CrossmintRail: Send + Sync {
    async fn transfer(&self, call: &TransferCall) -> Result<TransferResult, RailError>;
}

/// Signs the approval message Crossmint returns for a transfer. The operator
/// supplies the implementation; the adapter and gate never see the key.
#[allow(clippy::double_must_use)]
#[async_trait]
pub trait ApprovalSigner: Send + Sync {
    /// Crossmint signer locator, for example `external-wallet:0x...`.
    fn locator(&self) -> String;
    /// Sign the hex `message` exactly as returned. Returns the signature.
    async fn sign(&self, message: &str) -> Result<String, String>;
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AdapterError {
    #[error("denied before dispatch: {0}")]
    Denied(String),
    #[error("budget: {0}")]
    Budget(SpendError),
    #[error("rail refused, nothing charged, reservation released: {0}")]
    Rejected(String),
    #[error("outcome unknown, amount held for reconciliation: {0}")]
    Uncertain(String),
    #[error("reservation {0} already exists; refusing to dispatch it again")]
    AlreadyDispatched(String),
}

/// Evidence of one settled transfer. No API keys, signer secrets or signatures.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SpendReceipt {
    pub reservation_id: String,
    pub budget: String,
    pub rail: &'static str,
    pub unit: &'static str,
    pub payee: String,
    pub chain: String,
    pub token: String,
    pub reserved_ceiling: u64,
    pub final_cost: u64,
    /// Crossmint transaction id, to link this receipt to the provider record.
    pub settlement_ref: String,
    pub outcome: &'static str,
}

pub struct CrossmintAdapter<R: CrossmintRail> {
    ledger: Arc<BudgetLedger>,
    rail: R,
    policy: CrossmintPolicy,
}

impl<R: CrossmintRail> CrossmintAdapter<R> {
    pub fn new(ledger: Arc<BudgetLedger>, rail: R, policy: CrossmintPolicy) -> Self {
        Self {
            ledger,
            rail,
            policy,
        }
    }

    /// Upper bound on the cost of this intent, or a denial.
    pub fn ceiling_for(
        &self,
        payee: &str,
        amount_micro: u64,
        caller_limit: Option<u64>,
    ) -> Result<u64, AdapterError> {
        if amount_micro == 0 {
            return Err(AdapterError::Denied("amount must be positive".into()));
        }
        if !self.policy.payees.contains(payee) {
            return Err(AdapterError::Denied(format!(
                "payee {payee} is not allowed"
            )));
        }
        let limit = caller_limit.map_or(self.policy.per_call_ceiling_micro, |l| {
            l.min(self.policy.per_call_ceiling_micro)
        });
        if amount_micro > limit {
            return Err(AdapterError::Denied(format!(
                "amount {amount_micro} exceeds per-call limit {limit}"
            )));
        }
        Ok(amount_micro)
    }

    pub async fn pay(
        &self,
        budget: &str,
        reservation_id: &str,
        payee: &str,
        amount_micro: u64,
        per_call_limit: Option<u64>,
    ) -> Result<SpendReceipt, AdapterError> {
        let ceiling = self.ceiling_for(payee, amount_micro, per_call_limit)?;
        match self.ledger.reserve(budget, reservation_id, ceiling) {
            Ok(Reserved::New) => {}
            Ok(Reserved::Existing) => {
                return Err(AdapterError::AlreadyDispatched(reservation_id.into()))
            }
            Err(e) => return Err(AdapterError::Budget(e)),
        }
        let call = TransferCall {
            idempotency_key: reservation_id.into(),
            payee: payee.into(),
            amount_micro,
        };
        match self.rail.transfer(&call).await {
            Ok(r) => match r.status {
                TransferStatus::Success => {
                    self.ledger
                        .finalize(reservation_id, amount_micro)
                        .map_err(AdapterError::Budget)?;
                    Ok(self.receipt(budget, reservation_id, payee, ceiling, r.id))
                }
                TransferStatus::Failed => {
                    self.ledger
                        .release(reservation_id)
                        .map_err(AdapterError::Budget)?;
                    Err(AdapterError::Rejected(format!("transfer {} failed", r.id)))
                }
                TransferStatus::Pending | TransferStatus::AwaitingApproval => {
                    let why = format!("transfer {} not final ({:?})", r.id, r.status);
                    self.hold(reservation_id, &why)?;
                    Err(AdapterError::Uncertain(why))
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
        payee: &str,
        amount: u64,
        tx_id: String,
    ) -> SpendReceipt {
        SpendReceipt {
            reservation_id: id.into(),
            budget: budget.into(),
            rail: "crossmint",
            unit: UNIT,
            payee: payee.into(),
            chain: self.policy.chain.clone(),
            token: self.policy.token.clone(),
            reserved_ceiling: amount,
            final_cost: amount,
            settlement_ref: tx_id,
            outcome: "settled",
        }
    }

    /// Operator reconciliation of an uncertain reservation against Crossmint's
    /// own record: `Some(cost)` if the transfer succeeded, `None` if confirmed
    /// not to have happened.
    pub fn reconcile(&self, id: &str, observed_cost: Option<u64>) -> Result<(), SpendError> {
        self.ledger.resolve_uncertain(id, observed_cost)
    }
}

/// Micro-USDC as the decimal string Crossmint expects, for example `3140000`
/// becomes `3.14`.
pub fn format_amount(micro: u64) -> String {
    let scale = 10u64.pow(DECIMALS);
    let (whole, frac) = (micro / scale, micro % scale);
    if frac == 0 {
        return whole.to_string();
    }
    let frac = format!("{frac:0width$}", width = DECIMALS as usize);
    format!("{whole}.{}", frac.trim_end_matches('0'))
}

fn parse_status(v: &Value) -> Option<TransferResult> {
    let id = v.get("id")?.as_str()?.to_string();
    let status = match v.get("status")?.as_str()? {
        "success" => TransferStatus::Success,
        "pending" => TransferStatus::Pending,
        "awaiting-approval" => TransferStatus::AwaitingApproval,
        "failed" => TransferStatus::Failed,
        _ => return None,
    };
    Some(TransferResult { id, status })
}

fn pending_message(v: &Value) -> Option<String> {
    v.pointer("/approvals/pending/0/message")
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// Crossmint REST client. The API key never leaves this struct.
pub struct HttpCrossmint {
    policy: CrossmintPolicy,
    key: Secret,
    signer: Option<Arc<dyn ApprovalSigner>>,
    http: reqwest::Client,
    polls: u32,
    poll_every: Duration,
}

impl fmt::Debug for HttpCrossmint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpCrossmint")
            .field("api_base", &self.policy.api_base)
            .field("wallet", &self.policy.wallet)
            .field("key", &"<redacted>")
            .field("signer", &self.signer.as_ref().map(|s| s.locator()))
            .finish()
    }
}

impl HttpCrossmint {
    pub fn new(
        policy: CrossmintPolicy,
        key: Secret,
        signer: Option<Arc<dyn ApprovalSigner>>,
        timeout: Duration,
    ) -> Result<Self, RailError> {
        // No redirects: X-API-KEY is a custom header and would follow a
        // cross-host redirect, so the client refuses to follow any.
        membrane_core::tls::install_default_provider();
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| RailError::NotCharged(e.to_string()))?;
        let mut policy = policy;
        policy.api_base = policy.api_base.trim_end_matches('/').to_string();
        Ok(Self {
            policy,
            key,
            signer,
            http,
            polls: 10,
            poll_every: Duration::from_secs(2),
        })
    }

    /// Load policy and key from the environment. `None` when neither is set; a
    /// partial setup is an error. Operator-supplied; never read from a request.
    pub fn from_env(
        signer: Option<Arc<dyn ApprovalSigner>>,
    ) -> anyhow::Result<Option<(Self, CrossmintPolicy)>> {
        let path = std::env::var_os(ENV_CROSSMINT_POLICY);
        let key = Secret::load(ENV_CROSSMINT_API_KEY_FILE, &[ENV_CROSSMINT_API_KEY])?;
        let (Some(path), Some(key)) = (path.clone(), key.clone()) else {
            if path.is_some()
                || key.is_some()
                || std::env::var_os(ENV_CROSSMINT_API_KEY_FILE).is_some()
            {
                anyhow::bail!(
                    "crossmint is partly configured: set {ENV_CROSSMINT_POLICY} and {ENV_CROSSMINT_API_KEY} together"
                );
            }
            return Ok(None);
        };
        let policy: CrossmintPolicy = serde_yaml::from_str(&std::fs::read_to_string(path)?)?;
        if policy.per_call_ceiling_micro == 0
            || policy.payees.is_empty()
            || policy.api_base.is_empty()
            || policy.wallet.is_empty()
        {
            anyhow::bail!(
                "crossmint policy needs api_base, wallet, payees and a positive per_call_ceiling_micro"
            );
        }
        let rail = Self::new(policy.clone(), key, signer, Duration::from_secs(60))
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        Ok(Some((rail, policy)))
    }

    fn transfers_url(&self) -> String {
        format!(
            "{}/api/{API_VERSION}/wallets/{}/tokens/{}:{}/transfers",
            self.policy.api_base, self.policy.wallet, self.policy.chain, self.policy.token
        )
    }

    fn unknown(&self, e: impl fmt::Display) -> RailError {
        RailError::Unknown(self.key.scrub(&e.to_string()))
    }

    async fn read(&self, resp: reqwest::Response) -> Result<Value, RailError> {
        let status = resp.status();
        if status.is_client_error() {
            return Err(RailError::NotCharged(format!("http {status}")));
        }
        if !status.is_success() {
            return Err(RailError::Unknown(format!("http {status}")));
        }
        resp.json()
            .await
            .map_err(|_| RailError::Unknown("unreadable reply".into()))
    }
}

#[async_trait]
impl CrossmintRail for HttpCrossmint {
    async fn transfer(&self, call: &TransferCall) -> Result<TransferResult, RailError> {
        let mut body = json!({
            "recipient": call.payee,
            "amount": format_amount(call.amount_micro),
        });
        if let Some(s) = &self.signer {
            body["signer"] = json!(s.locator());
        }
        let resp = self
            .http
            .post(self.transfers_url())
            .header("X-API-KEY", self.key.expose())
            .header("x-idempotency-key", &call.idempotency_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                if e.is_connect() {
                    RailError::NotCharged("could not connect".into())
                } else {
                    self.unknown(e)
                }
            })?;
        let created = self.read(resp).await?;
        let mut result = parse_status(&created)
            .ok_or_else(|| RailError::Unknown("unrecognized transfer reply".into()))?;

        if result.status == TransferStatus::AwaitingApproval {
            // Without a signer the transfer stays unapproved; the adapter holds it.
            let (Some(signer), Some(message)) = (&self.signer, pending_message(&created)) else {
                return Ok(result);
            };
            let signature = signer
                .sign(&message)
                .await
                .map_err(|e| self.unknown(format!("signer failed: {e}")))?;
            let url = format!(
                "{}/api/{API_VERSION}/wallets/{}/transactions/{}/approvals",
                self.policy.api_base, self.policy.wallet, result.id
            );
            let resp = self
                .http
                .post(url)
                .header("X-API-KEY", self.key.expose())
                .json(&json!({"approvals": [{"signer": signer.locator(), "signature": signature}]}))
                .send()
                .await
                .map_err(|e| self.unknown(e))?;
            // The transfer exists now, so a refusal here is not proof of "not charged".
            let approved = self.read(resp).await.map_err(|e| match e {
                RailError::NotCharged(w) => RailError::Unknown(w),
                other => other,
            })?;
            if let Some(r) = parse_status(&approved) {
                result = r;
            }
        }

        // Poll toward finality. Anything still non-final is held by the adapter.
        let mut polls = 0;
        while result.status == TransferStatus::Pending && polls < self.polls {
            tokio::time::sleep(self.poll_every).await;
            polls += 1;
            let resp = self
                .http
                .get(format!("{}/{}", self.transfers_url(), result.id))
                .header("X-API-KEY", self.key.expose())
                .send()
                .await
                .map_err(|e| self.unknown(e))?;
            let v = self.read(resp).await.map_err(|e| match e {
                RailError::NotCharged(w) => RailError::Unknown(w),
                other => other,
            })?;
            if let Some(r) = parse_status(&v) {
                result = r;
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        extract::State,
        http::{HeaderMap, StatusCode},
        routing::post,
        Json, Router,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    enum Mode {
        Status(TransferStatus),
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
    impl CrossmintRail for Arc<Mock> {
        async fn transfer(&self, call: &TransferCall) -> Result<TransferResult, RailError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.keys.lock().unwrap().push(call.idempotency_key.clone());
            match &*self.mode.lock().unwrap() {
                Mode::Status(s) => Ok(TransferResult {
                    id: "tx1".into(),
                    status: *s,
                }),
                Mode::NotCharged => Err(RailError::NotCharged("http 402".into())),
                Mode::Unknown => Err(RailError::Unknown("timeout".into())),
            }
        }
    }

    const PAYEE: &str = "0xAAAA000000000000000000000000000000000001";

    fn policy() -> CrossmintPolicy {
        CrossmintPolicy {
            api_base: "https://staging.crossmint.com".into(),
            wallet: "0xWALLET".into(),
            chain: "base-sepolia".into(),
            token: "usdc".into(),
            payees: BTreeSet::from([PAYEE.to_string()]),
            per_call_ceiling_micro: 5_000_000,
        }
    }
    fn dir(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "membrane-crossmint-{name}-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ))
    }
    fn setup(
        name: &str,
        mode: Mode,
        cap: u64,
    ) -> (Arc<BudgetLedger>, Arc<Mock>, CrossmintAdapter<Arc<Mock>>) {
        let ledger = Arc::new(BudgetLedger::open(dir(name)).unwrap());
        ledger.open_budget("b", UNIT, cap).unwrap();
        let mock = Mock::new(mode);
        let adapter = CrossmintAdapter::new(ledger.clone(), mock.clone(), policy());
        (ledger, mock, adapter)
    }

    #[tokio::test]
    async fn success_finalizes_and_receipts_without_secrets() {
        let (ledger, mock, a) = setup("ok", Mode::Status(TransferStatus::Success), 10_000_000);
        let r = a.pay("b", "r1", PAYEE, 1_500_000, None).await.unwrap();
        assert_eq!(r.final_cost, 1_500_000);
        assert_eq!(r.settlement_ref, "tx1");
        assert_eq!(r.rail, "crossmint");
        let v = ledger.budget("b").unwrap();
        assert_eq!((v.spent, v.held, v.remaining), (1_500_000, 0, 8_500_000));
        assert_eq!(mock.keys.lock().unwrap().as_slice(), ["r1"]);
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains("key") && !json.contains("signature"));
    }

    #[tokio::test]
    async fn denies_unknown_payee_zero_and_over_ceiling_without_dispatch() {
        let (ledger, mock, a) = setup("deny", Mode::Status(TransferStatus::Success), 10_000_000);
        assert!(matches!(
            a.pay("b", "r1", "0xBAD", 1, None).await,
            Err(AdapterError::Denied(_))
        ));
        assert!(matches!(
            a.pay("b", "r2", PAYEE, 0, None).await,
            Err(AdapterError::Denied(_))
        ));
        assert!(matches!(
            a.pay("b", "r3", PAYEE, 5_000_001, None).await,
            Err(AdapterError::Denied(_))
        ));
        // a tighter grant limit wins over the policy ceiling
        assert!(matches!(
            a.pay("b", "r4", PAYEE, 2_000_000, Some(1_000_000)).await,
            Err(AdapterError::Denied(_))
        ));
        assert_eq!(mock.calls.load(Ordering::SeqCst), 0);
        assert_eq!(ledger.budget("b").unwrap().held, 0);
    }

    #[tokio::test]
    async fn exhausted_budget_denies_before_dispatch() {
        let (_l, mock, a) = setup("budget", Mode::Status(TransferStatus::Success), 1_000_000);
        assert!(matches!(
            a.pay("b", "r1", PAYEE, 2_000_000, None).await,
            Err(AdapterError::Budget(SpendError::Insufficient { .. }))
        ));
        assert_eq!(mock.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn repeat_reservation_never_sends_twice() {
        let (_l, mock, a) = setup("repeat", Mode::Status(TransferStatus::Success), 10_000_000);
        a.pay("b", "r1", PAYEE, 1_000_000, None).await.unwrap();
        assert!(matches!(
            a.pay("b", "r1", PAYEE, 1_000_000, None).await,
            Err(AdapterError::AlreadyDispatched(_))
        ));
        assert_eq!(mock.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn definite_refusal_and_failed_transfer_release() {
        let (ledger, _m, a) = setup("refuse", Mode::NotCharged, 10_000_000);
        assert!(matches!(
            a.pay("b", "r1", PAYEE, 1_000_000, None).await,
            Err(AdapterError::Rejected(_))
        ));
        assert_eq!(ledger.budget("b").unwrap().held, 0);
        let (ledger, _m, a) = setup("failed", Mode::Status(TransferStatus::Failed), 10_000_000);
        assert!(matches!(
            a.pay("b", "r1", PAYEE, 1_000_000, None).await,
            Err(AdapterError::Rejected(_))
        ));
        assert_eq!(ledger.budget("b").unwrap().held, 0);
    }

    #[tokio::test]
    async fn timeout_pending_and_unapproved_are_held_not_released() {
        for (name, mode) in [
            ("timeout", Mode::Unknown),
            ("pending", Mode::Status(TransferStatus::Pending)),
            ("approval", Mode::Status(TransferStatus::AwaitingApproval)),
        ] {
            let (ledger, _m, a) = setup(name, mode, 10_000_000);
            assert!(matches!(
                a.pay("b", "r1", PAYEE, 1_000_000, None).await,
                Err(AdapterError::Uncertain(_))
            ));
            assert_eq!(ledger.budget("b").unwrap().held, 1_000_000, "{name}");
            assert_eq!(ledger.open_reservations().unwrap().len(), 1);
            // reconcile: Crossmint shows it landed
            a.reconcile("r1", Some(1_000_000)).unwrap();
            let v = ledger.budget("b").unwrap();
            assert_eq!((v.spent, v.held), (1_000_000, 0));
        }
    }

    #[test]
    fn amounts_format_as_crossmint_decimals() {
        assert_eq!(format_amount(3_140_000), "3.14");
        assert_eq!(format_amount(1_000_000), "1");
        assert_eq!(format_amount(1), "0.000001");
        assert_eq!(format_amount(500_000), "0.5");
    }

    #[test]
    fn debug_never_shows_key() {
        let rail = HttpCrossmint::new(
            policy(),
            "sk_secret_value".into(),
            None,
            Duration::from_secs(1),
        )
        .unwrap();
        let d = format!("{rail:?}");
        assert!(!d.contains("sk_secret_value"));
        assert_eq!(
            Secret::new("sk_secret_value").scrub("boom sk_secret_value"),
            "boom [redacted]"
        );
    }

    #[tokio::test]
    async fn api_key_does_not_follow_a_redirect() {
        use axum::{http::StatusCode, routing::any};
        use std::sync::atomic::{AtomicUsize, Ordering};
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        let target = axum::Router::new().fallback(any(move || {
            let h = h.clone();
            async move {
                h.fetch_add(1, Ordering::SeqCst);
                StatusCode::OK
            }
        }));
        let tl = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = tl.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(tl, target).await.ok() });
        let redirect = axum::Router::new().fallback(any(move || async move {
            (
                StatusCode::TEMPORARY_REDIRECT,
                [("location", format!("http://{target_addr}/stolen"))],
            )
        }));
        let rl = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", rl.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(rl, redirect).await.ok() });
        let rail = http_rail(&base, None);
        let call = TransferCall {
            idempotency_key: "res-redirect".into(),
            payee: PAYEE.into(),
            amount_micro: 1_000_000,
        };
        assert!(rail.transfer(&call).await.is_err());
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }

    // ---- HTTP client against a local stand-in for the Crossmint API ----

    #[derive(Default)]
    struct Seen {
        creates: Mutex<Vec<(HeaderMap, Value)>>,
        approvals: Mutex<Vec<Value>>,
    }

    struct FixedSigner;
    #[async_trait]
    impl ApprovalSigner for FixedSigner {
        fn locator(&self) -> String {
            "external-wallet:0xSIGNER".into()
        }
        async fn sign(&self, message: &str) -> Result<String, String> {
            Ok(format!("sig-of-{message}"))
        }
    }

    async fn serve(first: &'static str, create_status: u16) -> (String, Arc<Seen>) {
        let seen = Arc::new(Seen::default());
        let app = Router::new()
            .route(
                "/api/2025-06-09/wallets/0xWALLET/tokens/base-sepolia:usdc/transfers",
                post(
                    move |State(s): State<Arc<Seen>>, h: HeaderMap, Json(b): Json<Value>| async move {
                        s.creates.lock().unwrap().push((h, b));
                        let body = json!({
                            "id": "tx-http",
                            "status": first,
                            "approvals": {"pending": [{"message": "0xDEAD"}]}
                        });
                        (StatusCode::from_u16(create_status).unwrap(), Json(body))
                    },
                ),
            )
            .route(
                "/api/2025-06-09/wallets/0xWALLET/transactions/tx-http/approvals",
                post(
                    |State(s): State<Arc<Seen>>, Json(b): Json<Value>| async move {
                        s.approvals.lock().unwrap().push(b);
                        Json(json!({"id": "tx-http", "status": "success"}))
                    },
                ),
            )
            .with_state(seen.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}"), seen)
    }

    fn http_rail(base: &str, signer: Option<Arc<dyn ApprovalSigner>>) -> HttpCrossmint {
        let mut p = policy();
        p.api_base = base.into();
        HttpCrossmint::new(p, "sk_secret_value".into(), signer, Duration::from_secs(5)).unwrap()
    }

    #[tokio::test]
    async fn http_sends_key_idempotency_and_decimal_amount() {
        let (base, seen) = serve("success", 200).await;
        let rail = http_rail(&base, None);
        let call = TransferCall {
            idempotency_key: "res-1".into(),
            payee: PAYEE.into(),
            amount_micro: 3_140_000,
        };
        let r = rail.transfer(&call).await.unwrap();
        assert_eq!(r.status, TransferStatus::Success);
        let creates = seen.creates.lock().unwrap();
        let (h, b) = &creates[0];
        assert_eq!(h["x-api-key"], "sk_secret_value");
        assert_eq!(h["x-idempotency-key"], "res-1");
        assert_eq!(b["recipient"], PAYEE);
        assert_eq!(b["amount"], "3.14");
        assert!(b.get("signer").is_none());
    }

    #[tokio::test]
    async fn http_without_signer_leaves_unapproved_transfer_held() {
        let (base, seen) = serve("awaiting-approval", 200).await;
        let rail = http_rail(&base, None);
        let call = TransferCall {
            idempotency_key: "res-2".into(),
            payee: PAYEE.into(),
            amount_micro: 1_000_000,
        };
        let r = rail.transfer(&call).await.unwrap();
        assert_eq!(r.status, TransferStatus::AwaitingApproval);
        assert!(seen.approvals.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn http_with_signer_submits_approval_for_the_returned_message() {
        let (base, seen) = serve("awaiting-approval", 200).await;
        let rail = http_rail(&base, Some(Arc::new(FixedSigner)));
        let call = TransferCall {
            idempotency_key: "res-3".into(),
            payee: PAYEE.into(),
            amount_micro: 1_000_000,
        };
        let r = rail.transfer(&call).await.unwrap();
        assert_eq!(r.status, TransferStatus::Success);
        let creates = seen.creates.lock().unwrap();
        assert_eq!(creates[0].1["signer"], "external-wallet:0xSIGNER");
        let ap = seen.approvals.lock().unwrap();
        assert_eq!(ap[0]["approvals"][0]["signature"], "sig-of-0xDEAD");
        assert_eq!(ap[0]["approvals"][0]["signer"], "external-wallet:0xSIGNER");
    }

    #[tokio::test]
    async fn http_status_codes_map_to_charge_certainty() {
        let call = TransferCall {
            idempotency_key: "res-4".into(),
            payee: PAYEE.into(),
            amount_micro: 1_000_000,
        };
        let (base, _s) = serve("success", 402).await;
        assert!(matches!(
            http_rail(&base, None).transfer(&call).await,
            Err(RailError::NotCharged(_))
        ));
        let (base, _s) = serve("success", 502).await;
        assert!(matches!(
            http_rail(&base, None).transfer(&call).await,
            Err(RailError::Unknown(_))
        ));
        let (base, _s) = serve("mystery-status", 200).await;
        assert!(matches!(
            http_rail(&base, None).transfer(&call).await,
            Err(RailError::Unknown(_))
        ));
    }
}
