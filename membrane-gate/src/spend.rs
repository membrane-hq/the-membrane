//! Durable, atomic spend budget ledger.
//!
//! Many concurrent calls reserve a cost ceiling against one shared budget before
//! anything is dispatched. Every transition is appended to a checksummed,
//! hash-chained, fsynced journal before it takes effect in memory. Any journal
//! failure poisons the ledger: it denies everything until an operator restarts
//! and replays it. Amounts are integers in the budget's smallest unit (for
//! example millisatoshi); there is no floating point and no unit conversion.
//!
//! The ledger only does accounting. It does not hold payment credentials, talk
//! to a rail, or decide policy. Adapters call it around a dispatch:
//!
//! 1. `reserve` the ceiling (denied if it does not fit the remaining budget).
//! 2. Dispatch once, bound to the reservation id as the idempotency key.
//! 3. `finalize` at the measured cost, `release` if nothing was spent, or
//!    `mark_uncertain` if the outcome is unknown. An uncertain reservation keeps
//!    holding its ceiling until `resolve_uncertain`. A timeout is not proof that
//!    nothing was paid.
//!
//! Open reservations survive a crash and are replayed as held, so a restart can
//! only make the ledger stricter, never more permissive.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Mutex,
};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SpendError {
    #[error("budget not found: {0}")]
    UnknownBudget(String),
    #[error("reservation not found: {0}")]
    UnknownReservation(String),
    #[error("budget {budget} exhausted: need {needed}, remaining {remaining}")]
    Insufficient {
        budget: String,
        needed: u64,
        remaining: u64,
    },
    #[error("conflicting request for existing id: {0}")]
    Conflict(String),
    #[error("invalid transition for reservation {id}: state is {state}")]
    InvalidState { id: String, state: &'static str },
    #[error("invalid amount: {0}")]
    InvalidAmount(String),
    #[error("ledger failed closed: {0}")]
    Closed(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationState {
    /// Ceiling is held; dispatch has not been confirmed either way.
    Reserved,
    /// Dispatch may have spent funds and the result is unknown. Ceiling stays held.
    Uncertain,
    Finalized,
    Released,
}
impl ReservationState {
    fn name(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Uncertain => "uncertain",
            Self::Finalized => "finalized",
            Self::Released => "released",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Record {
    OpenBudget {
        budget: String,
        unit: String,
        cap: u64,
    },
    Reserve {
        budget: String,
        id: String,
        ceiling: u64,
    },
    Finalize {
        id: String,
        spent: u64,
    },
    Release {
        id: String,
    },
    Uncertain {
        id: String,
        note: String,
    },
}

#[derive(Serialize, Deserialize)]
struct Frame {
    sequence: u64,
    previous: String,
    record: Record,
    checksum: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Reservation {
    pub id: String,
    pub budget: String,
    pub ceiling: u64,
    pub state: ReservationState,
    /// Final measured cost once finalized.
    pub spent: Option<u64>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BudgetView {
    pub budget: String,
    pub unit: String,
    pub cap: u64,
    /// Final spend recorded so far.
    pub spent: u64,
    /// Ceilings held by open (reserved or uncertain) reservations.
    pub held: u64,
    pub remaining: u64,
}

struct Budget {
    unit: String,
    cap: u64,
    spent: u64,
    held: u64,
}

struct Inner {
    file: File,
    sequence: u64,
    previous: String,
    budgets: BTreeMap<String, Budget>,
    reservations: BTreeMap<String, Reservation>,
    poisoned: Option<String>,
    _lock: File,
}

pub struct BudgetLedger {
    dir: PathBuf,
    inner: Mutex<Inner>,
}

/// Outcome of `reserve`: `Existing` means the same reservation id was already
/// accepted with identical parameters, so a retry never double-holds budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reserved {
    New,
    Existing,
}

impl BudgetLedger {
    /// Open (or create) the ledger in `dir`, replaying and verifying the journal.
    /// A torn tail, checksum break or inconsistent record refuses to open.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, SpendError> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir).map_err(closed)?;
        let absolute = fs::canonicalize(&dir).map_err(closed)?;
        for ancestor in absolute.ancestors() {
            File::open(ancestor)
                .and_then(|f| f.sync_all())
                .map_err(closed)?;
        }
        let mut lock_opts = OpenOptions::new();
        lock_opts
            .create(true)
            .truncate(false)
            .read(true)
            .write(true);
        #[cfg(unix)]
        lock_opts.mode(0o600);
        let lock = lock_opts.open(dir.join("ledger.lock")).map_err(closed)?;
        lock.try_lock()
            .map_err(|e| SpendError::Closed(format!("ledger already open elsewhere: {e}")))?;

        let path = dir.join("ledger.jsonl");
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => vec![],
            Err(e) => return Err(closed(e)),
        };
        if !bytes.is_empty() && !bytes.ends_with(b"\n") {
            return Err(SpendError::Closed(
                "torn ledger tail; operator review required".into(),
            ));
        }
        let mut state = Inner {
            file: open_append(&path)?,
            sequence: 0,
            previous: "0".repeat(64),
            budgets: BTreeMap::new(),
            reservations: BTreeMap::new(),
            poisoned: None,
            _lock: lock,
        };
        if !bytes.is_empty() {
            for line in bytes[..bytes.len() - 1].split(|b| *b == b'\n') {
                let frame: Frame = serde_json::from_slice(line).map_err(closed)?;
                let checksum = digest(&(frame.sequence, &frame.previous, &frame.record))?;
                if frame.sequence != state.sequence
                    || frame.previous != state.previous
                    || frame.checksum != checksum
                {
                    return Err(SpendError::Closed(
                        "ledger checksum/sequence discontinuity".into(),
                    ));
                }
                state.apply(&frame.record).map_err(|e| {
                    SpendError::Closed(format!(
                        "ledger replay inconsistent at {}: {e}",
                        frame.sequence
                    ))
                })?;
                state.sequence += 1;
                state.previous = frame.checksum;
            }
        }
        Ok(Self {
            dir,
            inner: Mutex::new(state),
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Create a budget. Repeating the call with identical parameters is a no-op;
    /// different parameters for an existing id are a conflict (budgets are not
    /// resized in place).
    pub fn open_budget(&self, budget: &str, unit: &str, cap: u64) -> Result<(), SpendError> {
        nonempty(budget, "budget id")?;
        nonempty(unit, "unit")?;
        let mut s = self.lock()?;
        if let Some(b) = s.budgets.get(budget) {
            return if b.unit == unit && b.cap == cap {
                Ok(())
            } else {
                Err(SpendError::Conflict(budget.into()))
            };
        }
        s.commit(Record::OpenBudget {
            budget: budget.into(),
            unit: unit.into(),
            cap,
        })
    }

    /// Hold `ceiling` against the budget before dispatch. All-or-nothing and
    /// atomic across threads; a zero ceiling is rejected.
    pub fn reserve(&self, budget: &str, id: &str, ceiling: u64) -> Result<Reserved, SpendError> {
        nonempty(id, "reservation id")?;
        if ceiling == 0 {
            return Err(SpendError::InvalidAmount(
                "ceiling must be greater than zero".into(),
            ));
        }
        let mut s = self.lock()?;
        if let Some(r) = s.reservations.get(id) {
            return if r.budget == budget && r.ceiling == ceiling {
                Ok(Reserved::Existing)
            } else {
                Err(SpendError::Conflict(id.into()))
            };
        }
        let b = s
            .budgets
            .get(budget)
            .ok_or_else(|| SpendError::UnknownBudget(budget.into()))?;
        let remaining = b.remaining();
        if ceiling > remaining {
            return Err(SpendError::Insufficient {
                budget: budget.into(),
                needed: ceiling,
                remaining,
            });
        }
        s.commit(Record::Reserve {
            budget: budget.into(),
            id: id.into(),
            ceiling,
        })?;
        Ok(Reserved::New)
    }

    /// Record the measured cost and free the rest of the ceiling. A cost above the
    /// ceiling is recorded as it happened (the money is gone) and leaves the
    /// budget with nothing remaining; it is never silently capped.
    pub fn finalize(&self, id: &str, spent: u64) -> Result<(), SpendError> {
        let mut s = self.lock()?;
        let r = s.reservation(id)?;
        match r.state {
            ReservationState::Finalized if r.spent == Some(spent) => return Ok(()),
            ReservationState::Reserved | ReservationState::Uncertain => {}
            st => {
                return Err(SpendError::InvalidState {
                    id: id.into(),
                    state: st.name(),
                })
            }
        }
        s.commit(Record::Finalize {
            id: id.into(),
            spent,
        })
    }

    /// Free a reservation that definitely spent nothing (never dispatched, or the
    /// rail confirmed no charge). Not allowed from `Uncertain`; use
    /// `resolve_uncertain` with evidence instead.
    pub fn release(&self, id: &str) -> Result<(), SpendError> {
        let mut s = self.lock()?;
        let r = s.reservation(id)?;
        match r.state {
            ReservationState::Released => return Ok(()),
            ReservationState::Reserved => {}
            st => {
                return Err(SpendError::InvalidState {
                    id: id.into(),
                    state: st.name(),
                })
            }
        }
        s.commit(Record::Release { id: id.into() })
    }

    /// Dispatch may have spent funds and the result is unknown. The ceiling stays
    /// held and cannot be released automatically.
    pub fn mark_uncertain(&self, id: &str, note: &str) -> Result<(), SpendError> {
        let mut s = self.lock()?;
        let r = s.reservation(id)?;
        match r.state {
            ReservationState::Uncertain => return Ok(()),
            ReservationState::Reserved => {}
            st => {
                return Err(SpendError::InvalidState {
                    id: id.into(),
                    state: st.name(),
                })
            }
        }
        s.commit(Record::Uncertain {
            id: id.into(),
            note: note.into(),
        })
    }

    /// Reconciliation result for an uncertain reservation: `Some(cost)` finalizes
    /// at the observed cost, `None` releases it because the rail confirmed
    /// nothing was paid.
    pub fn resolve_uncertain(
        &self,
        id: &str,
        observed_spent: Option<u64>,
    ) -> Result<(), SpendError> {
        let mut s = self.lock()?;
        let r = s.reservation(id)?;
        if r.state != ReservationState::Uncertain {
            return Err(SpendError::InvalidState {
                id: id.into(),
                state: r.state.name(),
            });
        }
        match observed_spent {
            Some(spent) => s.commit(Record::Finalize {
                id: id.into(),
                spent,
            }),
            None => s.commit(Record::Release { id: id.into() }),
        }
    }

    pub fn budget(&self, budget: &str) -> Result<BudgetView, SpendError> {
        let s = self.lock()?;
        let b = s
            .budgets
            .get(budget)
            .ok_or_else(|| SpendError::UnknownBudget(budget.into()))?;
        Ok(BudgetView {
            budget: budget.into(),
            unit: b.unit.clone(),
            cap: b.cap,
            spent: b.spent,
            held: b.held,
            remaining: b.remaining(),
        })
    }

    pub fn reservation(&self, id: &str) -> Result<Reservation, SpendError> {
        Ok(self.lock()?.reservation(id)?.clone())
    }

    /// Reservations that still hold budget and need a decision: dispatched-but-
    /// unconfirmed ones first matter most to an operator.
    pub fn open_reservations(&self) -> Result<Vec<Reservation>, SpendError> {
        Ok(self
            .lock()?
            .reservations
            .values()
            .filter(|r| {
                matches!(
                    r.state,
                    ReservationState::Reserved | ReservationState::Uncertain
                )
            })
            .cloned()
            .collect())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Inner>, SpendError> {
        let g = self
            .inner
            .lock()
            .map_err(|_| SpendError::Closed("poisoned ledger lock".into()))?;
        match &g.poisoned {
            Some(why) => Err(SpendError::Closed(why.clone())),
            None => Ok(g),
        }
    }
}

impl Budget {
    fn remaining(&self) -> u64 {
        self.cap
            .saturating_sub(self.spent)
            .saturating_sub(self.held)
    }
}

impl Inner {
    fn reservation(&self, id: &str) -> Result<&Reservation, SpendError> {
        self.reservations
            .get(id)
            .ok_or_else(|| SpendError::UnknownReservation(id.into()))
    }

    /// Validate and apply to memory. Used for replay and after a durable append.
    fn apply(&mut self, record: &Record) -> Result<(), String> {
        match record {
            Record::OpenBudget { budget, unit, cap } => {
                if self.budgets.contains_key(budget) {
                    return Err(format!("duplicate budget {budget}"));
                }
                self.budgets.insert(
                    budget.clone(),
                    Budget {
                        unit: unit.clone(),
                        cap: *cap,
                        spent: 0,
                        held: 0,
                    },
                );
            }
            Record::Reserve {
                budget,
                id,
                ceiling,
            } => {
                if self.reservations.contains_key(id) {
                    return Err(format!("duplicate reservation {id}"));
                }
                let b = self.budgets.get_mut(budget).ok_or("unknown budget")?;
                if *ceiling > b.remaining() {
                    return Err(format!("reservation {id} exceeds remaining budget"));
                }
                b.held += ceiling;
                self.reservations.insert(
                    id.clone(),
                    Reservation {
                        id: id.clone(),
                        budget: budget.clone(),
                        ceiling: *ceiling,
                        state: ReservationState::Reserved,
                        spent: None,
                        note: None,
                    },
                );
            }
            Record::Uncertain { id, note } => {
                let r = self.reservations.get_mut(id).ok_or("unknown reservation")?;
                if r.state != ReservationState::Reserved {
                    return Err(format!("{id} not reserved"));
                }
                r.state = ReservationState::Uncertain;
                r.note = Some(note.clone());
            }
            Record::Finalize { id, spent } => {
                let r = self.reservations.get_mut(id).ok_or("unknown reservation")?;
                if !matches!(
                    r.state,
                    ReservationState::Reserved | ReservationState::Uncertain
                ) {
                    return Err(format!("{id} not open"));
                }
                let b = self.budgets.get_mut(&r.budget).ok_or("unknown budget")?;
                b.held -= r.ceiling;
                b.spent = b.spent.checked_add(*spent).ok_or("spend overflow")?;
                r.state = ReservationState::Finalized;
                r.spent = Some(*spent);
            }
            Record::Release { id } => {
                let r = self.reservations.get_mut(id).ok_or("unknown reservation")?;
                if !matches!(
                    r.state,
                    ReservationState::Reserved | ReservationState::Uncertain
                ) {
                    return Err(format!("{id} not open"));
                }
                let b = self.budgets.get_mut(&r.budget).ok_or("unknown budget")?;
                b.held -= r.ceiling;
                r.state = ReservationState::Released;
            }
        }
        Ok(())
    }

    /// Durable append, then apply. If the append fails the on-disk state is
    /// unknown, so the ledger poisons itself rather than guess.
    fn commit(&mut self, record: Record) -> Result<(), SpendError> {
        let checksum = digest(&(self.sequence, &self.previous, &record))?;
        let frame = Frame {
            sequence: self.sequence,
            previous: self.previous.clone(),
            record,
            checksum,
        };
        let mut bytes = serde_json::to_vec(&frame).map_err(closed)?;
        bytes.push(b'\n');
        if let Err(e) = self
            .file
            .write_all(&bytes)
            .and_then(|_| self.file.sync_all())
        {
            let why = format!("append failed: {e}");
            self.poisoned = Some(why.clone());
            return Err(SpendError::Closed(why));
        }
        if let Err(e) = self.apply(&frame.record) {
            let why = format!("inconsistent transition after append: {e}");
            self.poisoned = Some(why.clone());
            return Err(SpendError::Closed(why));
        }
        self.sequence += 1;
        self.previous = frame.checksum;
        Ok(())
    }
}

fn open_append(path: &Path) -> Result<File, SpendError> {
    let mut o = OpenOptions::new();
    o.append(true).create(true);
    #[cfg(unix)]
    o.mode(0o600);
    let f = o.open(path).map_err(closed)?;
    if let Some(parent) = path.parent() {
        File::open(parent)
            .and_then(|d| d.sync_all())
            .map_err(closed)?;
    }
    Ok(f)
}
fn digest<T: Serialize>(v: &T) -> Result<String, SpendError> {
    Ok(hex::encode(Sha256::digest(
        serde_json::to_vec(v).map_err(closed)?,
    )))
}
fn closed(e: impl std::fmt::Display) -> SpendError {
    SpendError::Closed(e.to_string())
}
fn nonempty(v: &str, what: &str) -> Result<(), SpendError> {
    if v.trim().is_empty() {
        Err(SpendError::InvalidAmount(format!(
            "{what} must not be empty"
        )))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "membrane-spend-{name}-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn reserve_finalize_release_accounting() {
        let l = BudgetLedger::open(dir("basic")).unwrap();
        l.open_budget("b", "msat", 1000).unwrap();
        assert_eq!(l.reserve("b", "r1", 400).unwrap(), Reserved::New);
        assert_eq!(l.budget("b").unwrap().remaining, 600);
        l.finalize("r1", 150).unwrap();
        let v = l.budget("b").unwrap();
        assert_eq!((v.spent, v.held, v.remaining), (150, 0, 850));
        l.reserve("b", "r2", 500).unwrap();
        l.release("r2").unwrap();
        assert_eq!(l.budget("b").unwrap().remaining, 850);
    }

    #[test]
    fn denies_over_budget_and_zero() {
        let l = BudgetLedger::open(dir("deny")).unwrap();
        l.open_budget("b", "msat", 100).unwrap();
        l.reserve("b", "r1", 80).unwrap();
        assert!(matches!(
            l.reserve("b", "r2", 21),
            Err(SpendError::Insufficient { remaining: 20, .. })
        ));
        assert!(matches!(
            l.reserve("b", "r3", 0),
            Err(SpendError::InvalidAmount(_))
        ));
        assert!(matches!(
            l.reserve("nope", "r4", 1),
            Err(SpendError::UnknownBudget(_))
        ));
        assert_eq!(l.budget("b").unwrap().held, 80);
    }

    #[test]
    fn reserve_is_idempotent_and_detects_conflict() {
        let l = BudgetLedger::open(dir("idem")).unwrap();
        l.open_budget("b", "msat", 100).unwrap();
        assert_eq!(l.reserve("b", "r", 60).unwrap(), Reserved::New);
        assert_eq!(l.reserve("b", "r", 60).unwrap(), Reserved::Existing);
        assert_eq!(l.budget("b").unwrap().held, 60);
        assert!(matches!(
            l.reserve("b", "r", 61),
            Err(SpendError::Conflict(_))
        ));
        l.finalize("r", 10).unwrap();
        l.finalize("r", 10).unwrap();
        assert!(matches!(
            l.finalize("r", 11),
            Err(SpendError::InvalidState { .. })
        ));
        assert!(matches!(
            l.release("r"),
            Err(SpendError::InvalidState { .. })
        ));
        assert_eq!(l.budget("b").unwrap().spent, 10);
    }

    #[test]
    fn concurrent_reservations_never_exceed_budget() {
        let l = Arc::new(BudgetLedger::open(dir("conc")).unwrap());
        l.open_budget("b", "msat", 1000).unwrap();
        let handles: Vec<_> = (0..64)
            .map(|i| {
                let l = l.clone();
                std::thread::spawn(move || l.reserve("b", &format!("r{i}"), 100).is_ok())
            })
            .collect();
        let granted = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|ok| *ok)
            .count();
        assert_eq!(granted, 10);
        let v = l.budget("b").unwrap();
        assert_eq!((v.held, v.remaining), (1000, 0));
    }

    #[test]
    fn uncertain_holds_ceiling_until_resolved() {
        let l = BudgetLedger::open(dir("unc")).unwrap();
        l.open_budget("b", "msat", 100).unwrap();
        l.reserve("b", "r", 100).unwrap();
        l.mark_uncertain("r", "dispatch timed out").unwrap();
        assert!(matches!(
            l.release("r"),
            Err(SpendError::InvalidState { .. })
        ));
        assert!(matches!(
            l.reserve("b", "r2", 1),
            Err(SpendError::Insufficient { .. })
        ));
        assert_eq!(l.open_reservations().unwrap().len(), 1);
        l.resolve_uncertain("r", Some(40)).unwrap();
        let v = l.budget("b").unwrap();
        assert_eq!((v.spent, v.remaining), (40, 60));
        assert!(l.open_reservations().unwrap().is_empty());
        assert!(matches!(
            l.resolve_uncertain("r", None),
            Err(SpendError::InvalidState { .. })
        ));
    }

    #[test]
    fn overrun_is_recorded_not_capped() {
        let l = BudgetLedger::open(dir("over")).unwrap();
        l.open_budget("b", "msat", 100).unwrap();
        l.reserve("b", "r", 100).unwrap();
        l.finalize("r", 130).unwrap();
        let v = l.budget("b").unwrap();
        assert_eq!((v.spent, v.remaining), (130, 0));
        assert!(matches!(
            l.reserve("b", "r2", 1),
            Err(SpendError::Insufficient { .. })
        ));
    }

    #[test]
    fn crash_replay_keeps_open_reservations_held() {
        let d = dir("replay");
        {
            let l = BudgetLedger::open(&d).unwrap();
            l.open_budget("b", "msat", 1000).unwrap();
            l.reserve("b", "a", 300).unwrap();
            l.reserve("b", "b1", 200).unwrap();
            l.finalize("a", 100).unwrap();
            l.mark_uncertain("b1", "crash mid-dispatch").unwrap();
            // dropped without any shutdown step: simulates a crash
        }
        let l = BudgetLedger::open(&d).unwrap();
        let v = l.budget("b").unwrap();
        assert_eq!((v.spent, v.held, v.remaining), (100, 200, 700));
        assert_eq!(
            l.reservation("b1").unwrap().state,
            ReservationState::Uncertain
        );
        assert_eq!(l.reserve("b", "a", 300).unwrap(), Reserved::Existing);
        l.reserve("b", "c", 700).unwrap();
    }

    #[test]
    fn second_open_of_same_dir_is_refused() {
        let d = dir("lock");
        let _l = BudgetLedger::open(&d).unwrap();
        assert!(matches!(BudgetLedger::open(&d), Err(SpendError::Closed(_))));
    }

    #[test]
    fn torn_tail_and_tampering_fail_closed() {
        let d = dir("torn");
        {
            let l = BudgetLedger::open(&d).unwrap();
            l.open_budget("b", "msat", 100).unwrap();
            l.reserve("b", "r", 10).unwrap();
        }
        let path = d.join("ledger.jsonl");
        let good = fs::read(&path).unwrap();

        let mut torn = good.clone();
        torn.pop();
        fs::write(&path, &torn).unwrap();
        assert!(matches!(BudgetLedger::open(&d), Err(SpendError::Closed(_))));

        // Raise the cap in place: the checksum no longer matches.
        let tampered = String::from_utf8(good.clone())
            .unwrap()
            .replace("\"cap\":100", "\"cap\":999999");
        fs::write(&path, tampered).unwrap();
        assert!(matches!(BudgetLedger::open(&d), Err(SpendError::Closed(_))));

        // Drop the first record: sequence discontinuity.
        let lines: Vec<&[u8]> = good.split_inclusive(|b| *b == b'\n').collect();
        fs::write(&path, lines[1]).unwrap();
        assert!(matches!(BudgetLedger::open(&d), Err(SpendError::Closed(_))));

        fs::write(&path, &good).unwrap();
        assert!(BudgetLedger::open(&d).is_ok());
    }

    #[test]
    fn journal_write_failure_poisons_ledger() {
        let d = dir("poison");
        let l = BudgetLedger::open(&d).unwrap();
        l.open_budget("b", "msat", 100).unwrap();
        // Swap the append handle for a read-only one so the next write fails.
        {
            let mut s = l.inner.lock().unwrap();
            s.file = File::open(d.join("ledger.jsonl")).unwrap();
        }
        assert!(matches!(
            l.reserve("b", "r", 10),
            Err(SpendError::Closed(_))
        ));
        assert!(matches!(
            l.reserve("b", "r2", 1),
            Err(SpendError::Closed(_))
        ));
        assert!(matches!(l.budget("b"), Err(SpendError::Closed(_))));
        drop(l);
        // Nothing was granted on disk, so a fresh open sees the full budget.
        let l = BudgetLedger::open(&d).unwrap();
        assert_eq!(l.budget("b").unwrap().remaining, 100);
    }

    #[test]
    fn budget_reopen_rules() {
        let l = BudgetLedger::open(dir("reopen")).unwrap();
        l.open_budget("b", "msat", 100).unwrap();
        l.open_budget("b", "msat", 100).unwrap();
        assert!(matches!(
            l.open_budget("b", "msat", 200),
            Err(SpendError::Conflict(_))
        ));
        assert!(matches!(
            l.open_budget("b", "sat", 100),
            Err(SpendError::Conflict(_))
        ));
    }
}
