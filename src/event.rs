//! Event data contract — one entry of the replayable log.
//!
//! Traceability: handover doc §2 ("sequence: u64 تسلسلي لا UUID", "الانهيار:
//! HandlerOutcome::Crashed حدث مسجّل لا استثناء", "policy_set_hash في كل Event",
//! "لا وقت داخل الحالة القابلة للهاش"), §4-أ.
//!
//! Invariants:
//! - `sequence` is a dense `u64` assigned by the runtime, never a UUID. Replay
//!   order is the sequence order.
//! - `recorded_at_unix_ms` is **metadata only**: it is excluded from
//!   [`Event::to_canonical`] and therefore from every hash. Two events that differ
//!   only in timestamp hash identically — this is what makes replay possible
//!   without the model.
//! - A handler crash is an ordinary outcome ([`HandlerOutcome::Crashed`]), not an
//!   error path. The log must be able to represent every way execution ends.
//! - `evidence_ref` is a hash produced by the **runtime**; the agent never signs or
//!   hashes its own evidence.
//! - `policy_set_hash` pins which policy set was in force when the event was
//!   recorded so an auditor can tell "allowed under policy X" from "allowed under
//!   policy Y".

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::hex;
use crate::instruction::Instruction;
use crate::state::{CanonicalError, CanonicalValue, HashAlg, StateHash};
use crate::Hash32;

/// How the handler for an instruction finished.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum HandlerOutcome {
    /// Handler finished; runtime produced and hashed evidence.
    Completed {
        /// Runtime-computed digest of the evidence blob (hex on the wire).
        #[serde(with = "hex::array32")]
        evidence_ref: Hash32,
    },
    /// Policy / capability / lease check refused the instruction before execution.
    Rejected {
        /// Machine-readable reason (stable identifier, not free prose).
        reason: String,
    },
    /// Handler process died. Recorded, never raised.
    Crashed {
        /// Terminating signal if the host reported one (POSIX).
        signal: Option<i32>,
        /// Exit code if the host reported one.
        exit_code: Option<i32>,
    },
    /// Handler exceeded its lease's time budget.
    TimedOut,
}

impl HandlerOutcome {
    /// Canonical form. Always a map with a `status` key; other keys are fixed per
    /// variant so absence/presence never varies within a variant.
    pub fn to_canonical(&self) -> CanonicalValue {
        let mut m = BTreeMap::new();
        match self {
            HandlerOutcome::Completed { evidence_ref } => {
                m.insert(
                    "status".to_string(),
                    CanonicalValue::Str("completed".into()),
                );
                m.insert(
                    "evidence_ref".to_string(),
                    CanonicalValue::Bytes(evidence_ref.to_vec()),
                );
            }
            HandlerOutcome::Rejected { reason } => {
                m.insert("status".to_string(), CanonicalValue::Str("rejected".into()));
                m.insert("reason".to_string(), CanonicalValue::Str(reason.clone()));
            }
            HandlerOutcome::Crashed { signal, exit_code } => {
                m.insert("status".to_string(), CanonicalValue::Str("crashed".into()));
                m.insert("signal".to_string(), opt_i32(*signal));
                m.insert("exit_code".to_string(), opt_i32(*exit_code));
            }
            HandlerOutcome::TimedOut => {
                m.insert(
                    "status".to_string(),
                    CanonicalValue::Str("timed_out".into()),
                );
            }
        }
        CanonicalValue::Map(m)
    }
}

fn opt_i32(v: Option<i32>) -> CanonicalValue {
    match v {
        Some(i) => CanonicalValue::Int(i64::from(i)),
        None => CanonicalValue::Null,
    }
}

/// One recorded step of a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Dense, runtime-assigned position in the log. Starts at 0.
    pub sequence: u64,
    /// Wall-clock time of recording. **Excluded from all hashes.**
    pub recorded_at_unix_ms: u64,
    /// The instruction that was processed.
    pub instruction: Instruction,
    /// How processing ended.
    pub outcome: HandlerOutcome,
    /// Digest of the policy set in force (hex on the wire).
    #[serde(with = "hex::array32")]
    pub policy_set_hash: Hash32,
}

impl Event {
    /// Canonical form used for hashing. `recorded_at_unix_ms` is deliberately
    /// absent — see module invariants.
    pub fn to_canonical(&self) -> Result<CanonicalValue, CanonicalError> {
        CanonicalValue::map([
            ("instruction", self.instruction.to_canonical()?),
            ("outcome", self.outcome.to_canonical()),
            (
                "policy_set_hash",
                CanonicalValue::Bytes(self.policy_set_hash.to_vec()),
            ),
            (
                "sequence",
                CanonicalValue::Int(sequence_as_i64(self.sequence)?),
            ),
        ])
    }

    /// Hash of the canonical form under `alg`.
    pub fn hash(&self, alg: HashAlg) -> Result<StateHash, CanonicalError> {
        self.to_canonical()?.hash(alg)
    }
}

/// `CanonicalValue::Int` is `i64`; a log longer than `i64::MAX` entries is not a
/// realistic case but we refuse rather than wrap silently.
fn sequence_as_i64(seq: u64) -> Result<i64, CanonicalError> {
    i64::try_from(seq).map_err(|_| CanonicalError::IntegerOutOfRange)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(recorded_at: u64) -> Event {
        Event {
            sequence: 7,
            recorded_at_unix_ms: recorded_at,
            instruction: Instruction::nop(),
            outcome: HandlerOutcome::Completed {
                evidence_ref: [0x11; 32],
            },
            policy_set_hash: [0x22; 32],
        }
    }

    #[test]
    fn timestamp_is_excluded_from_hash() {
        let a = sample(1_000).hash(HashAlg::Blake3).map(|h| h.to_hex());
        let b = sample(9_999_999).hash(HashAlg::Blake3).map(|h| h.to_hex());
        assert_eq!(a, b);
        assert!(a.is_ok());
    }

    #[test]
    fn canonical_json_has_fixed_shape() {
        let c = sample(0).to_canonical().map(|v| v.to_canonical_json());
        let expected = format!(
            concat!(
                "{{\"instruction\":{{\"args\":{{}},\"capability\":\"kernel.nop\",\"kind\":\"nop\"}},",
                "\"outcome\":{{\"evidence_ref\":{{\"$bytes\":\"{}\"}},\"status\":\"completed\"}},",
                "\"policy_set_hash\":{{\"$bytes\":\"{}\"}},",
                "\"sequence\":7}}"
            ),
            "11".repeat(32),
            "22".repeat(32)
        );
        assert_eq!(c, Ok(expected));
    }

    #[test]
    fn every_outcome_variant_roundtrips_on_the_wire() {
        let outcomes = [
            HandlerOutcome::Completed {
                evidence_ref: [0xaa; 32],
            },
            HandlerOutcome::Rejected {
                reason: "policy.denied".into(),
            },
            HandlerOutcome::Crashed {
                signal: Some(9),
                exit_code: None,
            },
            HandlerOutcome::Crashed {
                signal: None,
                exit_code: Some(1),
            },
            HandlerOutcome::TimedOut,
        ];
        for o in outcomes {
            let wire = serde_json::to_string(&o).map_err(|e| e.to_string());
            let back: Result<HandlerOutcome, String> =
                wire.and_then(|w| serde_json::from_str(&w).map_err(|e| e.to_string()));
            assert_eq!(back, Ok(o));
        }
    }

    #[test]
    fn outcome_wire_uses_status_tag() {
        let wire = serde_json::to_string(&HandlerOutcome::TimedOut).map_err(|e| e.to_string());
        assert_eq!(wire, Ok(r#"{"status":"timed_out"}"#.to_string()));
        let wire = serde_json::to_string(&HandlerOutcome::Crashed {
            signal: Some(11),
            exit_code: None,
        })
        .map_err(|e| e.to_string());
        assert_eq!(
            wire,
            Ok(r#"{"status":"crashed","signal":11,"exit_code":null}"#.to_string())
        );
    }

    #[test]
    fn different_outcomes_hash_differently() {
        let mut a = sample(0);
        let mut b = sample(0);
        a.outcome = HandlerOutcome::TimedOut;
        b.outcome = HandlerOutcome::Rejected { reason: "x".into() };
        assert_ne!(
            a.hash(HashAlg::Blake3).map(|h| h.to_hex()),
            b.hash(HashAlg::Blake3).map(|h| h.to_hex())
        );
    }

    #[test]
    fn event_wire_json_roundtrips() {
        let e = sample(123);
        let wire = serde_json::to_string(&e).map_err(|e| e.to_string());
        let back: Result<Event, String> =
            wire.and_then(|w| serde_json::from_str(&w).map_err(|e| e.to_string()));
        assert_eq!(back, Ok(e));
    }
}
